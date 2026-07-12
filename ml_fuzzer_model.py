import os
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, Dataset
from torch.utils.tensorboard import SummaryWriter
from typing import List, Tuple, Optional, Dict
import random
from pathlib import Path
import numpy as np

ADDRESS_OFFSET_SCALE = 0x10000

#for mutual information based feature selection in the future
from sklearn.feature_selection import mutual_info_regression, SelectKBest 

#logging 
import logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


def get_model_dir() -> str:
    """Return the repository models directory."""
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "models"))


def find_pretrained_model_paths(base_dir: Optional[str] = None,
                                model_names: Optional[List[str]] = None) -> List[str]:
    """Find existing pretrained model checkpoint files in common locations."""
    if model_names is None:
        model_names = [
            "vaegan_fuzzer_model.pth",
            "vaegan_model.pth",
            "vaegan.pth",
            "address_oracle.pth",
            "address_oracle_old.pth",
        ]

    roots = []
    if base_dir:
        roots.append(base_dir)
    roots.extend([
        get_model_dir(),
        os.path.join(get_model_dir(), "..", "models_unloaded"),
        os.path.join(get_model_dir(), "..", "models_old"),
    ])

    found: List[str] = []
    seen = set()
    for root in roots:
        resolved_root = os.path.abspath(root)
        if not os.path.isdir(resolved_root):
            continue
        for name in model_names:
            path = os.path.join(resolved_root, name)
            if os.path.isfile(path) and path not in seen:
                found.append(path)
                seen.add(path)
    return found


def normalize_feature_vector(values: List[float]) -> List[float]:
    """Normalize a feature vector to the unit interval while preserving length."""
    if not values:
        return []
    if len(values) == 1:
        return [1.0]

    min_val = min(values)
    max_val = max(values)
    if abs(max_val - min_val) < 1e-8:
        return [0.5 for _ in values]

    return [(value - min_val) / (max_val - min_val) for value in values]


def summarize_feature_correlation(feature_matrix: np.ndarray, target_matrix: np.ndarray,
                                  feature_names: Optional[List[str]] = None,
                                  top_k: int = 8) -> Dict[str, List[Dict[str, float]]]:
    """Compute the strongest feature-to-target correlations for logging and model tuning."""
    if feature_matrix.size == 0 or target_matrix.size == 0:
        return {"top_features": []}

    feature_matrix = np.asarray(feature_matrix, dtype=np.float32)
    target_matrix = np.asarray(target_matrix, dtype=np.float32)
    if feature_matrix.ndim == 1:
        feature_matrix = feature_matrix.reshape(1, -1)
    if target_matrix.ndim == 1:
        target_matrix = target_matrix.reshape(-1, 1)

    correlations = []
    for feat_idx in range(feature_matrix.shape[1]):
        feat_vals = feature_matrix[:, feat_idx]
        if np.std(feat_vals) < 1e-6:
            continue
        max_abs_corr = 0.0
        for out_idx in range(target_matrix.shape[1]):
            target_vals = target_matrix[:, out_idx]
            if np.std(target_vals) < 1e-6:
                continue
            corr = np.corrcoef(feat_vals, target_vals)[0, 1]
            if not np.isnan(corr):
                max_abs_corr = max(max_abs_corr, abs(float(corr)))
        correlations.append((feat_idx, max_abs_corr))

    correlations.sort(key=lambda item: item[1], reverse=True)
    top = []
    for feat_idx, corr in correlations[:max(1, top_k)]:
        name = feature_names[feat_idx] if feature_names and feat_idx < len(feature_names) else f"feature_{feat_idx}"
        top.append({"name": name, "correlation": round(corr, 4)})
    return {"top_features": top}


try:
    import pil_loader # Use pil_loader.py for PIL operations
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
    logger.warning("pil_loader not available - PIL operations will be disabled")

from dataclasses import dataclass
import numpy as np
from lime.lime_tabular import LimeTabularExplainer # Import LIME 
import time
import psutil  # For process features
import json

# Assuming FuzzingSample and InstrumentationSuggestion are defined in data_processor.py
# For standalone testing, we'll define them here or import if data_processor is available.
try:
    from data_processor import FuzzingSample, InstrumentationSuggestion, ELF_FEATURE_VECTOR_SIZE
except ImportError:
    # Define a dummy ELF_FEATURE_VECTOR_SIZE for standalone testing if data_processor is not available
    ELF_FEATURE_VECTOR_SIZE = 50 
    @dataclass
    class FuzzingSample:
        viewer_name: str
        fuzz_type: str
        file_features: List[float]
        payload_offset_attempted: int
        status_one_hot: List[float]
        gdb_crash_features: List[float]
        leaked_addresses_features: List[float]
        apport_crash_features: List[float]
        success_label: int
        elf_features: List[float]  # New field for ELF features
        chain_type_prediction: str  # e.g., "ROP", "JOP", "VOP"
        trigger_offset_attempted: int = 0


    @dataclass
    class InstrumentationSuggestion:
        fuzz_type_prediction: str
        payload_offset_prediction: int
        trigger_offset_prediction: Optional[int] = None
        chain_type_prediction: str = "ROP"  # New: "ROP", "JOP", "VOP", etc.
        confidence: float = 1.0


@dataclass
class AddressSample:
    addresses: List[int]  # actual addresses of gadgets
    features: Optional[List[float]] = None
    static_elf_features: Optional[List[float]] = None
    dynamic_features: Optional[List[float]] = None
    viewer_name: str = ""
    fuzz_type: str = ""
    chain_type: str = ""
    payload_offset: int = 0
    trigger_offset: int = 0
    instrumentation_loaded: float = 0.0

    def __post_init__(self):
        if self.features is None:
            self.features = []
        if self.static_elf_features is None:
            self.static_elf_features = []
        if self.dynamic_features is None:
            self.dynamic_features = []
        if not self.features and self.static_elf_features and self.dynamic_features:
            self.features = self.static_elf_features + self.dynamic_features


class AddressDataset(Dataset):
    """Dataset for AddressOracle training."""
    
    def __init__(self, samples: List[AddressSample]):
        self.samples = samples
        if samples:
            self.input_dim = len(samples[0].features)
            self.output_dim = len(samples[0].addresses)
        else:
            self.input_dim = 0
            self.output_dim = 0

    def __len__(self):
        return len(self.samples)

    def __getitem__(self, idx) -> Tuple[torch.Tensor, torch.Tensor]:
        sample = self.samples[idx]
        input_tensor = torch.tensor(sample.features, dtype=torch.float32)
        normalized_addresses = [addr / ADDRESS_OFFSET_SCALE for addr in sample.addresses]
        output_tensor = torch.tensor(normalized_addresses, dtype=torch.float64)
        return input_tensor, output_tensor

    @classmethod
    def create_synthetic_oracle_dataset(cls,
                                       viewers: List[str],
                                       fuzz_types: List[str],
                                       chain_types: List[str],
                                       elf_feature_size: int = 50,
                                       max_payload_offset: int = 16384,
                                       max_trigger_offset: int = 16384,
                                       base_variants: int = 3) -> 'AddressDataset':
        """Generate a varied synthetic AddressOracle dataset combining static ELF and dynamic runtime features."""
        samples: List[AddressSample] = []
        payload_offsets = [0, max_payload_offset // 4, max_payload_offset // 2, 3 * max_payload_offset // 4, max_payload_offset]
        trigger_offsets = [0, max_trigger_offset // 4, max_trigger_offset // 2, 3 * max_trigger_offset // 4, max_trigger_offset]

        for viewer_name in viewers:
            for fuzz_type in fuzz_types:
                for chain_type in chain_types:
                    static_elf_features = cls._generate_elf_features(viewer_name, fuzz_type, elf_feature_size)
                    for variant in range(base_variants):
                        main_base, libc_base, heap_start, stack_start = cls._sample_address_bases(viewer_name)
                        for payload_offset in payload_offsets:
                            for trigger_offset in trigger_offsets:
                                for instrumentation_loaded in [0.0, 1.0]:
                                    dynamic_features = cls._generate_dynamic_address_features(
                                        viewer_name,
                                        fuzz_type,
                                        chain_type,
                                        main_base,
                                        libc_base,
                                        heap_start,
                                        stack_start,
                                        payload_offset,
                                        trigger_offset,
                                        instrumentation_loaded,
                                        viewers,
                                        fuzz_types,
                                        chain_types,
                                        max_payload_offset,
                                        max_trigger_offset
                                    )
                                    addresses = cls._generate_address_targets(
                                        viewer_name,
                                        chain_type,
                                        main_base,
                                        libc_base,
                                        heap_start,
                                        stack_start,
                                        payload_offset,
                                        trigger_offset,
                                        instrumentation_loaded
                                    )
                                    samples.append(AddressSample(
                                        addresses=addresses,
                                        static_elf_features=static_elf_features,
                                        dynamic_features=dynamic_features,
                                        viewer_name=viewer_name,
                                        fuzz_type=fuzz_type,
                                        chain_type=chain_type,
                                        payload_offset=payload_offset,
                                        trigger_offset=trigger_offset,
                                        instrumentation_loaded=instrumentation_loaded
                                    ))
        return cls(samples)

    @staticmethod
    def _generate_elf_features(viewer_name: str, fuzz_type: str, feature_size: int) -> List[float]:
        """Generate ELF features for AddressOracle synthetic data."""
        features = []
        if viewer_name == "png_consumer":
            base_entropy = 0.7
            base_complexity = 0.8
        elif viewer_name in ["eog", "firefox"]:
            base_entropy = 0.6
            base_complexity = 0.9
        else:
            base_entropy = 0.5
            base_complexity = 0.6

        for i in range(feature_size):
            if i < 10:
                feature = base_entropy + random.gauss(0, 0.1)
            elif i < 20:
                feature = base_complexity + random.gauss(0, 0.1)
            else:
                feature = random.gauss(0.5, 0.2)
            features.append(max(0.0, min(1.0, feature)))
        return features

    @staticmethod
    def _sample_address_bases(viewer_name: str) -> Tuple[int, int, int, int]:
        base_offset = random.randint(0, 0xfff) * 0x1000
        main_base = 0x7fff00000000 + base_offset
        libc_base = main_base + 0x1200000 + random.randint(-4, 4) * 0x1000
        heap_start = main_base + 0x2200000 + random.randint(-8, 8) * 0x1000
        stack_start = main_base + 0x3200000 + random.randint(-8, 8) * 0x1000
        return main_base, libc_base, heap_start, stack_start

    @staticmethod
    def _generate_dynamic_address_features(viewer_name: str,
                                         fuzz_type: str,
                                         chain_type: str,
                                         main_base: int,
                                         libc_base: int,
                                         heap_start: int,
                                         stack_start: int,
                                         payload_offset: int,
                                         trigger_offset: int,
                                         instrumentation_loaded: float,
                                         viewers: List[str],
                                         fuzz_types: List[str],
                                         chain_types: List[str],
                                         max_payload_offset: int,
                                         max_trigger_offset: int) -> List[float]:
        payload_norm = min(1.0, payload_offset / max(1, max_payload_offset))
        trigger_norm = min(1.0, trigger_offset / max(1, max_trigger_offset))

        main_base_norm = ((main_base >> 12) & 0xfff) / 0xfff
        libc_offset_norm = min(1.0, (libc_base - main_base) / float(0x2000000))
        heap_offset_norm = min(1.0, (heap_start - main_base) / float(0x4000000))
        stack_offset_norm = min(1.0, (stack_start - main_base) / float(0x6000000))

        cpu_util = random.uniform(0.1, 0.9)
        mem_pressure = random.uniform(0.1, 0.9)
        trace_variance = random.uniform(0.0, 1.0)

        viewer_one_hot = [1.0 if viewer_name == v else 0.0 for v in viewers]
        fuzz_one_hot = [1.0 if fuzz_type == f else 0.0 for f in fuzz_types]
        chain_one_hot = [1.0 if chain_type == c else 0.0 for c in chain_types]

        return [
            main_base_norm,
            libc_offset_norm,
            heap_offset_norm,
            stack_offset_norm,
            payload_norm,
            trigger_norm,
            instrumentation_loaded,
            cpu_util,
            mem_pressure,
            trace_variance,
        ] + viewer_one_hot + fuzz_one_hot + chain_one_hot

    @staticmethod
    def _generate_address_targets(viewer_name: str,
                                  chain_type: str,
                                  main_base: int,
                                  libc_base: int,
                                  heap_start: int,
                                  stack_start: int,
                                  payload_offset: int,
                                  trigger_offset: int,
                                  instrumentation_loaded: float) -> List[int]:
        base_mod = int((payload_offset + trigger_offset) / 8 + instrumentation_loaded * 0x20)
        if chain_type == "ROP":
            return [
                0x1100 + base_mod,
                0x1000 + base_mod,
                0x2100 + base_mod,
                0x2000 + base_mod,
                0x1300 + base_mod,
                0x1400 + base_mod,
                0x1800 + base_mod,
                0x1900 + base_mod,
                0x2500 + base_mod,
            ]
        elif chain_type == "JOP":
            return [
                0x1200 + base_mod,
                0x1500 + base_mod,
                0x2200 + base_mod,
                0x2600 + base_mod,
                0x1700 + base_mod,
                0x1900 + base_mod,
                0x2100 + base_mod,
                0x2700 + base_mod,
                0x2a00 + base_mod,
            ]
        elif chain_type == "VOP":
            return [
                0x1300 + base_mod,
                0x1400 + base_mod,
                0x1600 + base_mod,
                0x1a00 + base_mod,
                0x1c00 + base_mod,
                0x2300 + base_mod,
                0x1e00 + base_mod,
                0x2b00 + base_mod,
                0x2400 + base_mod,
            ]
        else:
            return [
                0x1300 + base_mod,
                0x1400 + base_mod,
                0x1500 + base_mod,
                0x1800 + base_mod,
                0x1d00 + base_mod,
                0x2000 + base_mod,
                0x1f00 + base_mod,
                0x2c00 + base_mod,
                0x2600 + base_mod,
            ]


class FuzzingDataset(Dataset):
    """Dataset for VAE/GAN training on fuzzing samples."""
    
    def __init__(self, samples: List[FuzzingSample], fuzz_types: List[str], 
                 chain_types: List[str], max_payload_offset: int, max_trigger_offset: int):
        self.samples = samples
        self.fuzz_types = fuzz_types
        self.chain_types = chain_types
        self.max_payload_offset = max_payload_offset
        self.max_trigger_offset = max_trigger_offset
        
        # Calculate dimensions based on actual sample structure
        if samples:
            sample = samples[0]
            self.input_dim = (
                len(sample.file_features) +
                len(sample.status_one_hot) +
                len(sample.gdb_crash_features) +
                len(sample.leaked_addresses_features) +
                len(sample.apport_crash_features) +
                len(sample.elf_features) +
                1 +  # normalized_payload_offset
                1    # normalized_trigger_offset
            )
            logger.info(f"Dataset input_dim: {self.input_dim}")
        else:
            self.input_dim = 79  # Default fallback

        # Output dimensions: fuzz_type (7) + chain_type (2) + payload_offset (1) + trigger_offset (1)
        self.output_dim = len(fuzz_types) + len(chain_types) + 2
        logger.info(f"Dataset output_dim: {self.output_dim} (fuzz={len(fuzz_types)}, chain={len(chain_types)})")

    @classmethod
    def create_comprehensive_dataset(cls, viewers: List[str], fuzz_types: List[str], 
                                   chain_types: List[str], max_payload_offset: int, 
                                   max_trigger_offset: int, elf_feature_size: int = 50,
                                   image_paths: List[str] = None) -> 'FuzzingDataset':
        """Create a comprehensive dataset with synthetic samples covering all combinations of 
        viewer + fuzz_type + chain_type with realistic feature distributions.
        
        Args:
            viewers: List of viewer names
            fuzz_types: List of fuzz types
            chain_types: List of chain types
            max_payload_offset: Maximum payload offset
            max_trigger_offset: Maximum trigger offset
            elf_feature_size: Size of ELF feature vector
            image_paths: Optional list of image paths to use for real feature extraction
        """
        
        samples = []
        image_idx = 0
        
        # Generate samples for each combination
        for viewer_name in viewers:
            for fuzz_type in fuzz_types:
                for chain_type in chain_types:
                    # Generate multiple samples per combination with different offsets
                    for payload_offset in [0, max_payload_offset // 4, max_payload_offset // 2, 3 * max_payload_offset // 4, max_payload_offset]:
                        for trigger_offset in [0, max_trigger_offset // 4, max_trigger_offset // 2, 3 * max_trigger_offset // 4, max_trigger_offset]:
                            
                            # Try to use real image if available
                            image_path = None
                            if image_paths and image_idx < len(image_paths):
                                image_path = image_paths[image_idx]
                                image_idx += 1
                            
                            # Create realistic synthetic features based on viewer/fuzz_type combination
                            file_features = cls._generate_file_features(viewer_name, fuzz_type, image_path)
                            status_one_hot = cls._generate_status_features(viewer_name, fuzz_type, chain_type)
                            gdb_crash_features = cls._generate_gdb_features(viewer_name, fuzz_type, chain_type)
                            leaked_addresses_features = cls._generate_leaked_address_features(viewer_name, fuzz_type)
                            apport_crash_features = cls._generate_apport_features(viewer_name, fuzz_type, chain_type)
                            elf_features = cls._generate_elf_features(viewer_name, fuzz_type, elf_feature_size)
                            
                            # Determine success probability based on combination
                            success_prob = cls._calculate_success_probability(viewer_name, fuzz_type, chain_type, payload_offset, trigger_offset, max_payload_offset, max_trigger_offset)
                            success_label = 1 if random.random() < success_prob else 0
                            
                            sample = FuzzingSample(
                                viewer_name=viewer_name,
                                fuzz_type=fuzz_type,
                                file_features=file_features,
                                payload_offset_attempted=payload_offset,
                                status_one_hot=status_one_hot,
                                gdb_crash_features=gdb_crash_features,
                                leaked_addresses_features=leaked_addresses_features,
                                apport_crash_features=apport_crash_features,
                                success_label=success_label,
                                elf_features=elf_features,
                                chain_type_prediction=chain_type,
                                trigger_offset_attempted=trigger_offset
                            )
                            samples.append(sample)
        
        logger.info(f"Generated comprehensive dataset with {len(samples)} samples covering {len(viewers)} viewers × {len(fuzz_types)} fuzz_types × {len(chain_types)} chain_types × 5 payload_offsets × 5 trigger_offsets")
        if image_paths:
            logger.info(f"Used {min(len(image_paths), image_idx)} real images for feature extraction")
        return cls(samples, fuzz_types, chain_types, max_payload_offset, max_trigger_offset)
    
    @staticmethod
    def _generate_file_features(viewer_name: str, fuzz_type: str, image_path: str = None) -> List[float]:
        """Generate realistic file features based on viewer and fuzz type, optionally using real image analysis."""
        base_features = []
        
        # Try to analyze real image if path provided and pil_loader available
        if image_path and PIL_AVAILABLE and os.path.exists(image_path):
            try:
                # Use pil_loader to process the image and get features
                exit_code = pil_loader.load_and_process_image(image_path)
                if exit_code == 0:
                    # Image processed successfully - use more realistic features
                    if viewer_name == "png_consumer":
                        base_features.extend([0.15, 0.08, 0.75, 0.03])  # PNG consumer with real image
                    elif viewer_name in ["eog", "firefox"]:
                        base_features.extend([0.35, 0.18, 0.55, 0.10])  # GUI viewers with real image
                    else:
                        base_features.extend([0.25, 0.12, 0.65, 0.06])   # Default with real image
                else:
                    # Image processing failed - fall back to synthetic features
                    logger.debug(f"pil_loader failed to process {image_path}, using synthetic features")
                    return FuzzingDataset._generate_synthetic_file_features(viewer_name, fuzz_type)
            except Exception as e:
                logger.debug(f"Error using pil_loader for {image_path}: {e}, using synthetic features")
                return FuzzingDataset._generate_synthetic_file_features(viewer_name, fuzz_type)
        else:
            # No image path or pil_loader not available - use synthetic features
            return FuzzingDataset._generate_synthetic_file_features(viewer_name, fuzz_type)
        
        # Add fuzz-type specific variations
        if fuzz_type == "uaf":
            base_features = [f * 1.2 for f in base_features]  # UAF often needs larger structures
        elif fuzz_type == "overflow":
            base_features = [f * 0.8 for f in base_features]  # Overflow can work with smaller data
        elif fuzz_type == "double_free":
            base_features = [f * 1.1 for f in base_features]  # Double free needs specific allocations
        
        # Add some random variation
        features = [f + random.gauss(0, 0.05) for f in base_features]
        return [max(0, min(1, f)) for f in features]  # Clamp to [0,1]
    
    @staticmethod
    def _generate_synthetic_file_features(viewer_name: str, fuzz_type: str) -> List[float]:
        """Generate synthetic file features when real image processing is not available."""
        base_features = []
        
        # File size features (normalized)
        if viewer_name == "png_consumer":
            base_features.extend([0.1, 0.05, 0.8, 0.02])  # Smaller files for png_consumer
        elif viewer_name in ["eog", "firefox"]:
            base_features.extend([0.3, 0.15, 0.6, 0.08])  # Larger files for GUI viewers
        else:
            base_features.extend([0.2, 0.1, 0.7, 0.05])   # Default
        
        # Add fuzz-type specific variations
        if fuzz_type == "uaf":
            base_features = [f * 1.2 for f in base_features]  # UAF often needs larger structures
        elif fuzz_type == "overflow":
            base_features = [f * 0.8 for f in base_features]  # Overflow can work with smaller data
        elif fuzz_type == "double_free":
            base_features = [f * 1.1 for f in base_features]  # Double free needs specific allocations
        
        # Add some random variation
        features = [f + random.gauss(0, 0.05) for f in base_features]
        return [max(0, min(1, f)) for f in features]  # Clamp to [0,1]
    
    @staticmethod
    def _generate_status_features(viewer_name: str, fuzz_type: str, chain_type: str) -> List[float]:
        """Generate status one-hot features."""
        # [success, crash, timeout, instrumentation_loaded, netcat_connected]
        status = [0.0, 0.0, 0.0, 0.0, 0.0]
        
        # Instrumentation more likely loaded for eog/firefox
        if viewer_name in ["eog", "firefox"]:
            status[3] = 0.8  # instrumentation_loaded
        else:
            status[3] = 0.2
        
        # Netcat more likely connected for successful chains
        if chain_type in ["ROP", "JOP"]:
            status[4] = 0.6  # netcat_connected
        elif chain_type in ["VOP", "DOP"]:
            status[4] = 0.4
        
        return status
    
    @staticmethod
    def _generate_gdb_features(viewer_name: str, fuzz_type: str, chain_type: str) -> List[float]:
        """Generate GDB crash features."""
        # [crash_detected, registers_valid, backtrace_depth, memory_access_violation, signal_code]
        features = [0.0, 0.0, 0.0, 0.0, 0.0]
        
        # Different fuzz types have different crash characteristics
        if fuzz_type == "uaf":
            features[3] = 0.7  # memory_access_violation
            features[4] = 11   # SIGSEGV
        elif fuzz_type == "overflow":
            features[3] = 0.8
            features[4] = 11
        elif fuzz_type == "double_free":
            features[3] = 0.6
            features[4] = 6    # SIGABRT
        
        # Chain types affect crash detection
        if chain_type in ["VOP", "DOP"]:
            features[0] = 0.4  # crash_detected (less reliable for VOP/DOP)
        else:
            features[0] = 0.7
        
        features[1] = 0.8  # registers_valid
        features[2] = min(20, random.randint(5, 15)) / 20.0  # backtrace_depth
        
        return features
    
    @staticmethod
    def _generate_leaked_address_features(viewer_name: str, fuzz_type: str) -> List[float]:
        """Generate leaked address features."""
        # [libc_leaked, heap_leaked, stack_leaked]
        features = [0.0, 0.0, 0.0]
        
        # png_consumer is better at leaking addresses
        if viewer_name == "png_consumer":
            features[0] = 0.9  # libc_leaked
            features[1] = 0.7  # heap_leaked
            features[2] = 0.5  # stack_leaked
        elif viewer_name in ["eog", "firefox"]:
            features[0] = 0.6
            features[1] = 0.4
            features[2] = 0.3
        else:
            features[0] = 0.3
            features[1] = 0.2
            features[2] = 0.1
        
        return features
    
    @staticmethod
    def _generate_apport_features(viewer_name: str, fuzz_type: str, chain_type: str) -> List[float]:
        """Generate apport crash features."""
        # [crash_reported, pac_trap, bti_trap, vop_trap, crash_severity]
        features = [0.0, 0.0, 0.0, 0.0, 0.0]
        
        # GUI viewers more likely to generate apport reports
        if viewer_name in ["eog", "firefox"]:
            features[0] = 0.8  # crash_reported
        else:
            features[0] = 0.3
        
        # VOP/DOP more likely to trigger specific traps
        if chain_type in ["VOP", "DOP"]:
            features[3] = 0.6  # vop_trap
        elif chain_type in ["ROP", "JOP"]:
            features[1] = 0.4  # pac_trap
            features[2] = 0.3  # bti_trap
        
        features[4] = random.randint(1, 10) / 10.0  # crash_severity
        
        return features
    
    @staticmethod
    def _generate_elf_features(viewer_name: str, fuzz_type: str, feature_size: int) -> List[float]:
        """Generate ELF features for the viewer."""
        features = []
        
        # Base features depend on viewer
        if viewer_name == "png_consumer":
            base_entropy = 0.7
            base_complexity = 0.8
        elif viewer_name in ["eog", "firefox"]:
            base_entropy = 0.6
            base_complexity = 0.9
        else:
            base_entropy = 0.5
            base_complexity = 0.6
        
        # Generate features with some correlation to fuzz type
        for i in range(feature_size):
            if i < 10:  # First 10 are entropy-related
                feature = base_entropy + random.gauss(0, 0.1)
            elif i < 20:  # Next 10 are complexity-related
                feature = base_complexity + random.gauss(0, 0.1)
            else:  # Rest are general ELF features
                feature = random.gauss(0.5, 0.2)
            
            features.append(max(0, min(1, feature)))
        
        return features
    
    @staticmethod
    def _calculate_success_probability(viewer_name: str, fuzz_type: str, chain_type: str, 
                                    payload_offset: int, trigger_offset: int, 
                                    max_payload_offset: int, max_trigger_offset: int) -> float:
        """Calculate success probability for a given combination."""
        base_prob = 0.1  # Base success rate
        
        # Viewer-specific success rates
        viewer_multipliers = {
            "png_consumer": 2.0,  # Best for exploitation
            "eog": 1.5,
            "firefox": 1.3,
            "default": 1.0
        }
        viewer_mult = viewer_multipliers.get(viewer_name, viewer_multipliers["default"])
        
        # Fuzz type success rates
        fuzz_multipliers = {
            "uaf": 1.8,
            "overflow": 2.0,
            "double_free": 1.5,
            "metadata_trigger": 1.2,
            "default": 1.0
        }
        fuzz_mult = fuzz_multipliers.get(fuzz_type, fuzz_multipliers["default"])
        
        # Chain type success rates
        chain_multipliers = {
            "ROP": 1.5,
            "JOP": 1.3,
            "VOP": 1.2,
            "DOP": 1.1,
            "default": 1.0
        }
        chain_mult = chain_multipliers.get(chain_type, chain_multipliers["default"])
        
        # Offset penalties - extreme offsets are less likely to succeed
        payload_norm = payload_offset / max(1, max_payload_offset)
        trigger_norm = trigger_offset / max(1, max_trigger_offset)
        
        # Gaussian penalty for extreme offsets
        import math
        offset_penalty = math.exp(-((payload_norm - 0.5)**2 + (trigger_norm - 0.5)**2) / 0.2)
        
        probability = base_prob * viewer_mult * fuzz_mult * chain_mult * offset_penalty
        return min(0.95, max(0.01, probability))  # Clamp to reasonable range

    def __len__(self):
        return len(self.samples)

    def __getitem__(self, idx) -> Tuple[torch.Tensor, torch.Tensor]:
        sample = self.samples[idx]
        
        # Build input feature vector
        input_features = (
            sample.file_features +
            sample.status_one_hot +
            sample.gdb_crash_features +
            sample.leaked_addresses_features +
            sample.apport_crash_features +
            sample.elf_features +
            [sample.payload_offset_attempted / max(1, self.max_payload_offset)] +
            [sample.trigger_offset_attempted / max(1, self.max_trigger_offset)]
        )
        
        # Build output feature vector (one-hot encoded)
        fuzz_type_one_hot = [1.0 if ft == sample.fuzz_type else 0.0 for ft in self.fuzz_types]
        chain_type_one_hot = [1.0 if ct == sample.chain_type_prediction else 0.0 for ct in self.chain_types]
        
        # Normalized offsets as regression targets
        normalized_payload_offset = [sample.payload_offset_attempted / max(1, self.max_payload_offset)]
        normalized_trigger_offset = [sample.trigger_offset_attempted / max(1, self.max_trigger_offset)]
        
        output_features = (
            fuzz_type_one_hot +
            chain_type_one_hot +
            normalized_payload_offset +
            normalized_trigger_offset
        )
        
        input_tensor = torch.tensor(input_features, dtype=torch.float32)
        output_tensor = torch.tensor(output_features, dtype=torch.float32)
        
        return input_tensor, output_tensor


class Encoder(nn.Module):
    def __init__(self, input_dim, latent_dim):
        super().__init__()
        self.latent_dim = latent_dim # Store latent_dim as an attribute
        self.fc1 = nn.Linear(input_dim, 512)
        self.fc2 = nn.Linear(512, 256)
        self.fc_mu = nn.Linear(256, latent_dim)
        self.fc_logvar = nn.Linear(256, latent_dim)
        self.relu = nn.ReLU()

    def forward(self, x):
        h = self.relu(self.fc1(x))
        h = self.relu(self.fc2(h))
        mu = self.fc_mu(h)
        logvar = self.fc_logvar(h)
        return mu, logvar

class Decoder(nn.Module):
    def __init__(self, latent_dim, output_dim):
        super().__init__()
        self.fc1 = nn.Linear(latent_dim, 256)
        self.fc2 = nn.Linear(256, 512)
        self.fc3 = nn.Linear(512, output_dim)
        self.relu = nn.ReLU()
        self.sigmoid = nn.Sigmoid() # For normalized outputs

    def forward(self, z):
        h = self.relu(self.fc1(z))
        h = self.relu(self.fc2(h))
        return self.sigmoid(self.fc3(h)) # Sigmoid for outputs between 0 and 1

class Discriminator(nn.Module):
    def __init__(self, input_dim):
        super().__init__()
        self.fc1 = nn.Linear(input_dim, 512)
        self.fc2 = nn.Linear(512, 256)
        self.fc3 = nn.Linear(256, 1)
        self.relu = nn.ReLU()

    def forward(self, x):
        h = self.relu(self.fc1(x))
        h = self.relu(self.fc2(h))
        return self.fc3(h)

class VAEGAN(nn.Module):
    def __init__(self, input_dim, latent_dim, output_dim):
        super().__init__()
        self.encoder = Encoder(input_dim, latent_dim)
        self.decoder = Decoder(latent_dim, output_dim)
        self.discriminator = Discriminator(output_dim) # Discriminator takes generated output
        self.input_dim = input_dim # Store input_dim as an attribute
        self.output_dim = output_dim # Store output_dim as an attribute
        self.latent_dim = latent_dim # Store latent_dim as an attribute 
    
    def encode(self, x):
        return self.encoder(x)

    def decode(self, z):
        return self.decoder(z)

    def forward(self, x):
        mu, logvar = self.encoder(x)
        std = torch.exp(0.5 * logvar)
        eps = torch.randn_like(std)
        z = mu + eps * std # Reparameterization trick
        reconstructed_x = self.decoder(z)
        return reconstructed_x, mu, logvar, z

    def get_raw_output(self, input_features: torch.Tensor) -> torch.Tensor:
        """
        Returns the raw output from the decoder given input features.
        This is useful for LIME explanations.
        """
        self.eval() # Ensure model is in evaluation mode
        with torch.no_grad():
            mu, logvar = self.encoder(input_features)
            std = torch.exp(0.5 * logvar)
            eps = torch.randn_like(std)
            z = mu + eps * std
            raw_output = self.decoder(z)
        return raw_output


class AddressOracle(nn.Module):
    """Neural network to predict gadget addresses based on process features."""
    
    def __init__(self, input_dim, output_dim):
        super().__init__()
        
        # Use LayerNorm instead of BatchNorm for stability with small batches
        self.net = nn.Sequential(
            nn.Linear(input_dim, 256),
            nn.LayerNorm(256),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(256, 128),
            nn.LayerNorm(128),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(128, 64),
            nn.LayerNorm(64),
            nn.ReLU(),
            nn.Linear(64, output_dim)
        )
        
        # Initialize weights with proper scaling
        self._init_weights()
    
    def _init_weights(self):
        """Initialize network weights using Kaiming initialization."""
        for module in self.modules():
            if isinstance(module, nn.Linear):
                nn.init.kaiming_normal_(module.weight, mode='fan_out', nonlinearity='relu')
                if module.bias is not None:
                    nn.init.constant_(module.bias, 0.0)
            elif isinstance(module, nn.LayerNorm):
                nn.init.constant_(module.weight, 1.0)
                nn.init.constant_(module.bias, 0.0)

    def forward(self, x):
        return self.net(x)


def collect_address_features(pid: int,
                             elf_features: List[float],
                             viewer_name: str,
                             viewers: List[str],
                             payload_offset: Optional[int] = None,
                             trigger_offset: Optional[int] = None,
                             instrumentation_loaded: float = 0.0) -> List[float]:
    """Collect features for AddressOracle from procfs, process state, and ELF metadata."""
    try:
        process = psutil.Process(pid)
        process_age = time.time() - process.create_time()
        uptime = time.time() - psutil.boot_time()
        cpu_times = process.cpu_times()
        memory_info = process.memory_info()
        num_threads = process.num_threads()

        proc_maps = _parse_proc_maps(pid)
        proc_stats = _read_procfs_process_stats(pid)
        cpu_gpu_regs = _sample_cpu_gpu_registers()
        normalized_elf = normalize_feature_vector(elf_features)

        viewer_one_hot = [1.0 if v == viewer_name else 0.0 for v in viewers]

        import datetime
        now = datetime.datetime.now()
        hour_of_day = now.hour / 24.0
        minute_of_hour = now.minute / 60.0
        second_of_minute = now.second / 60.0
        day_of_week = now.weekday() / 7.0

        features = [
            min(process_age / 3600.0, 1.0),
            min(uptime / 86400.0, 1.0),
            cpu_times.user / 100.0,
            cpu_times.system / 100.0,
            min(memory_info.rss / float(2**30), 1.0),
            min(memory_info.vms / float(2**30), 1.0),
            min(num_threads / 100.0, 1.0),
            proc_maps['main_base'],
            proc_maps['libc_base'],
            proc_maps['heap_start'],
            proc_maps['stack_start'],
            proc_maps['mmap_count'],
            proc_maps['text_map_count'],
            proc_stats.get('aslr_enabled', 0.0),
            proc_stats.get('randomize_va_space', 0.0),
            proc_stats.get('entropy_avail', 0.0),
            proc_stats.get('rss_mb', 0.0),
            proc_stats.get('shared_clean', 0.0),
            proc_stats.get('major_faults', 0.0),
            hour_of_day,
            minute_of_hour,
            second_of_minute,
            day_of_week,
        ] + cpu_gpu_regs + normalized_elf + viewer_one_hot

        if payload_offset is not None and trigger_offset is not None:
            features += [
                min(1.0, payload_offset / 16384.0),
                min(1.0, trigger_offset / 16384.0),
                min(1.0, max(0.0, min(1.0, instrumentation_loaded)))
            ]
        else:
            features += [0.0, 0.0, min(1.0, max(0.0, instrumentation_loaded))]

        return features
    except Exception as e:
        logger.warning(f"Failed to collect features for pid {pid}: {e}")
        return get_system_features() + [0.0] * 8 + normalize_feature_vector(elf_features) + [1.0 if v == viewer_name else 0.0 for v in viewers] + [0.0, 0.0, min(1.0, max(0.0, instrumentation_loaded))]


def _read_procfs_value(path: str, default: float = 0.0) -> float:
    """Safely read an integer-valued procfs file and return a float."""
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as fh:
            text = fh.read().strip().split()[0]
        return float(text)
    except Exception:
        return default


def _read_procfs_process_stats(pid: int) -> Dict[str, float]:
    """Collect additional procfs-based process statistics for the address oracle."""
    stats = {
        'aslr_enabled': 0.0,
        'randomize_va_space': 0.0,
        'entropy_avail': 0.0,
        'rss_mb': 0.0,
        'shared_clean': 0.0,
        'major_faults': 0.0,
    }
    try:
        stats['aslr_enabled'] = 1.0 if _read_procfs_value('/proc/sys/kernel/randomize_va_space', 0.0) > 0 else 0.0
        stats['randomize_va_space'] = min(1.0, max(0.0, _read_procfs_value('/proc/sys/kernel/randomize_va_space', 0.0) / 2.0))
        stats['entropy_avail'] = min(1.0, max(0.0, _read_procfs_value('/proc/sys/kernel/entropy_avail', 0.0) / 4096.0))
    except Exception:
        pass

    status_path = f'/proc/{pid}/status'
    if os.path.exists(status_path):
        try:
            with open(status_path, 'r', encoding='utf-8', errors='ignore') as fh:
                for line in fh:
                    if line.startswith('VmRSS:'):
                        stats['rss_mb'] = min(1.0, float(line.split()[1]) / 1024.0 / 1024.0)
                    elif line.startswith('RssShmem:'):
                        stats['shared_clean'] = min(1.0, float(line.split()[1]) / 1024.0 / 1024.0)
        except Exception:
            pass

    stat_path = f'/proc/{pid}/stat'
    if os.path.exists(stat_path):
        try:
            with open(stat_path, 'r', encoding='utf-8', errors='ignore') as fh:
                parts = fh.read().split()
            if len(parts) > 12:
                stats['major_faults'] = min(1.0, float(parts[11]) / 100000.0)
        except Exception:
            pass

    return stats


def get_system_features() -> List[float]:
    """Get system-level features for AddressOracle when process is not available."""
    try:
        uptime = time.time() - psutil.boot_time()
        
        # Add time of day features
        import datetime
        now = datetime.datetime.now()
        hour_of_day = now.hour / 24.0
        minute_of_hour = now.minute / 60.0
        second_of_minute = now.second / 60.0
        day_of_week = now.weekday() / 7.0  # 0=Monday, 6=Sunday
        
        # System load averages
        load1, load5, load15 = psutil.getloadavg()
        load1_norm = min(load1 / 10.0, 1.0)
        load5_norm = min(load5 / 10.0, 1.0)
        load15_norm = min(load15 / 10.0, 1.0)
        
        return [
            0.0,  # process_age (not available)
            min(uptime / 86400.0, 1.0),
            0.0,  # cpu_times.user (not available)
            0.0,  # cpu_times.system (not available)
            0.0,  # memory_info.rss (not available)
            0.0,  # memory_info.vms (not available)
            0.0,  # num_threads (not available)
            0.0,  # main_base (not available)
            0.0,  # libc_base (not available)
            0.0,  # heap_start (not available)
            0.0,  # stack_start (not available)
            load1_norm,  # mmap_count -> system load1
            load5_norm,  # text_map_count -> system load5
            hour_of_day,
            minute_of_hour,
            second_of_minute,
            day_of_week,
        ]
    except Exception as e:
        logger.warning(f"Failed to collect system features: {e}")
        return [0.0] * 17


def _sample_cpu_gpu_registers() -> List[float]:
    """Sample CPU/GPU state registers from current process context."""
    try:
        # CPU register features from current process
        import ctypes
        cpu_percent = min(psutil.cpu_percent(interval=0.01) / 100.0, 1.0) if hasattr(psutil, 'cpu_percent') else 0.0
        
        # Memory pressure indicator (used vs available)
        virtual_memory = psutil.virtual_memory()
        mem_percent = virtual_memory.percent / 100.0
        swap_percent = psutil.swap_memory().percent / 100.0 if hasattr(psutil, 'swap_memory') else 0.0
        
        # CPU frequency state (normalized)
        try:
            cpu_freq = psutil.cpu_freq()
            freq_percent = (cpu_freq.current - cpu_freq.min) / max(1, cpu_freq.max - cpu_freq.min) if cpu_freq else 0.0
        except Exception:
            freq_percent = 0.0
        
        # Context switch rate indicator
        try:
            ctx_switches = psutil.cpu_stats().ctx_switches
            ctx_switch_norm = min(ctx_switches / 1000000.0, 1.0)
        except Exception:
            ctx_switch_norm = 0.0
        
        # GPU simulation (if GPU available, sample from nvidia-smi or similar)
        gpu_util = 0.0
        gpu_mem = 0.0
        try:
            # Try to read GPU info
            import subprocess
            result = subprocess.run(
                ['nvidia-smi', '--query-gpu=utilization.gpu,utilization.memory', '--format=csv,noheader,nounits'],
                capture_output=True, text=True, timeout=1
            )
            if result.returncode == 0:
                parts = result.stdout.strip().split(',')
                if len(parts) >= 2:
                    gpu_util = min(float(parts[0].strip()) / 100.0, 1.0)
                    gpu_mem = min(float(parts[1].strip()) / 100.0, 1.0)
        except Exception:
            gpu_util = 0.0
            gpu_mem = 0.0
        
        return [
            cpu_percent,
            mem_percent,
            swap_percent,
            freq_percent,
            ctx_switch_norm,
            gpu_util,
            gpu_mem,
            (cpu_percent + gpu_util) / 2.0,  # Combined CPU+GPU utilization
        ]
    except Exception as e:
        logger.debug(f"Failed to sample CPU/GPU registers: {e}")
        return [0.0] * 8


def _parse_proc_maps(pid: int) -> Dict[str, float]:
    """Extract normalized base addresses and memory region layout from /proc/<pid>/maps."""
    maps_info = {
        'main_base': 0.0,
        'libc_base': 0.0,
        'heap_start': 0.0,
        'stack_start': 0.0,
        'mmap_count': 0.0,
        'text_map_count': 0.0,
    }
    maps_path = f'/proc/{pid}/maps'
    if not os.path.exists(maps_path):
        return maps_info

    try:
        exe_path = None
        try:
            process = psutil.Process(pid)
            exe_path = process.exe()
        except Exception:
            exe_path = None

        main_base = None
        libc_base = None
        heap_start = 0
        stack_start = 0
        mmap_count = 0
        text_map_count = 0

        with open(maps_path, 'r') as f:
            for line in f:
                mmap_count += 1
                parts = line.strip().split()
                if len(parts) < 6:
                    continue
                addr_range, perms, offset, dev, inode = parts[:5]
                pathname = parts[5] if len(parts) >= 6 else ''
                start_str, _ = addr_range.split('-')
                start_addr = int(start_str, 16)

                if 'x' in perms:
                    text_map_count += 1

                normalized_addr = start_addr / float(2**20)
                if pathname and exe_path and os.path.realpath(pathname) == os.path.realpath(exe_path):
                    if main_base is None:
                        main_base = normalized_addr
                if pathname and 'libc' in pathname and libc_base is None:
                    libc_base = normalized_addr
                if pathname and ('ld-' in pathname or 'ld-linux' in pathname) and libc_base is None:
                    libc_base = normalized_addr
                if pathname == '[heap]' and heap_start == 0:
                    heap_start = normalized_addr
                if pathname == '[stack]' and stack_start == 0:
                    stack_start = normalized_addr

        if main_base is not None:
            maps_info['main_base'] = main_base
        if libc_base is not None:
            maps_info['libc_base'] = libc_base
        maps_info['heap_start'] = heap_start
        maps_info['stack_start'] = stack_start
        maps_info['mmap_count'] = float(mmap_count) / 200.0
        maps_info['text_map_count'] = float(text_map_count) / 50.0
    except Exception:
        return maps_info

    return maps_info


def parse_gadget_addresses(gdb_output: str) -> Dict[str, int]:
    """Parse gadget addresses from GDB output."""
    addresses = {}
    import re
    pattern = r'INJECTED_GADGET\s+(\w+):\s+(0x[0-9a-f]+)'
    matches = re.findall(pattern, gdb_output, re.IGNORECASE)
    for name, addr_str in matches:
        addresses[name] = int(addr_str, 16)
    return addresses


def convert_deltas_to_absolute_addresses(predicted_deltas: torch.Tensor, base_address: int, libc_base: int = None) -> Dict[str, int]:
    """Convert predicted address deltas to absolute addresses for exploitation.
    
    Args:
        predicted_deltas: Tensor of predicted address offsets from the model
        base_address: Base address of the target executable/library (from AddressOracle features)
        libc_base: Optional libc base address for ROP gadgets in libc
    
    Returns:
        Dictionary mapping gadget names to absolute addresses
    """
    gadget_names = [
        "pop_x0_x1_ret", "ldr_x0_x1_br_x0", "vop_ldr_str_q0",
        "pacia_x30", "autia_x30", "ldraa_x0_x1",
        "blraa_x0", "vop_ldr_d0_x1", "vop_str_d0_x0"
    ]
    
    addresses = {}
    if isinstance(predicted_deltas, torch.Tensor):
        deltas = predicted_deltas.detach().cpu().numpy().astype(int)
    else:
        deltas = np.array(predicted_deltas, dtype=int)
    
    # Use libc_base for most gadgets, fallback to base_address
    for i, name in enumerate(gadget_names):
        if i < len(deltas):
            offset = deltas[i]
            # Alternate between base and libc addresses for variety
            selected_base = libc_base if (libc_base and i % 2 == 0) else base_address
            addresses[name] = selected_base + offset
    
    return addresses


def compute_feature_weights(dataset: AddressDataset) -> torch.Tensor:
    """Compute feature importance weights based on correlation coefficients with targets.
    
    Features with higher absolute correlation to address deltas get higher weights,
    helping the model focus on the most predictive features during training.
    """
    if len(dataset) == 0:
        return None
    
    if len(dataset) < 8:
        logger.info("Too few samples for reliable feature correlation weighting; skipping.")
        return None
    
    # Collect all inputs and targets
    all_inputs = []
    all_targets = []
    
    for i in range(len(dataset)):
        inputs, targets = dataset[i]
        all_inputs.append(inputs.numpy())
        all_targets.append(targets.numpy())
    
    all_inputs = np.array(all_inputs)  # Shape: (num_samples, num_features)
    all_targets = np.array(all_targets)  # Shape: (num_samples, num_outputs)

    # Check for zero variance features and skip weighting if all features have low variance to avoid adding noise 
    feature_variances = np.var(all_inputs, axis=0)
    if np.all(feature_variances < 1e-6):
        logger.info("All features have near-zero variance; skipping feature weighting to avoid adding noise.")
        return None
    


    # Compute correlation coefficient for each feature with each output
    num_features = all_inputs.shape[1]
    num_outputs = all_targets.shape[1]
    
    feature_correlations = np.zeros(num_features)
    
    for feat_idx in range(num_features):
        feature_vals = all_inputs[:, feat_idx]
        # Compute max correlation across all outputs
        max_corr = 0.0
        for out_idx in range(num_outputs):
            target_vals = all_targets[:, out_idx]
            # Standardize for correlation
            if np.std(feature_vals) > 1e-6 and np.std(target_vals) > 1e-6:
                corr = np.abs(np.corrcoef(feature_vals, target_vals)[0, 1])
                max_corr = max(max_corr, corr)
        feature_correlations[feat_idx] = max_corr
    
    # Convert correlations to weights: use sqrt to soften extreme differences
    # Add small epsilon to avoid zero weights
    weights = np.sqrt(np.abs(feature_correlations) + 0.01)
    
    if np.allclose(weights, weights[0], atol=1e-4):
        logger.info("Feature correlation weights are uniform; skipping weighting.")
        return None

    # Normalize weights to mean=1.0 and clamp to avoid extreme scaling
    weights = weights / np.mean(weights)
    weights = np.clip(weights, 0.5, 2.0)

    logger.info(f"Feature weights computed from {len(dataset)} samples:")
    logger.info(f"  Raw corr min/max: {feature_correlations.min():.4f}/{feature_correlations.max():.4f}")
    logger.info(f"  Weight min/max: {weights.min():.4f}/{weights.max():.4f}, mean: {weights.mean():.4f}")

    return torch.tensor(weights, dtype=torch.float32)


def train_address_oracle(model: AddressOracle, dataset: AddressDataset, epochs: int = 100, device: str = "cpu", writer: SummaryWriter = None) -> float:
    """Train AddressOracle with feature weighting, learning rate scheduling, and gradient clipping."""
    if len(dataset) == 0:
        return 0.0
    
    # Compute feature weights based on correlation
    feature_weights = compute_feature_weights(dataset)
    all_inputs = []
    all_targets = []
    for inputs, targets in dataset:
        all_inputs.append(inputs.numpy())
        all_targets.append(targets.numpy())
    if all_inputs and all_targets:
        corr_summary = summarize_feature_correlation(np.array(all_inputs), np.array(all_targets), feature_names=[f"feature_{i}" for i in range(len(all_inputs[0]))])
        if corr_summary.get("top_features"):
            logger.info("AddressOracle feature correlation summary: %s", json.dumps(corr_summary, sort_keys=True))
    
    #if the feature_weights are all close to 1.0, skip weighting during training to avoid adding noise 
    if feature_weights is not None and min(feature_weights) > 0.99 and max(feature_weights) < 1.01: 
        logger.info("Feature weights are all close to 1.0, skipping weighting during training") 
        feature_weights = None
    #add mutual information based feature selection in the future to further improve training efficiency and accuracy by focusing on the most predictive features and reducing noise from less relevant ones 
    #use mutual_info_regression from sklearn to compute mutual information between each feature and the target addresses, then select top-k features based on mutual information scores to train the model, which can help improve accuracy and reduce overfitting by focusing on the most informative features for address prediction 
    if feature_weights is not None:
        logger.info("Applying feature weighting during training")
    else :
        logger.info("No significant feature weighting applied during training")

    #if feature_weights is not None:
    # Split dataset for validation
    train_size = int(0.8 * len(dataset))
    val_size = len(dataset) - train_size
    train_dataset, val_dataset = torch.utils.data.random_split(dataset, [train_size, val_size])
    
    train_dataloader = DataLoader(train_dataset, batch_size=32, shuffle=True)
    val_dataloader = DataLoader(val_dataset, batch_size=32, shuffle=False)
    
    optimizer = optim.Adam(model.parameters(), lr=1e-3)
    criterion = nn.MSELoss()
    
    # Learning rate scheduler: reduce LR when validation loss plateaus
    scheduler = optim.lr_scheduler.ReduceLROnPlateau(
        optimizer, mode='min', factor=0.5, patience=20
    )
    
    model.to(device)
    model.double()
    
    if feature_weights is not None:
        feature_weights = feature_weights.to(device)
    
    best_val_loss = float('inf')
    patience_counter = 0
    max_patience = 50
    
    for epoch in range(epochs):
        # Training phase
        model.train()
        total_loss = 0
        for inputs, targets in train_dataloader:
            inputs, targets = inputs.to(device).double(), targets.to(device).double()
            
            # Apply feature weighting to inputs
            if feature_weights is not None:
                weighted_inputs = inputs * feature_weights.unsqueeze(0)
            else:
                weighted_inputs = inputs
            
            optimizer.zero_grad()
            outputs = model(weighted_inputs)
            loss = criterion(outputs, targets)
            loss.backward()
            
            # Gradient clipping to prevent exploding gradients
            #torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
            
            optimizer.step()
            total_loss += loss.item()
        
        train_loss = total_loss / len(train_dataloader)
        
        # Validation phase
        model.eval()
        val_loss = 0.0
        with torch.no_grad():
            for inputs, targets in val_dataloader:
                inputs, targets = inputs.to(device).double(), targets.to(device).double()
                
                if feature_weights is not None:
                    weighted_inputs = inputs * feature_weights.unsqueeze(0)
                else:
                    weighted_inputs = inputs
                
                outputs = model(weighted_inputs)
                loss = criterion(outputs, targets)
                val_loss += loss.item()
        
        val_loss = val_loss / len(val_dataloader) if len(val_dataloader) > 0 else 0.0
        
        # Learning rate scheduling based on validation loss
        scheduler.step(val_loss)
        
        # Early stopping based on validation loss
        if val_loss < best_val_loss:
            best_val_loss = val_loss
            patience_counter = 0
        else:
            patience_counter += 1
        
        if epoch % 50 == 0:
            print(f"AddressOracle Epoch {epoch+1}/{epochs}, Train Loss: {train_loss:.4f}, Val Loss: {val_loss:.4f}")
        
        if writer:
            writer.add_scalar('AddressOracle/Train_Loss', train_loss, epoch)
            writer.add_scalar('AddressOracle/Val_Loss', val_loss, epoch)
        
        # Early stopping if validation loss doesn't improve
        if patience_counter >= max_patience:
            logger.info(f"Early stopping at epoch {epoch+1}: validation loss plateaued for {max_patience} epochs")
            break
    
    # Final evaluation on full dataset
    model.eval()
    total_mae = 0.0
    total_target_abs = 0.0
    count = 0
    full_dataloader = DataLoader(dataset, batch_size=32, shuffle=False)
    
    with torch.no_grad():
        for inputs, targets in full_dataloader:
            inputs, targets = inputs.to(device).double(), targets.to(device).double()
            
            if feature_weights is not None:
                weighted_inputs = inputs * feature_weights.unsqueeze(0)
            else:
                weighted_inputs = inputs
            
            outputs = model(weighted_inputs)
            mae = torch.mean(torch.abs(outputs - targets))
            total_mae += mae.item()
            total_target_abs += torch.mean(torch.abs(targets)).item()
            count += 1
    
    avg_mae = total_mae / count if count > 0 else 0.0
    avg_target_abs = total_target_abs / count if count > 0 else 1.0
    
    # Use RMSE-based accuracy metric: measure how well the model predicts within a tolerance band
    # Compute RMSE and convert to a 0-1 accuracy score
    # If MAE is very small (< 0.01), consider it excellent (0.95+ accuracy)
    # If MAE is moderate (0.01-0.1), scale accordingly
    # Formula: accuracy = exp(-5 * MAE) clamps between 0.007 and 1.0
    accuracy = float(np.exp(-5.0 * min(1.0, avg_mae)))  # Exponential decay for error-based accuracy
    
    print(f"AddressOracle Training MAE: {avg_mae:.4f}, Normalized accuracy: {accuracy:.4f}")
    if writer:
        writer.add_scalar('AddressOracle/Final_Accuracy', accuracy, epochs)
    return accuracy


def predict_addresses(oracle: AddressOracle, features: List[float], device: str = "cpu") -> List[int]:
    """Predict gadget addresses using the Oracle, converting predicted offsets to absolute addresses."""
    oracle.eval()
    with torch.no_grad():
        input_tensor = torch.tensor(features, dtype=torch.float32).unsqueeze(0).to(device).double()
        outputs = oracle(input_tensor).squeeze(0)
        main_base_norm = features[7] if len(features) > 7 else 0.0
        libc_base_norm = features[8] if len(features) > 8 else 0.0
        main_base = int(main_base_norm * (2**20))
        libc_base = int(libc_base_norm * (2**20))
        scaled_offsets = [float(offset) * ADDRESS_OFFSET_SCALE for offset in outputs.tolist()]
        return list(convert_deltas_to_absolute_addresses(scaled_offsets, main_base, libc_base).values())


def vae_loss(reconstructed_x, x, mu, logvar, criterion_recon):
    # Reconstruction loss (e.g., MSE or BCE)
    # Here, x is the target output (y from dataset), not the raw input
    recon_loss = criterion_recon(reconstructed_x, x)
    # KL divergence loss
    kl_div = -0.5 * torch.sum(1 + logvar - mu.pow(2) - logvar.exp())
    return recon_loss + kl_div

def train_vaegan(model: VAEGAN, dataset: FuzzingDataset, epochs: int, writer: SummaryWriter,
                 batch_size: int = 32, learning_rate: float = 1e-3,
                 kl_weight: float = 0.001, device: str = "cpu"):
    
    dataloader = DataLoader(dataset, batch_size=batch_size, shuffle=True)
    
    # Optimizers
    optimizer_encoder = optim.Adam(model.encoder.parameters(), lr=learning_rate)
    optimizer_decoder = optim.Adam(model.decoder.parameters(), lr=learning_rate)
    optimizer_discriminator = optim.Adam(model.discriminator.parameters(), lr=learning_rate)

    # Loss functions
    criterion_recon = nn.MSELoss()  # For continuous outputs (normalized offsets) and one-hot (can use MSE)
    criterion_gan = nn.BCEWithLogitsLoss()  # For discriminator logits

    model.to(device)

    for epoch in range(epochs):
        model.train()
        total_recon_loss = 0.0
        total_kl_loss = 0.0
        total_generator_loss = 0.0
        total_discriminator_loss = 0.0

        for batch_idx, (inputs, targets) in enumerate(dataloader):
            inputs, targets = inputs.to(device), targets.to(device)

            # --- Train Discriminator ---
            optimizer_discriminator.zero_grad()

            # Real samples
            real_output = model.discriminator(targets)
            loss_discriminator_real = criterion_gan(real_output, torch.ones_like(real_output))

            # Fake samples from VAE's decoder
            _, _, _, z_from_encoder = model.forward(inputs)  # Get latent z from encoder
            fake_samples_from_vae = model.decode(z_from_encoder.detach())  # Detach to not train decoder with D loss
            fake_output_vae = model.discriminator(fake_samples_from_vae)
            loss_discriminator_fake_vae = criterion_gan(fake_output_vae, torch.zeros_like(fake_output_vae))

            # Fake samples from random noise (pure GAN part)
            batch_size_actual = inputs.shape[0]
            z_random = torch.randn(batch_size_actual, model.encoder.latent_dim).to(device)
            fake_samples_random = model.decode(z_random.detach())
            fake_output_random = model.discriminator(fake_samples_random)
            loss_discriminator_fake_random = criterion_gan(fake_output_random, torch.zeros_like(fake_output_random))

            loss_discriminator = (loss_discriminator_real + loss_discriminator_fake_vae + loss_discriminator_fake_random) / 3.0
            loss_discriminator.backward()
            optimizer_discriminator.step()
            total_discriminator_loss += loss_discriminator.item()

            # --- Train Encoder and Decoder (Generator) ---
            optimizer_encoder.zero_grad()
            optimizer_decoder.zero_grad()

            reconstructed_x, mu, logvar, _ = model.forward(inputs)

            # VAE losses
            recon_loss = criterion_recon(reconstructed_x, targets)
            kl_loss = -0.5 * torch.sum(1 + logvar - mu.pow(2) - logvar.exp()) / float(batch_size_actual)

            # GAN loss for generator (decoder)
            fake_output_for_generator = model.discriminator(reconstructed_x)
            loss_generator = criterion_gan(fake_output_for_generator, torch.ones_like(fake_output_for_generator))

            # Combined loss for VAE-GAN
            total_loss_vae_gan = recon_loss + kl_weight * kl_loss + loss_generator
            total_loss_vae_gan.backward()

            optimizer_encoder.step()
            optimizer_decoder.step()

            total_recon_loss += recon_loss.item()
            total_kl_loss += kl_loss.item()
            total_generator_loss += loss_generator.item()

        avg_recon_loss = total_recon_loss / len(dataloader)
        avg_kl_loss = total_kl_loss / len(dataloader)
        avg_generator_loss = total_generator_loss / len(dataloader)
        avg_discriminator_loss = total_discriminator_loss / len(dataloader)

        if torch.isnan(torch.tensor([avg_recon_loss, avg_kl_loss, avg_generator_loss, avg_discriminator_loss])).any():
            logger.warning("NaN detected in VAEGAN training losses. Stopping training early.")
            break

        print(f"Epoch {epoch+1}/{epochs}, "
              f"Recon Loss: {avg_recon_loss:.4f}, "
              f"KL Loss: {avg_kl_loss:.4f}, "
              f"Gen Loss: {avg_generator_loss:.4f}, "
              f"Disc Loss: {avg_discriminator_loss:.4f}")

        if writer:
            writer.add_scalar('Loss/Reconstruction', avg_recon_loss, epoch)
            writer.add_scalar('Loss/KL_Divergence', avg_kl_loss, epoch)
            writer.add_scalar('Loss/Generator', avg_generator_loss, epoch)
            writer.add_scalar('Loss/Discriminator', avg_discriminator_loss, epoch)

    return avg_recon_loss

def generate_suggestion(model: VAEGAN, input_features: torch.Tensor,
                        fuzz_types: List[str], chain_types: List[str], # Added chain_types
                        max_payload_offset: int, max_trigger_offset: int,
                        *, device: str = "cpu") -> InstrumentationSuggestion: # Made 'device' keyword-only
    """
    Generates an instrumentation suggestion from the trained VAE/GAN model.
    """
    model.eval()
    with torch.no_grad():
        input_features = input_features.to(device) #will return a tensor of shape (input_dim,) which is correct for encoder input 

        # Use the encoder to get mu and logvar, then sample z 
        # fix RuntimeError: mat1 and mat2 shapes cannot be multiplied (1x30 and 40x512) by ensuring input_features has the correct shape 
        if input_features.dim() == 1:
            input_features = input_features.unsqueeze(0) # Add batch dimension if missing 
        
        mu, logvar = model.encode(input_features) # Add batch dimension
        std = torch.exp(0.5 * logvar)
        eps = torch.randn_like(std)
        z = mu + eps * std
        
        # Decode z to get the predicted output
        predicted_output = model.decode(z).squeeze(0) # Remove batch dimension

        # Interpret the output
        # The first `len(fuzz_types)` elements are one-hot encoded fuzz_type
        fuzz_type_probs = predicted_output[:len(fuzz_types)]
        predicted_fuzz_type_idx = torch.argmax(fuzz_type_probs).item()
        predicted_fuzz_type = fuzz_types[predicted_fuzz_type_idx]

        # The next `len(chain_types)` elements are one-hot encoded chain_type
        chain_type_probs = predicted_output[len(fuzz_types) : len(fuzz_types) + len(chain_types)]
        predicted_chain_type_idx = torch.argmax(chain_type_probs).item()
        predicted_chain_type = chain_types[predicted_chain_type_idx]

        # The next element is normalized payload_offset
        predicted_normalized_payload_offset = predicted_output[len(fuzz_types) + len(chain_types)].item()
        predicted_payload_offset = int(predicted_normalized_payload_offset * max_payload_offset)

        # The last element is normalized trigger_offset
        predicted_normalized_trigger_offset = predicted_output[len(fuzz_types) + len(chain_types) + 1].item()
        predicted_trigger_offset = int(predicted_normalized_trigger_offset * max_trigger_offset)

        # Confidence could be derived from the max probability of fuzz_type_probs
        confidence = torch.max(fuzz_type_probs).item() # Or a combined confidence

        return InstrumentationSuggestion(
            fuzz_type_prediction=predicted_fuzz_type,
            payload_offset_prediction=predicted_payload_offset,
            trigger_offset_prediction=predicted_trigger_offset,
            chain_type_prediction=predicted_chain_type, # New: Include chain_type_prediction
            confidence=confidence
        ), predicted_output # Return predicted_output (reconstructed_x) for LIME




    # NOTE: predict_proba and predict_chain_type_proba are defined below inside __main__
    # because they require the trained `model`, `device` and the dummy class lists in scope.

  
  
  
  
    

if __name__ == "__main__":
    print("--- Testing ml_fuzzer_model.py ---")

    # Dummy data for testing
    dummy_fuzz_types = ["uaf", "overflow", "metadata_trigger"]
    dummy_chain_types = ["ROP", "JOP", "DOP","VOP"] # New: Dummy chain types
    dummy_max_payload_offset = 1024
    dummy_max_trigger_offset = 512
    dummy_trigger_offset_attempted = 128 # Example trigger offset for testing

    # Test comprehensive dataset creation with pil_loader for PIL samples
    print("\n--- Testing Comprehensive Dataset Creation ---")
    test_viewers = ["png_consumer", "eog", "firefox"]
    
    # Try to find some PNG files for real image processing
    import glob
    image_paths = []
    if PIL_AVAILABLE:
        # Look for PNG files in common directories
        search_paths = ["generated_image_samples/*.png", "test_images/*.png", "*.png"]
        for pattern in search_paths:
            found = glob.glob(pattern)
            image_paths.extend(found[:5])  # Limit to 5 images for testing
        
        if image_paths:
            print(f"Found {len(image_paths)} PNG files for real image processing with pil_loader")
        else:
            print("No PNG files found, will use synthetic features only")
    
    # Create comprehensive dataset
    comprehensive_dataset = FuzzingDataset.create_comprehensive_dataset(
        viewers=test_viewers,
        fuzz_types=dummy_fuzz_types,
        chain_types=dummy_chain_types,
        max_payload_offset=dummy_max_payload_offset,
        max_trigger_offset=dummy_max_trigger_offset,
        elf_feature_size=50,
        image_paths=image_paths if PIL_AVAILABLE else None
    )
    
    print(f"Comprehensive dataset created with {len(comprehensive_dataset)} samples")
    print(f"Input dimension: {comprehensive_dataset.input_dim}")
    print(f"Output dimension: {comprehensive_dataset.output_dim}")

    # Create some dummy FuzzingSample instances for backward compatibility testing
    dummy_samples = [
        FuzzingSample(
            viewer_name="eog", fuzz_type="uaf", file_features=[0.5], payload_offset_attempted=100,
            status_one_hot=[0,1,0,0,0], gdb_crash_features=[1,0,5,0,0], leaked_addresses_features=[1,2,0],
            apport_crash_features=[0.1,0.2,0.3,0.4,5], success_label=0, elf_features=[0.0]*50,
            chain_type_prediction="ROP",
            trigger_offset_attempted=dummy_trigger_offset_attempted
        ),
        FuzzingSample(
            viewer_name="firefox", fuzz_type="overflow", file_features=[1.2], payload_offset_attempted=250,
            status_one_hot=[1,0,0,0,0], gdb_crash_features=[0,0,0,0,0], leaked_addresses_features=[0,0,0],
            apport_crash_features=[0,0,0,0,0], success_label=1, elf_features=[0.0]*50,
            chain_type_prediction="JOP",
            trigger_offset_attempted=dummy_trigger_offset_attempted
        ),
        FuzzingSample(
            viewer_name="eog", fuzz_type="metadata_trigger", file_features=[0.8], payload_offset_attempted=50,
            status_one_hot=[0,0,1,0,0], gdb_crash_features=[0,1,3,0,0], leaked_addresses_features=[1,1,0],
            apport_crash_features=[0.5,0.6,0.7,0.8,3], success_label=0, elf_features=[0.0]*50,
            chain_type_prediction="ROP",
            trigger_offset_attempted=dummy_trigger_offset_attempted
        ),
    ]

    # Use comprehensive dataset for training instead of dummy samples
    dataset = comprehensive_dataset

    input_dim = dataset.input_dim
    output_dim = dataset.output_dim
    latent_dim = 20 # Example latent dimension

    print(f"Input Dimension: {input_dim}")
    print(f"Output Dimension: {output_dim}")

    model = VAEGAN(input_dim, latent_dim, output_dim)
    print("\nVAEGAN Model Architecture:")
    print(model)

    # Check for GPU
    device = "cuda" if torch.cuda.is_available() else "cpu"
    print(f"\nUsing device: {device}")

    # Create a dummy TensorBoard writer
    writer = SummaryWriter("runs/fuzzing_test")

    # Train the model
    print("\nStarting VAEGAN training with dummy data...")
    train_vaegan(model, dataset, epochs=50, writer=writer, batch_size=1, device=device)
    print("Training complete.")

    # Test suggestion generation
    print("\nGenerating a suggestion:")
    # Create a dummy input feature tensor for inference
    # This should match the structure of x in FuzzingDataset.__getitem__
    dummy_input_features = torch.tensor(
        dummy_samples[0].file_features +
        dummy_samples[0].status_one_hot +
        dummy_samples[0].gdb_crash_features +
        dummy_samples[0].leaked_addresses_features +
        dummy_samples[0].apport_crash_features +
        dummy_samples[0].elf_features + # New: Include elf_features
        [dummy_samples[0].payload_offset_attempted / dummy_max_payload_offset,
         dummy_samples[0].trigger_offset_attempted / dummy_max_trigger_offset], # Include trigger_offset
        dtype=torch.float32
    )
    
    suggestion,tensor = generate_suggestion(model, dummy_input_features, dummy_fuzz_types, dummy_chain_types, # Pass chain_types
                                     dummy_max_payload_offset, dummy_max_trigger_offset, device=device)
    print(f"\n Debug : Generated Instrumentation Suggestion:{suggestion}\n\n")
    #check for attribute fuzz_type_prediction 
    
    
    
    if hasattr(suggestion, 'fuzz_type_prediction'):
        print(f"Suggested Fuzz Type: {suggestion.fuzz_type_prediction}")
    
    print(f"Suggested Payload Offset: {suggestion.payload_offset_prediction}")
    print(f"Suggested Trigger Offset: {suggestion.trigger_offset_prediction}")
    print(f"Suggested Chain Type: {suggestion.chain_type_prediction}") # New: Print chain type
    print(f"Confidence: {suggestion.confidence:.4f}")

    writer.close()
    print("\nTensorBoard logs saved to runs/fuzzing_test")

    # --- LIME Explanation ---
    print("\n--- Generating LIME Explanation ---")
    # Prepare data for LIME
    # LIME needs a training dataset to understand feature distributions
    train_data_np = np.array([item[0].cpu().numpy() for item in dataset])
    feature_names = [
        f"file_feature_{i}" for i in range(len(dummy_samples[0].file_features))
    ] + [
        f"status_one_hot_{i}" for i in range(len(dummy_samples[0].status_one_hot))
    ] + [
        f"gdb_crash_feature_{i}" for i in range(len(dummy_samples[0].gdb_crash_features))
    ] + [
        f"leaked_addr_feature_{i}" for i in range(len(dummy_samples[0].leaked_addresses_features))
    ] + [
        f"apport_crash_feature_{i}" for i in range(len(dummy_samples[0].apport_crash_features))
    ] + [
        f"elf_feature_{i}" for i in range(len(dummy_samples[0].elf_features))
    ] + [
        "normalized_payload_offset", "normalized_trigger_offset"
    ]

    # Create LIME explainer for fuzz_type
    explainer_fuzz_type = LimeTabularExplainer(
        training_data=train_data_np,
        feature_names=feature_names,
        class_names=dummy_fuzz_types,
        mode='classification' # Since we are explaining fuzz_type prediction
    )


    explainer_chain_type = LimeTabularExplainer(
        training_data=train_data_np,
        feature_names=feature_names,
        class_names=dummy_chain_types,
        mode='classification' # Since we are explaining chain_type prediction
    )

    # Define prediction functions for LIME using the trained model and the local device/list variables
    def predict_proba(inputs_np):
        # inputs_np: (num_samples, input_dim)
        inputs_tensor = torch.tensor(inputs_np, dtype=torch.float32).to(device)
        with torch.no_grad():
            reconstructed_x, _, _, _ = model(inputs_tensor)
        fuzz_type_probs = reconstructed_x[:, :len(dummy_fuzz_types)]
        return fuzz_type_probs.detach().cpu().numpy()

    def predict_chain_type_proba(inputs_np):
        inputs_tensor = torch.tensor(inputs_np, dtype=torch.float32).to(device)
        with torch.no_grad():
            reconstructed_x, _, _, _ = model(inputs_tensor)
        chain_type_probs = reconstructed_x[:, len(dummy_fuzz_types) : len(dummy_fuzz_types) + len(dummy_chain_types)]
        return chain_type_probs.detach().cpu().numpy()

    # Choose a sample to explain (e.g., the first dummy sample)
    instance_to_explain = dummy_input_features.cpu().numpy()

    # Explain the instance for fuzz_type
    explanation_fuzz_type = explainer_fuzz_type.explain_instance(
        data_row=instance_to_explain,
        predict_fn=predict_proba, # Use the existing predict_proba for fuzz_type
        num_features=10, # Show top 10 important features
        num_samples=1000
    )

    print("\nLIME Explanation for Fuzz Type Prediction (first dummy sample):")
    for feature, weight in explanation_fuzz_type.as_list():
        print(f"  {feature}: {weight:.4f}")

    # Explain the instance for chain_type
    explanation_chain_type = explainer_chain_type.explain_instance(
        data_row=instance_to_explain,
        predict_fn=predict_chain_type_proba, # Use the new predict_chain_type_proba
        num_features=10,
        num_samples=1000
    )

    print("\nLIME Explanation for Chain Type Prediction (first dummy sample):")
    for feature, weight in explanation_chain_type.as_list():
        print(f"  {feature}: {weight:.4f}")

    # You can also save the explanation as an HTML file
    # explanation_fuzz_type.save_to_file('lime_explanation_fuzz_type.html')
    # explanation_chain_type.save_to_file('lime_explanation_chain_type.html')
    print("\nLIME explanations generated. You can uncomment `explanation.save_to_file` to save as HTML.")

    # --- Test AddressOracle ---
    print("\n--- Testing AddressOracle ---")
    dummy_viewers = ["eog", "firefox"]
    dummy_gadget_names = ["pop_x0_x1_ret", "ldr_x0_x1_br_x0", "vop_ldr_str_q0_ret"]
    dummy_address_samples = [
        AddressSample(
            features=[0.1, 0.5, 0.2, 0.3, 0.1, 0.05] + [0.0]*50 + [1, 0],
            addresses=[0x1000, 0x1010, 0x1020]
        ),
        AddressSample(
            features=[0.2, 0.6, 0.3, 0.4, 0.15, 0.08] + [0.1]*50 + [0, 1],
            addresses=[0x1200, 0x1210, 0x1220]
        )
    ]
    address_dataset = AddressDataset(dummy_address_samples)
    oracle = AddressOracle(address_dataset.input_dim, address_dataset.output_dim)
    accuracy = train_address_oracle(oracle, address_dataset, epochs=50, device=device)
    print(f"AddressOracle Accuracy: {accuracy:.4f}")
    if accuracy > 0.95:
        predicted = predict_addresses(oracle, dummy_address_samples[0].features, device=device)
        print(f"Predicted addresses: {predicted}")
    else:
        print("Oracle not accurate enough, skipping prediction.")

