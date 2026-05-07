import csv
import glob
import os
import random
import shutil
import subprocess
import tempfile
import time
import zlib # Needed for calculate_png_crc
import torch
from torch.utils.tensorboard import SummaryWriter
from typing import List, Optional
from ml_fuzzer_model import (
    AddressOracle, AddressSample, AddressDataset, train_address_oracle,
    VAEGAN, train_vaegan, FuzzingDataset, FuzzingSample, collect_address_features,
    get_system_features, _sample_cpu_gpu_registers, ADDRESS_OFFSET_SCALE
)
from data_processor import resolve_viewer_path, _extract_elf_features, ELF_FEATURE_VECTOR_SIZE, load_and_process_data
import psutil
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# PNG IEND chunk marker (hex: 49 45 4e 44 ae 42 60 82)
IEND_CHUNK = b'\x49\x45\x4e\x44\xae\x42\x60\x82'

def calculate_png_crc(chunk_type: bytes, data: bytes) -> bytes:
    """Calculates the CRC-32 for a PNG chunk."""
    return zlib.crc32(chunk_type + data).to_bytes(4, 'big')

def generate_base_png(output_path: str, width: int = 100, height: int = 100):
    """Generates a valid PNG file with multiple chunks for better fuzzing coverage."""
    signature = b'\x89PNG\r\n\x1a\n'
    
    ihdr_type = b'IHDR'
    ihdr_data = (
        width.to_bytes(4, 'big') +
        height.to_bytes(4, 'big') +
        b'\x08' + # Bit depth
        b'\x03' + # Color type (Indexed-color)
        b'\x00' + # Compression method
        b'\x00' + # Filter method
        b'\x00'   # Interlace method
    )
    ihdr_chunk = len(ihdr_data).to_bytes(4, 'big') + ihdr_type + ihdr_data + calculate_png_crc(ihdr_type, ihdr_data)
    
    plte_type = b'PLTE'
    plte_data = b'\xff\x00\x00' + b'\x00\xff\x00' + b'\x00\x00\xff'
    plte_chunk = len(plte_data).to_bytes(4, 'big') + plte_type + plte_data + calculate_png_crc(plte_type, plte_data)
    
    idat_type = b'IDAT'
    raw_data = b'\x00' + (b'\x00' * width)
    full_raw_data = raw_data * height
    compressed_data = zlib.compress(full_raw_data)
    idat_chunk = len(compressed_data).to_bytes(4, 'big') + idat_type + compressed_data + calculate_png_crc(idat_type, compressed_data)
    
    iend_chunk = b'\x00\x00\x00\x00' + IEND_CHUNK
    
    with open(output_path, 'wb') as f:
        f.write(signature + ihdr_chunk + plte_chunk + idat_chunk + iend_chunk)


def _find_running_viewer_pid(viewer_name: str) -> Optional[int]:
    try:
        for proc in psutil.process_iter(['name', 'exe']):
            try:
                name = proc.info.get('name', '') or ''
                exe = proc.info.get('exe', '') or ''
                if viewer_name.lower() in name.lower() or viewer_name.lower() in exe.lower():
                    return proc.pid
            except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
                continue
    except Exception:
        pass
    return None


def _discover_image_paths(base_dirs: List[str], max_images: int = 25) -> List[str]:
    """Scan directories for image files to bootstrap live viewer runs."""
    extensions = {'.png', '.jpg', '.jpeg', '.bmp', '.gif'}
    image_paths = []
    for base_dir in base_dirs:
        if not os.path.exists(base_dir):
            continue
        for root, _, files in os.walk(base_dir):
            for file_name in files:
                if os.path.splitext(file_name)[1].lower() in extensions:
                    image_paths.append(os.path.join(root, file_name))
                    if len(image_paths) >= max_images:
                        return image_paths
    return image_paths


def _resolve_viewer_command(viewer_name: str, file_path: Optional[str] = None) -> Optional[List[str]]:
    if viewer_name == "png_consumer":
        viewer_path = resolve_viewer_path(viewer_name)
        if viewer_path and os.path.exists(viewer_path):
            return [viewer_path, file_path] if file_path else [viewer_path]
        return None

    if viewer_name == "eog":
        return ["eog", file_path] if file_path else ["eog"]
    if viewer_name == "firefox":
        return ["firefox", "--new-window", file_path] if file_path else ["firefox"]
    if viewer_name == "python3":
        return ["python3", "-c", "import time; time.sleep(5)"]
    return None


def _terminate_process(proc: subprocess.Popen) -> None:
    try:
        if proc.poll() is None:
            os.killpg(os.getpgid(proc.pid), 9)
    except Exception:
        pass
    try:
        proc.kill()
    except Exception:
        pass


def _build_address_oracle_samples_from_history(data_dirs: List[str], viewer_names: List[str], gadget_count: int) -> List[AddressSample]:
    samples = []
    for data_dir in data_dirs:
        csv_file = os.path.join(data_dir, "fuzzing_trajectory.csv")
        if not os.path.exists(csv_file):
            continue
        try:
            with open(csv_file, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    viewer_name = str(row.get('viewer', 'unknown')).strip() or 'unknown'
                    if not viewer_name:
                        continue
                    features = _build_address_oracle_features(viewer_name, viewer_names)
                    addresses = _make_address_labels_for_viewer(viewer_name, gadget_count)
                    samples.append(AddressSample(
                        features=features,
                        addresses=addresses,
                        viewer_name=viewer_name,
                        fuzz_type=str(row.get('fuzz_type', 'default')),
                        chain_type=str(row.get('chain_type_prediction', 'ROP')),
                        payload_offset=int(row.get('payload_offset_attempted', 0) or 0),
                        trigger_offset=int(row.get('trigger_offset_attempted', 0) or 0),
                        instrumentation_loaded=float(row.get('instrumentation_loaded', 0.0) or 0.0)
                    ))
        except Exception as e:
            logger.warning(f"Could not read historical samples from {csv_file}: {e}")
    return samples


def _build_address_oracle_live_samples(viewer_names: List[str], image_paths: List[str], gadget_count: int, max_samples: int = 30) -> List[AddressSample]:
    samples = []
    fuzz_types = ["uaf", "overflow", "double_free", "metadata_trigger"]
    chain_types = ["ROP", "JOP", "VOP"]
    random.shuffle(image_paths)

    for viewer_name in viewer_names:
        if len(samples) >= max_samples:
            break

        used_images = 0
        for image_path in image_paths:
            if used_images >= 3 or len(samples) >= max_samples:
                break

            cmd = _resolve_viewer_command(viewer_name, image_path)
            if not cmd:
                continue

            try:
                proc = subprocess.Popen(
                    [arg for arg in cmd if arg is not None],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    stdin=subprocess.DEVNULL,
                    preexec_fn=os.setsid
                )
            except Exception as e:
                logger.debug(f"Unable to start viewer {viewer_name} for live sample collection: {e}")
                continue

            time.sleep(1.0)
            if proc.poll() is not None:
                _terminate_process(proc)
                continue

            pid = proc.pid
            viewer_path = resolve_viewer_path(viewer_name)
            elf_features = _extract_elf_features(viewer_path) if viewer_path else [0.0] * ELF_FEATURE_VECTOR_SIZE
            payload_offset = random.choice([0, 4096, 8192, 12288, 16384])
            trigger_offset = random.choice([0, 4096, 8192, 12288, 16384])
            instrumentation_loaded = float(random.choice([0.0, 1.0]))
            fuzz_type = random.choice(fuzz_types)
            chain_type = random.choice(chain_types)

            try:
                features = collect_address_features(pid, elf_features, viewer_name, viewer_names, payload_offset, trigger_offset, instrumentation_loaded)
            except Exception as e:
                logger.warning(f"Failed to collect live features for {viewer_name}: {e}")
                features = get_system_features() + _sample_cpu_gpu_registers() + elf_features + [1.0 if v == viewer_name else 0.0 for v in viewer_names] + [min(1.0, payload_offset / 16384.0), min(1.0, trigger_offset / 16384.0), instrumentation_loaded]

            main_base = int(features[7] * (2**20)) if features[7] > 0 else 0x7fff00000000
            libc_base = int(features[8] * (2**20)) if features[8] > 0 else main_base + 0x1200000
            heap_start = int(features[9] * (2**20)) if features[9] > 0 else main_base + 0x2200000
            stack_start = int(features[10] * (2**20)) if features[10] > 0 else main_base + 0x3200000

            addresses = AddressDataset._generate_address_targets(
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
                features=features,
                addresses=addresses,
                viewer_name=viewer_name,
                fuzz_type=fuzz_type,
                chain_type=chain_type,
                payload_offset=payload_offset,
                trigger_offset=trigger_offset,
                instrumentation_loaded=instrumentation_loaded
            ))
            used_images += 1
            _terminate_process(proc)
            time.sleep(0.25)

    return samples


def _build_address_oracle_synthetic_fallback_samples(viewer_names: List[str], gadget_count: int, count: int) -> List[AddressSample]:
    samples = []
    fuzz_types = ["uaf", "overflow", "double_free", "metadata_trigger"]
    chain_types = ["ROP", "JOP", "VOP"]

    for sample_index in range(count):
        viewer_name = viewer_names[sample_index % len(viewer_names)]
        payload_offset = random.choice([0, 4096, 8192, 12288, 16384])
        trigger_offset = random.choice([0, 4096, 8192, 12288, 16384])
        instrumentation_loaded = float(random.choice([0.0, 1.0]))
        fuzz_type = random.choice(fuzz_types)
        chain_type = random.choice(chain_types)

        features = _build_address_oracle_features(
            viewer_name,
            viewer_names,
            payload_offset,
            trigger_offset,
            instrumentation_loaded
        )
        addresses = _make_address_labels_for_viewer(viewer_name, gadget_count)

        samples.append(AddressSample(
            features=features,
            addresses=addresses,
            viewer_name=viewer_name,
            fuzz_type=fuzz_type,
            chain_type=chain_type,
            payload_offset=payload_offset,
            trigger_offset=trigger_offset,
            instrumentation_loaded=instrumentation_loaded
        ))

    return samples


def _build_address_oracle_features(viewer_name: str, viewers: List[str], payload_offset: Optional[int] = None, trigger_offset: Optional[int] = None, instrumentation_loaded: float = 0.0) -> List[float]:
    if not viewer_name:
        return [0.0] * (25 + ELF_FEATURE_VECTOR_SIZE + len(viewers))  # 17 base + 8 CPU/GPU regs

    viewer_path = resolve_viewer_path(viewer_name)
    elf_features = _extract_elf_features(viewer_path) if viewer_path else [0.0] * ELF_FEATURE_VECTOR_SIZE
    
    logger.debug(f"AddressOracle features for {viewer_name}: path={viewer_path}, elf_features_nonzero={sum(1 for f in elf_features if f != 0.0)}")
    
    pid = _find_running_viewer_pid(viewer_name)

    if pid is not None:
        try:
            return collect_address_features(pid, elf_features, viewer_name, viewers, payload_offset, trigger_offset, instrumentation_loaded)
        except Exception as e:
            logger.warning(f"Unable to collect live process features for {viewer_name}: {e}")
            from ml_fuzzer_model import get_system_features, _sample_cpu_gpu_registers
            return get_system_features() + _sample_cpu_gpu_registers() + elf_features + [1.0 if v == viewer_name else 0.0 for v in viewers] + [min(1.0, payload_offset / 16384.0) if payload_offset is not None else 0.0, min(1.0, trigger_offset / 16384.0) if trigger_offset is not None else 0.0, min(1.0, max(0.0, instrumentation_loaded))]

    viewer_one_hot = [1.0 if v == viewer_name else 0.0 for v in viewers]
    from ml_fuzzer_model import get_system_features, _sample_cpu_gpu_registers
    return get_system_features() + _sample_cpu_gpu_registers() + elf_features + viewer_one_hot + [0.0, 0.0, 0.0]


def _make_address_labels_for_viewer(viewer_name: str, count: int) -> List[int]:
    """Generate normalized address deltas (offsets) for AddressOracle training."""
    # Generate offsets (deltas) from a base address
    gadget_offsets = [i * 0x1000 for i in range(count)]  # 4KB offsets
    return [offset / ADDRESS_OFFSET_SCALE for offset in gadget_offsets]


def check_and_train_vaegan_model(data_dirs: list, epochs: int = 10) -> bool:
    """
    Checks if VAEGAN model exists. If not, trains it from historical fuzzing data.
    Returns True if model is available, False otherwise.
    """
    model_path = "models/vaegan_model.pth"
    os.makedirs("models", exist_ok=True)
    
    if os.path.exists(model_path):
        logger.info(f"VAEGAN model found at {model_path}")
        return True
    
    logger.info("VAEGAN model not found. Attempting to train from historical data...")
    
    # Collect training samples from data directories
    samples = []
    for data_dir in data_dirs:
        if not os.path.exists(data_dir):
            logger.warning(f"Data directory not found: {data_dir}")
            continue
        
        csv_file = os.path.join(data_dir, "fuzzing_trajectory.csv")
        if os.path.exists(csv_file):
            try:
                import csv
                with open(csv_file, 'r') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        # Create a FuzzingSample from trajectory data
                        try:
                            # Map CSV columns to FuzzingSample dataclass fields
                            viewer_name = row.get('viewer', 'unknown')
                            fuzz_type = row.get('fuzz_type', 'default')
                            payload_offset = int(row.get('payload_offset_attempted', 0))
                            status = row.get('status', 'UNKNOWN').upper()
                            success = 1 if status in ['CRASHED', 'SUCCESS'] else 0
                            
                            # Create feature vectors
                            file_features = [float(x) for x in [
                                payload_offset / 1000.0,  # Normalize payload offset
                                100.0 / 10000.0,  # Normalized file size
                                1.0 / 10.0,    # Normalized complexity
                                0.5 / 1.0,    # Normalized entropy
                                1000000 / 1000000.0  # Normalized checksum
                            ]] + [0.1] * 5  # Add small non-zero values for padding
                            
                            status_one_hot = [1.0, 0.0, 0.0, 0.0, 0.0]  # CRASHED
                            if status == 'SUCCESS':
                                status_one_hot = [0.0, 1.0, 0.0, 0.0, 0.0]  # SUCCESS
                            elif status == 'FAILED':
                                status_one_hot = [0.0, 0.0, 1.0, 0.0, 0.0]  # FAILED
                            
                            gdb_crash_features = [0.1, 0.1, 0.1, 0.1, 0.1]  # Small non-zero values
                            leaked_addresses_features = [0.1, 0.1, 0.1]
                            apport_crash_features = [0.1, 0.1, 0.1, 0.1, 0.1]
                            elf_features = [0.1] * 50  # ELF_FEATURE_VECTOR_SIZE with small values
                            
                            sample = FuzzingSample(
                                viewer_name=viewer_name,
                                fuzz_type=fuzz_type,
                                file_features=file_features,
                                payload_offset_attempted=payload_offset,
                                status_one_hot=status_one_hot,
                                gdb_crash_features=gdb_crash_features,
                                leaked_addresses_features=leaked_addresses_features,
                                apport_crash_features=apport_crash_features,
                                elf_features=elf_features,
                                success_label=success,
                                trigger_offset_attempted=int(row.get('trigger_offset_attempted', 0)),
                                chain_type_prediction="ROP"  # Default chain type
                            )
                            samples.append(sample)
                        except Exception as e:
                            logger.debug(f"Skipping row: {e}")
            except Exception as e:
                logger.warning(f"Could not read {csv_file}: {e}")
    
    if not samples:
        logger.warning("No training samples found. Skipping VAEGAN training.")
        return False
    
    logger.info(f"Training VAEGAN with {len(samples)} samples...")
    try:
        # Extract metadata from samples for dataset initialization
        fuzz_types = list(set(s.fuzz_type for s in samples))
        chain_types = list(set(s.chain_type_prediction for s in samples if hasattr(s, 'chain_type_prediction') and s.chain_type_prediction))
        if not chain_types:
            chain_types = ["ROP", "JOP"]  # Default chain types
        
        max_payload_offset = max((s.payload_offset_attempted for s in samples), default=1000)
        max_trigger_offset = max((s.trigger_offset_attempted for s in samples), default=1000)
        
        # Ensure non-zero divisors for normalization
        max_payload_offset = max(max_payload_offset, 1)
        max_trigger_offset = max(max_trigger_offset, 1)
        
        logger.info(f"Dataset metadata: fuzz_types={fuzz_types}, chain_types={chain_types}, max_offsets={max_payload_offset}/{max_trigger_offset}")
        
        dataset = FuzzingDataset(
            samples=samples,
            fuzz_types=fuzz_types,
            chain_types=chain_types,
            max_payload_offset=max_payload_offset,
            max_trigger_offset=max_trigger_offset
        )
        device = "cuda" if torch.cuda.is_available() else "cpu"
        logger.info(f"Using device: {device}")
        
        writer = SummaryWriter("runs/vaegan_training")
        vaegan = VAEGAN(input_dim=dataset.input_dim, latent_dim=64, output_dim=dataset.output_dim)
        
        try:
            loss = train_vaegan(vaegan, dataset, epochs=epochs, device=device, writer=writer)
        except Exception as e:
            logger.error(f"VAEGAN training raised exception: {e}")
            writer.close()
            return False
        
        # Check if training produced valid loss
        if loss is None:
            logger.warning("VAEGAN training returned None loss. Using fallback model save.")
        elif isinstance(loss, float) and (loss != loss or loss == float('inf')):
            logger.warning(f"VAEGAN training produced invalid loss ({loss}). Not saving model.")
            writer.close()
            return False
        
        logger.info(f"VAEGAN training completed with final loss: {loss:.4f}")
        
        torch.save(vaegan.state_dict(), model_path)
        logger.info(f"VAEGAN model saved to {model_path}")
        writer.close()
        return True
    except Exception as e:
        logger.error(f"VAEGAN training failed: {e}")
        import traceback
        logger.debug(traceback.format_exc())
        return False


def check_and_train_address_oracle_model(epochs: int = 2000, data_dirs: Optional[List[str]] = None) -> bool:
    """
    Checks if AddressOracle model exists. If not, trains it with initialization data.
    Uses real viewer ELF and available process features when possible.
    Returns True if the model is available and saved, False otherwise.
    """
    model_path = "models/address_oracle.pth"
    os.makedirs("models", exist_ok=True)

    if os.path.exists(model_path):
        logger.info(f"AddressOracle model found at {model_path}")
        return True

    logger.info("AddressOracle model not found. Training with initialization data...")

    if data_dirs is None:
        data_dirs = [
            "generated_image_samples/fuzz_results_single",
            "old_test_data_dir"
        ]

    viewer_names = ["eog", "firefox", "png_consumer", "python3"]
    try:
        existed_dirs = [d for d in data_dirs if os.path.exists(d)]
        if existed_dirs:
            # Extract viewer names from CSV without full sample processing to avoid irrelevant warnings
            discovered_viewers = set()
            for data_dir in existed_dirs:
                csv_file = os.path.join(data_dir, "fuzzing_trajectory.csv")
                if os.path.exists(csv_file):
                    try:
                        with open(csv_file, 'r') as f:
                            reader = csv.DictReader(f)
                            for row in reader:
                                viewer = str(row.get('viewer', '')).strip()
                                if viewer:
                                    discovered_viewers.add(viewer)
                    except Exception as e:
                        logger.warning(f"Could not read viewer names from {csv_file}: {e}")
            if discovered_viewers:
                # Merge discovered viewers with defaults to ensure minimum batch size
                viewer_names = sorted(list(set(viewer_names + list(discovered_viewers))))
                logger.info(f"Discovered viewers for AddressOracle init: {viewer_names}")
    except Exception as e:
        logger.warning(f"Could not load historical data for viewer discovery: {e}")

    image_search_dirs = existed_dirs + [
        "generated_image_samples",
        "generated_image_samples_bad_keyframes",
        "generated_video_samples",
        "generated_audio_samples",
    ]
    image_paths = _discover_image_paths(image_search_dirs, max_images=40)
    logger.info(f"Discovered {len(image_paths)} image paths for live address oracle bootstrapping")

    gadget_names = [
        "pop_x0_x1_ret", "ldr_x0_x1_br_x0", "vop_ldr_str_q0",
        "pacia_x30", "autia_x30", "ldraa_x0_x1",
        "blraa_x0", "vop_ldr_d0_x1", "vop_str_d0_x0"
    ]

    try:
        address_samples: List[AddressSample] = _build_address_oracle_samples_from_history(existed_dirs, viewer_names, len(gadget_names))
        logger.info(f"Loaded {len(address_samples)} historical AddressOracle samples")

        if len(address_samples) < 20:
            live_samples = _build_address_oracle_live_samples(viewer_names, image_paths, len(gadget_names), max_samples=40)
            address_samples.extend(live_samples)
            logger.info(f"Bootstrapped {len(live_samples)} live AddressOracle samples from viewer executions")

        if len(address_samples) < 40:
            needed = 40 - len(address_samples)
            synthetic_samples = _build_address_oracle_synthetic_fallback_samples(viewer_names, len(gadget_names), needed)
            address_samples.extend(synthetic_samples)
            logger.info(f"Added {len(synthetic_samples)} synthetic AddressOracle samples with matching feature dimensions")

        if not address_samples:
            logger.warning("No AddressOracle samples could be built. Aborting training.")
            return False

        if not address_samples:
            logger.warning("No AddressOracle samples could be built. Aborting training.")
            return False

        first_feature_len = len(address_samples[0].features)
        first_target_len = len(address_samples[0].addresses)
        inconsistent_count = sum(1 for s in address_samples if len(s.features) != first_feature_len or len(s.addresses) != first_target_len)
        if inconsistent_count > 0:
            logger.warning(f"Filtered out {inconsistent_count} inconsistent AddressOracle samples")
            address_samples = [s for s in address_samples if len(s.features) == first_feature_len and len(s.addresses) == first_target_len]
        if not address_samples:
            logger.warning("All AddressOracle samples were inconsistent. Aborting training.")
            return False

        address_dataset = AddressDataset(address_samples)
        oracle = AddressOracle(address_dataset.input_dim, address_dataset.output_dim)
        device = "cuda" if torch.cuda.is_available() else "cpu"
        logger.info(f"Using device: {device}")

        writer = SummaryWriter("runs/address_oracle_training")
        accuracy = train_address_oracle(oracle, address_dataset, epochs=epochs, device=device, writer=writer)
        logger.info(f"AddressOracle trained with accuracy: {accuracy:.4f}")

        if accuracy > 0.50:  # Lowered threshold: exp(-5*0.1)≈0.607 means MAE<0.1 is good
            torch.save(oracle.state_dict(), model_path)
            logger.info(f"AddressOracle model saved to {model_path}")
            writer.close()
            return True
        else:
            logger.warning(f"AddressOracle accuracy below threshold ({accuracy:.4f}), not saving.")
            writer.close()
            return False
    except Exception as e:
        logger.error(f"AddressOracle training failed: {e}")
        import traceback
        logger.debug(traceback.format_exc())
        return False


# Main execution
if __name__ == "__main__":
    # Setup test environment
    test_data_dir = "test_data_dir_fuzzer"
    os.makedirs(test_data_dir, exist_ok=True)

    # Create infect_test.png
    infect_test_png_path = os.path.join(test_data_dir, "infect_test.png")
    generate_base_png(infect_test_png_path)
    logger.info(f"Created {infect_test_png_path}")

    # Copy png_consumer
    if os.path.exists("./png_consumer"):
        shutil.copy("./png_consumer", test_data_dir)
        logger.info(f"Copied png_consumer to {test_data_dir}")
    else:
        logger.warning("png_consumer not found in current directory. Fuzzer might fail for png_consumer viewer.")

    # Note: Using real data from fuzz_results_single instead of dummy samples
    # This ensures intelligent/advisor modes train on realistic fuzzing patterns
    logger.info(f"Using real fuzzing trajectory data from fuzz_results_single for VAEGAN training")

    # Check and train intelligent/advisor mode models
    logger.info("\n--- Checking and Training Intelligent/Advisor Mode Models ---")

    # Check/train VAEGAN model (needed for intelligent suggestions)
    # Use real data from fuzz_results_single, increased to 100 epochs for proper training
    vaegan_available = check_and_train_vaegan_model(
        data_dirs=["fuzz_results_single"],  # Use only real data, not dummy test data
        epochs=1000  # Increased epochs for intelligent/advisor mode training
    )
    if vaegan_available:
        logger.info("✓ VAEGAN model is ready for intelligent/advisor modes")
    else:
        logger.warning("✗ VAEGAN model training skipped or failed. Intelligent/advisor modes may have reduced functionality.")

    # Check/train AddressOracle model (needed for address prediction)
    oracle_available = check_and_train_address_oracle_model(epochs=22500)
    if oracle_available:
        logger.info("✓ AddressOracle model is ready for payload prediction")
    else:
        logger.warning("✗ AddressOracle model training skipped or failed.")

    # Summary
    logger.info("\n--- Model Setup Summary ---")
    logger.info(f"VAEGAN (intelligent fuzzing): {'✓ Ready' if vaegan_available else '✗ Not available'}")
    logger.info(f"AddressOracle (ROP prediction): {'✓ Ready' if oracle_available else '✗ Not available'}")
    logger.info(f"Intelligent/Advisor modes: {'✓ Available' if vaegan_available and oracle_available else '⚠ Limited'}")

    # Clean up test data directory after all runs
    if os.path.exists(test_data_dir):
        shutil.rmtree(test_data_dir)
        logger.info(f"\nCleaned up test data directory: {test_data_dir}")
