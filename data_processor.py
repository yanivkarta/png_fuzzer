import os
import json
import pandas as pd
import subprocess
import re
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
import logging
#AppCrashInfo and monitoring functions are imported from crash_monitor.py to avoid circular dependencies 
from crash_monitor import ApportCrashInfo, request_sudo_if_needed, monitor_apport_log

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

@dataclass
class FuzzingSample:
    """Represents a single fuzzing trial with all extracted features."""
    viewer_name: str
    fuzz_type: str
    file_features: List[float]  # 10 features from PNG file analysis
    payload_offset_attempted: int
    status_one_hot: List[float]  # 5-element one-hot encoding
    gdb_crash_features: List[float]  # 5 features from crash analysis
    leaked_addresses_features: List[float]  # 3 features from address leaks
    apport_crash_features: List[float]  # 5 features from Apport report
    elf_features: List[float]  # ELF_FEATURE_VECTOR_SIZE features from binary
    success_label: int  # 1 if successful, 0 otherwise
    trigger_offset_attempted: int = 0  # Offset for trigger data
    chain_type_prediction: str = "ROP"  # Inferred chain type
    confidence_score: float = 0.0  # Model confidence for this sample

@dataclass
class InstrumentationSuggestion:
    """ML model suggestion for payload instrumentation."""
    fuzz_type_prediction: str
    payload_offset_prediction: int
    trigger_offset_prediction: int = 0
    chain_type_prediction: str = "ROP"
    confidence: float = 0.0
    vop_recommended: bool = False  # New: VOP gadget recommendation

ELF_FEATURE_VECTOR_SIZE = 50  # Fixed size for ELF feature vector

def _extract_elf_features(elf_path: str) -> List[float]:
    """
    Extracts numerical features from an ELF binary using readelf.
    Returns a fixed-size list of floats.
    """
    features = [0.0] * ELF_FEATURE_VECTOR_SIZE
    
    # Resolve the real path in case it's a symbolic link
    resolved_elf_path = os.path.realpath(elf_path)

    if not os.path.exists(resolved_elf_path):
        print(f"DEBUG: ELF file not found: {resolved_elf_path}")
        return features

    try:
        # 1. ELF Header information (readelf -h)
        header_output = subprocess.run(['readelf', '-h', resolved_elf_path], capture_output=True, text=True, check=True)
        
        # ELF Class (32-bit vs 64-bit)
        elf_class_match = re.search(r"Class:\s+ELF(\d+)", header_output.stdout)
        if elf_class_match:
            features[0] = 1.0 if elf_class_match.group(1) == "64" else 0.0 # 1.0 for 64-bit, 0.0 for 32-bit

        # Machine type (normalized hash)
        machine_match = re.search(r"Machine:\s+([^\n]+)", header_output.stdout)
        if machine_match:
            features[1] = hash(machine_match.group(1).strip()) % 1000 / 1000.0

        # Entry point address (normalized)
        entry_point_match = re.search(r"Entry point address:\s+(0x[0-9a-fA-F]+)", header_output.stdout)
        if entry_point_match:
            entry_point_val = int(entry_point_match.group(1), 16)
            features[2] = float(entry_point_val) / (2**32 - 1) if features[0] == 0.0 else float(entry_point_val) / (2**64 - 1) # Normalize based on 32/64-bit

        # 2. Section Headers (readelf -S)
        sections_output = subprocess.run(['readelf', '-S', resolved_elf_path], capture_output=True, text=True, check=True)
        
        # Number of sections
        section_count_match = re.search(r"There are (\d+) section headers", sections_output.stdout)
        if section_count_match:
            features[3] = float(int(section_count_match.group(1))) / 100.0 # Normalize by a reasonable max (e.g., 100 sections)

        # Presence of key sections
        key_sections = {
            b'.text': 4, b'.data': 5, b'.rodata': 6, b'.bss': 7, b'.symtab': 8,
            b'.strtab': 9, b'.dynsym': 10, b'.dynstr': 11, b'.plt': 12, b'.got': 13,
            b'.init': 14, b'.fini': 15, b'.ctors': 16, b'.dtors': 17, b'.eh_frame': 18
        }
        for section_name_bytes, feature_idx in key_sections.items():
            if section_name_bytes.decode() in sections_output.stdout:
                features[feature_idx] = 1.0
        
        # Section flags (e.g., Writable, Executable, Allocatable)
        # This is a more complex parsing. We'll look for common flags.
        # Example line: [Nr] Name              Type            Address          Off    Size   EntSize  Flags  Link  Info  Align
        #               [ 1] .text             PROGBITS        0000000000001000 001000 000010 000000   AX     0     0     16
        
        # Regex to capture flags: look for lines starting with [ number ] and then capture the flags part
        section_flags_pattern = re.compile(r"\[\s*\d+\]\s+\S+\s+\S+\s+[0-9a-fA-F]+\s+[0-9a-fA-F]+\s+[0-9a-fA-F]+\s+[0-9a-fA-F]+\s+([A-Z]+)")
        
        flags_present = set()
        for line in sections_output.stdout.splitlines():
            match = section_flags_pattern.search(line)
            if match:
                for flag_char in match.group(1):
                    flags_present.add(flag_char)
        
        # Assign features for common flags
        flag_features = {
            'W': 19, # Writable
            'A': 20, # Allocatable
            'X': 21, # Executable
            'M': 22, # Merge
            'S': 23, # Strings
            'I': 24, # Info
            'L': 25, # Link order
            'G': 26, # Group
            'T': 27, # TLS
            'C': 28, # Compressed
        }
        for flag_char, feature_idx in flag_features.items():
            if flag_char in flags_present:
                features[feature_idx] = 1.0

        # 3. Symbol Table (readelf -s)
        symbols_output = subprocess.run(['readelf', '-s', resolved_elf_path], capture_output=True, text=True, check=True)
        
        # Number of symbols
        symbol_count_match = re.search(r"Symbol table '.symtab' contains (\d+) entries", symbols_output.stdout)
        if symbol_count_match:
            features[29] = float(int(symbol_count_match.group(1))) / 1000.0 # Normalize by a reasonable max (e.g., 1000 symbols)
        
        # Number of dynamic symbols
        dynsym_count_match = re.search(r"Symbol table '.dynsym' contains (\d+) entries", symbols_output.stdout)
        if dynsym_count_match:
            features[30] = float(int(dynsym_count_match.group(1))) / 1000.0

        # 4. Dynamic Section (readelf -d)
        dynamic_output = subprocess.run(['readelf', '-d', resolved_elf_path], capture_output=True, text=True, check=True)
        
        # Presence of specific dynamic tags
        key_dynamic_tags = {
            'RPATH': 31, 'RUNPATH': 32, 'TEXTREL': 33, 'BIND_NOW': 34,
            'DEBUG': 35, 'INIT': 36, 'FINI': 37, 'NEEDED': 38, 'SONAME': 39
        }
        for tag_name, feature_idx in key_dynamic_tags.items():
            if tag_name in dynamic_output.stdout:
                features[feature_idx] = 1.0

        # Additional features (e.g., number of shared libraries, version info)
        # Number of NEEDED libraries
        needed_libs = re.findall(r"\(NEEDED\)\s+Shared library: \[(.+?)\]", dynamic_output.stdout)
        features[40] = float(len(needed_libs)) / 10.0 # Normalize by a reasonable max (e.g., 10 libs)

        # Check for PIE (Position Independent Executable)
        # This is usually indicated by ET_DYN in header, but readelf -h doesn't directly show it.
        # We can infer it if the entry point is relative or if sections are relocatable.
        # A simpler check is to look for "Type:                              DYN (Shared object file)" in header
        type_match = re.search(r"Type:\s+([^\n]+)", header_output.stdout)
        if type_match and "DYN (Shared object file)" in type_match.group(1):
            features[41] = 1.0 # Likely PIE

        # Check for stripped binary (absence of .symtab and .debug sections)
        if features[8] == 0.0 and "debug" not in sections_output.stdout: # .symtab is feature[8]
            features[42] = 1.0 # Likely stripped

        # Fill remaining features with 0.0 if not all slots are used
        # (already initialized with zeros, so this is implicit)

    except subprocess.CalledProcessError as e:
        print(f"DEBUG: readelf command failed for {resolved_elf_path}: {e}")
        print(f"DEBUG: Stderr: {e.stderr}")
        return [0.0] * ELF_FEATURE_VECTOR_SIZE
    except FileNotFoundError:
        print(f"DEBUG: readelf command not found. Please ensure it's in your PATH.")
        return [0.0] * ELF_FEATURE_VECTOR_SIZE
    except Exception as e:
        print(f"DEBUG: Error extracting ELF features from {resolved_elf_path}: {e}")
        return [0.0] * ELF_FEATURE_VECTOR_SIZE
    
    return features

def _extract_file_features(file_path: str) -> List[float]:
    """
    Placeholder for extracting numerical features from a PNG file.
    This would involve parsing PNG chunks, metadata, dimensions, etc.
    For now, it returns dummy features.
    """
    print(f"DEBUG: _extract_file_features called with file_path: {file_path}")
    if file_path is None or not os.path.exists(file_path):
        return [0.0] * 10 # Return a fixed-size list of zeros for consistency

    features = [0.0] * 10 # Initialize with zeros

    try:
        with open(file_path, 'rb') as f:
            content = f.read()

        # PNG Signature: 8 bytes
        if len(content) < 8 or content[:8] != b'\x89PNG\r\n\x1a\n':
            print(f"DEBUG: Not a valid PNG file: {file_path}")
            return features

        offset = 8 # Start after PNG signature
        
        # IHDR chunk features
        ihdr_found = False
        width, height, bit_depth, color_type = 0, 0, 0, 0
        
        # Chunk counts and sizes
        chunk_counts = {}
        chunk_sizes = {} # Store total size for each chunk type

        while offset < len(content):
            if offset + 8 > len(content): # Ensure enough bytes for length and type
                break
            
            length = int.from_bytes(content[offset:offset+4], 'big')
            chunk_type = content[offset+4:offset+8]
            
            chunk_data_start = offset + 8
            chunk_data_end = chunk_data_start + length
            chunk_crc_end = chunk_data_end + 4

            if chunk_crc_end > len(content): # Ensure chunk fits within file
                break

            chunk_counts[chunk_type] = chunk_counts.get(chunk_type, 0) + 1
            chunk_sizes[chunk_type] = chunk_sizes.get(chunk_type, 0) + length

            if chunk_type == b'IHDR' and length == 13:
                ihdr_found = True
                width = int.from_bytes(content[chunk_data_start:chunk_data_start+4], 'big')
                height = int.from_bytes(content[chunk_data_start+4:chunk_data_start+8], 'big')
                bit_depth = content[chunk_data_start+8]
                color_type = content[chunk_data_start+9]
            
            offset = chunk_crc_end # Move to the next chunk

        # Assign features
        features[0] = float(width) / 1000.0 # Normalize width
        features[1] = float(height) / 1000.0 # Normalize height
        features[2] = float(bit_depth) / 16.0 # Normalize bit depth (max 16)
        features[3] = float(color_type) / 6.0 # Normalize color type (max 6)
        features[4] = float(chunk_counts.get(b'IHDR', 0))
        features[5] = float(chunk_counts.get(b'PLTE', 0))
        features[6] = float(chunk_counts.get(b'IDAT', 0))
        features[7] = float(chunk_counts.get(b'tEXt', 0))
        features[8] = float(chunk_counts.get(b'iTXt', 0))
        features[9] = float(chunk_counts.get(b'pHYs', 0))
        
        return features

    except FileNotFoundError:
        print(f"DEBUG: FileNotFoundError for {file_path}")
        return [0.0] * 10
    except Exception as e:
        print(f"DEBUG: Error extracting file features from {file_path}: {e}")
        return [0.0] * 10

def _extract_gdb_crash_features(crash_log_path: str) -> List[float]:
    """
    Placeholder for extracting numerical features from a GDB crash log.
    """
    print(f"DEBUG: _extract_gdb_crash_features called with crash_log_path: {crash_log_path}")
    if crash_log_path is None or not os.path.exists(crash_log_path):
        print(f"DEBUG: GDB crash log not found or path is None: {crash_log_path}")
        return [0.0] * 5 # Dummy features

    features = [0.0] * 5 # faulting_instruction_type, metadata_involvement, backtrace_depth, etc.
    try:
        with open(crash_log_path, 'r') as f:
            content = f.read()
            # Example: simple feature extraction
            if "SIGSEGV" in content or "segmentation fault" in content:
                features[0] = 1.0 # Indicates a segfault
            if "metadata" in content.lower():
                features[1] = 1.0 # Metadata involvement
            features[2] = content.count("#") # Backtrace depth (rough estimate)
            # Add more sophisticated parsing here
    except Exception as e:
        print(f"DEBUG: Error reading GDB crash log {crash_log_path}: {e}")
    return features

def _extract_leaked_addresses_features(debug_json_path: str) -> List[float]:
    """
    Placeholder for extracting numerical features from leaked addresses in debug JSON.
    """
    print(f"DEBUG: _extract_leaked_addresses_features called with debug_json_path: {debug_json_path}")
    if debug_json_path is None or not os.path.exists(debug_json_path):
        print(f"DEBUG: Debug JSON not found or path is None: {debug_json_path}")
        return [0.0] * 3 # Dummy features

    features = [0.0] * 3 # relative_offsets, presence_of_key_addresses, etc.
    try:
        with open(debug_json_path, 'r') as f:
            debug_data = json.load(f)
            leaked_addresses = debug_data.get("leaked_addresses", [])
            if leaked_addresses:
                features[0] = 1.0 # Presence of leaked addresses
                features[1] = len(leaked_addresses) # Number of leaked addresses
                # Further analysis of addresses could go here
    except Exception as e:
        print(f"DEBUG: Error reading debug JSON {debug_json_path}: {e}")
    return features

def _extract_apport_crash_features(apport_info: Optional[ApportCrashInfo]) -> List[float]:
    """
    Converts ApportCrashInfo into numerical features.
    """
    if apport_info is None:
        return [0.0] * 5 # Dummy features

    features = [0.0] * 5 # crash_signature, package_hash, process_name_hash, associated_file_hash, backtrace_depth
    
    # Simple hashing for categorical features
    if apport_info.package:
        features[0] = hash(apport_info.package) % 1000 / 1000.0 # Normalize to 0-1
    if apport_info.executable:
        features[1] = hash(apport_info.executable) % 1000 / 1000.0
    if apport_info.problem_type:
        features[2] = hash(apport_info.problem_type) % 1000 / 1000.0
    if apport_info.associated_file:
        features[3] = hash(apport_info.associated_file) % 1000 / 1000.0
    
    features[4] = len(apport_info.backtrace_summary) # Backtrace depth

    return features

def _get_status_one_hot(status: str) -> List[float]:
    """
    Converts status string to one-hot encoding.
    """
    mapping = {
        "SUCCESS": [1.0, 0.0, 0.0, 0.0, 0.0],
        "CRASHED": [0.0, 1.0, 0.0, 0.0, 0.0],
        "FAILED": [0.0, 0.0, 1.0, 0.0, 0.0],
        "CRASHED_INVALID_WEAKNESS": [0.0, 0.0, 0.0, 1.0, 0.0],
        "INJECTION_FAILED": [0.0, 0.0, 0.0, 0.0, 1.0],
        "CRASHED_APPORT": [0.0, 1.0, 0.0, 0.0, 0.0], # Apport crashes are also a type of crash
    }
    print(f"DEBUG: _get_status_one_hot called with status: {status}")
    return mapping.get(status, [0.0, 0.0, 0.0, 0.0, 0.0]) # Default to all zeros if unknown


def _infer_chain_type_from_fuzz_type(fuzz_type: str, viewer_name: str, 
                                     leaked_addresses: Dict = None) -> str:
    """
    Infers optimal chain type (ROP vs JOP) based on vulnerability characteristics.
    
    JOP is preferred for:
    - Metadata triggers (less gadget requirement, more dispatcher-based)
    - double_free (heap manipulation, JOP better for incremental changes)
    
    ROP is preferred for:
    - optimization_bypass (needs system() call, ROP simpler)
    - PAC-aware attacks (AUTIA/AUTIB are ROP-friendly)
    """
    try: 
        
        leaked_addresses = leaked_addresses or {}
        #check vop gadget availability for JOP preference in overflow cases 
        if leaked_addresses.get("mov_x0_x1_br_x0") or leaked_addresses.get('ldr_x0_x1_br_x0'): 
            return "VOP" # VOP preferred if gadgets available, regardless of fuzz type
        elif leaked_addresses.get("scvtf_x0_x1_br_x0") or leaked_addresses.get('sqrdmulh_x0_x1_br_x0'):
            return "VOP" # VOP preferred if floating-point gadgets available, regardless of fuzz type 
        #check for PAC/BTI traps for ROP preference 

        bti = leaked_addresses.get("bti_jop") or leaked_addresses.get("bti_rop") 
        pac = leaked_addresses.get("pac_jop") or leaked_addresses.get("pac_rop") 


        if fuzz_type == "double_free":
            # JOP for heap-based attacks
            if bti or pac:
                return "JOP" # JOP preferred if PAC/BTI traps detected, even for double_free
            else:
                return "JOP" if leaked_addresses.get("ldr_x0_x1_br_x0") or leaked_addresses.get('ldraa_x0_x1_br_x0') else "ROP"
           
        elif fuzz_type == "metadata_trigger":
            # JOP preferred for metadata readers (eog)
            return "JOP" if viewer_name == "eog" else "ROP"
        elif fuzz_type in ["overflow", "generic_viewer"]:
            # Can use either, prefer JOP if gadgets available
            return "JOP" if leaked_addresses.get("mov_x0_x1_br_x0") else "ROP" 
        
        else:
            # Default to ROP for control flow (optimization_bypass, UAF)
            return "ROP"
    except Exception as e:
        print(f"DEBUG: Error inferring chain type for fuzz_type: {fuzz_type}, viewer_name: {viewer_name}, leaked_addresses: {leaked_addresses}: {e}")
        return "ROP" # Default to ROP on error
    



def load_and_process_data(data_dirs: List[str]) -> List[FuzzingSample]:
    """Loads and processes all historical fuzzing data from CSV files."""
    fuzzing_samples: List[FuzzingSample] = []
    
    for data_dir in data_dirs:
        # Support both direct CSV path and directory containing CSV
        if data_dir.endswith('.csv'):
            trajectory_path = data_dir
        else:
            trajectory_path = os.path.join(data_dir, "fuzzing_trajectory.csv")
        
        if not os.path.exists(trajectory_path):
            logger.warning(f"Fuzzing trajectory CSV not found: {trajectory_path}")
            continue

        try:
            df = pd.read_csv(trajectory_path)
            logger.info(f"Loaded {len(df)} records from {trajectory_path}")
            
            for idx, row in df.iterrows():
                # Extract all required fields, with defaults for missing ones
                viewer_name = str(row.get('viewer', 'unknown'))
                fuzz_type = str(row.get('fuzz_type', 'generic_viewer'))
                file_path = str(row.get('original_file', ''))
                
                # Extract or compute file features
                if file_path and os.path.exists(file_path):
                    file_features = _extract_file_features(file_path)
                else:
                    file_features = [0.0] * 10
                
                # Status one-hot encoding
                status = str(row.get('status', 'FAILED')).upper()
                status_one_hot = _get_status_one_hot(status)
                
                # Payload and trigger offsets
                payload_offset = int(row.get('payload_offset_attempted', 0))
                trigger_offset = int(row.get('trigger_offset_attempted', 0))
                
                # Extract crash features if available
                gdb_log_path = str(row.get('gdb_crash_log', ''))
                gdb_crash_features = _extract_gdb_crash_features(gdb_log_path) if gdb_log_path else [0.0] * 5
                
                # Leaked addresses features
                debug_json_path = str(row.get('debug_json', ''))
                leaked_addresses_features = _extract_leaked_addresses_features(debug_json_path) if debug_json_path else [0.0] * 3
                
                # Apport crash features
                apport_report_path = str(row.get('apport_report', ''))
                apport_info = None
                if apport_report_path and os.path.exists(apport_report_path):
                    apport_info = parse_apport_report(apport_report_path)
                apport_crash_features = _extract_apport_crash_features(apport_info)
                
                # ELF features for viewer binary
                resolved_viewer_path = str(row.get('resolved_viewer_path', f'/usr/bin/{viewer_name}'))
                elf_features = _extract_elf_features(resolved_viewer_path)
                
                # Infer chain type
                inferred_chain_type = _infer_chain_type_from_fuzz_type(
                    fuzz_type=fuzz_type,
                    viewer_name=viewer_name,
                    leaked_addresses={}  # Can be extended if addresses are available
                )
                
                # Success label
                success_label = 1 if "SUCCESS" in status else 0
                
                # Confidence score from model (if available in CSV)
                confidence_score = float(row.get('confidence_score', 0.0))
                
                # Create FuzzingSample
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
                    success_label=success_label,
                    trigger_offset_attempted=trigger_offset,
                    chain_type_prediction=inferred_chain_type,
                    confidence_score=confidence_score
                )
                
                fuzzing_samples.append(sample)
                logger.debug(f"Loaded sample {idx}: {viewer_name} + {fuzz_type} -> {status}")
        
        except Exception as e:
            logger.error(f"Error processing {trajectory_path}: {e}")
            import traceback
            logger.error(traceback.format_exc())

    logger.info(f"Total fuzzing samples loaded: {len(fuzzing_samples)}")
    return fuzzing_samples

if __name__ == "__main__":
    print("--- Testing data_processor.py ---")

    # Create dummy data for testing
    os.makedirs("test_data_dir", exist_ok=True)

    # Dummy fuzzing_trajectory.csv
    dummy_csv_content = """
timestamp,original_file,viewer,fuzz_type,payload_offset_attempted,status,reason
1678886400,test_image.png,eog,uaf,100,CRASHED,segfault
1678886401,test_image.png,firefox,overflow,200,SUCCESS,
1678886402,another_image.png,eog,uaf,50,FAILED,timeout
"""
    with open("test_data_dir/fuzzing_trajectory.csv", "w") as f:
        f.write(dummy_csv_content)

    # Dummy debug JSON
    dummy_debug_json_content = {
        "leaked_addresses": ["0x12345678", "0x87654321"],
        "chunk_info": {"IHDR": {"width": 100, "height": 100}}
    }
    with open("test_data_dir/test_image.png.eog.uaf.retry0.png.debug", "w") as f:
        json.dump(dummy_debug_json_content, f)
    with open("test_data_dir/test_image.png.firefox.overflow.retry0.png.debug", "w") as f:
        json.dump({}, f) # Empty debug for success case

    # Dummy crash log
    dummy_crash_log_content = "Program received signal SIGSEGV, Segmentation fault.\nMetadata related crash."
    with open("test_data_dir/test_image.png.eog.uaf.retry0.png.crash.log", "w") as f:
        f.write(dummy_crash_log_content)

    # Dummy Apport report (matching test_image.png)
    dummy_apport_report_content = """
ProblemType: Crash
Package: eog
ExecutablePath: /usr/bin/eog
Signal: 11
CrashTime: 1678886400.5
ProblemType: Crash
CoreDump: file:///./test_data_dir/test_image.png
AttachedFiles: /tmp/stacktrace.txt ///./test_data_dir/test_image.png
Stacktrace:
 #0 0x00007f8e12345678 in crash_func ()
 #1 0x00007f8e87654321 in main ()
    """
    with open("test_data_dir/apport_eog_crash_test_image.crash", "w") as f:
        f.write(dummy_apport_report_content)
    
    # Create dummy image files for _extract_file_features
    with open("test_data_dir/test_image.png", "wb") as f:
        f.write(b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\xda\xed\xc1\x01\x01\x00\x00\x00\xc2\xa0\xf7Om\x00\x00\x00\x00IEND\xaeB`\x82')
    with open("test_data_dir/another_image.png", "wb") as f:
        f.write(b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x02\x00\x00\x00\x02\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\xda\xed\xc1\x01\x01\x00\x00\x00\xc2\xa0\xf7Om\x00\x00\x00\x00IEND\xaeB`\x82')

    # Dummy debug JSON
    dummy_debug_json_content = {
        "leaked_addresses": ["0x12345678", "0x87654321"],
        "chunk_info": {"IHDR": {"width": 100, "height": 100}}
    }
    with open("test_data_dir/test_image.png.eog.uaf.retry0.png.debug", "w") as f:
        json.dump(dummy_debug_json_content, f)
    with open("test_data_dir/test_image.png.firefox.overflow.retry0.png.debug", "w") as f:
        json.dump({}, f) # Empty debug for success case

    # Dummy crash log
    dummy_crash_log_content = "Program received signal SIGSEGV, Segmentation fault.\nMetadata related crash."
    with open("test_data_dir/test_image.png.eog.uaf.retry0.png.crash.log", "w") as f:
        f.write(dummy_crash_log_content)

    # Dummy Apport report (matching test_image.png)
    dummy_apport_report_content = """
ProblemType: Crash
Package: eog
ExecutablePath: /usr/bin/eog
Signal: 11
CrashTime: 1678886400.5
ProblemType: Crash
CoreDump: file://///./test_data_dir/test_image.png
AttachedFiles: /tmp/stacktrace.txt ///./test_data_dir/test_image.png
Stacktrace:
 #0 0x00007f8e12345678 in crash_func ()
 #1 0x00007f8e87654321 in main ()
    """
    with open("test_data_dir/apport_eog_crash_test_image.crash", "w") as f:
        f.write(dummy_apport_report_content)
    
    # Create dummy image files for _extract_file_features
    with open("test_data_dir/test_image.png", "wb") as f:
        f.write(b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\xda\xed\xc1\x01\x01\x00\x00\x00\xc2\xa0\xf7Om\x00\x00\x00\x00IEND\xaeB`\x82')
    with open("test_data_dir/another_image.png", "wb") as f:
        f.write(b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x02\x00\x00\x00\x02\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\xda\xed\xc1\x01\x01\x00\x00\x00\xc2\xa0\xf7Om\x00\x00\x00\x00IEND\xaeB`\x82')


    samples = load_and_process_data(["test_data_dir"])

    print(f"\nLoaded {len(samples)} fuzzing samples.")
    for i, sample in enumerate(samples):
        print(f"\nSample {i+1}:")
        print(f"  Viewer: {sample.viewer_name}")
        print(f"  Fuzz Type: {sample.fuzz_type}")
        print(f"  Payload Offset: {sample.payload_offset_attempted}")
        print(f"  Status One-Hot: {sample.status_one_hot}")
        print(f"  Success Label: {sample.success_label}")
        print(f"  File Features: {sample.file_features}")
        print(f"  GDB Crash Features: {sample.gdb_crash_features}")
        print(f"  Leaked Addresses Features: {sample.leaked_addresses_features}")
        print(f"  Apport Crash Features: {sample.apport_crash_features}")
        print(f"  ELF Features: {sample.elf_features}")

    # --- Unit tests for _extract_elf_features ---
    print("\n--- Testing _extract_elf_features ---")
    
    # Test with a known valid ELF file (e.g., /bin/ls)
    ls_path = "/bin/ls"
    if os.path.exists(ls_path):
        ls_elf_features = _extract_elf_features(ls_path)
        print(f"ELF features for /bin/ls (first 5): {ls_elf_features[:5]}")
        assert len(ls_elf_features) == ELF_FEATURE_VECTOR_SIZE, "ELF feature vector size mismatch for /bin/ls"
        assert any(f != 0.0 for f in ls_elf_features), "ELF features for /bin/ls should not be all zeros"
        print(f"  _extract_elf_features for /bin/ls: PASSED (non-zero features, correct size)")
    else:
        print(f"  Skipping /bin/ls test: {ls_path} not found.")

    # Test with a non-existent file path
    non_existent_path = "non_existent_elf_file"
    non_existent_features = _extract_elf_features(non_existent_path)
    print(f"ELF features for non-existent file (first 5): {non_existent_features[:5]}")
    assert all(f == 0.0 for f in non_existent_features), "Non-existent file should return all zeros"
    assert len(non_existent_features) == ELF_FEATURE_VECTOR_SIZE, "ELF feature vector size mismatch for non-existent file"
    print(f"  _extract_elf_features for non-existent file: PASSED (all zeros, correct size)")

    # Test with a non-ELF file (e.g., a dummy text file)
    dummy_non_elf_path = "test_data_dir/dummy_non_elf.txt"
    with open(dummy_non_elf_path, "w") as f:
        f.write("This is not an ELF file.")
    dummy_non_elf_features = _extract_elf_features(dummy_non_elf_path)
    print(f"ELF features for non-ELF file (first 5): {dummy_non_elf_features[:5]}")
    assert all(f == 0.0 for f in dummy_non_elf_features), "Non-ELF file should return all zeros"
    assert len(dummy_non_elf_features) == ELF_FEATURE_VECTOR_SIZE, "ELF feature vector size mismatch for non-ELF file"
    print(f"  _extract_elf_features for non-ELF file: PASSED (all zeros, correct size)")

    # --- Integration tests for load_and_process_data with ELF features ---
    print("\n--- Testing load_and_process_data with ELF features ---")
    # Create a dummy ELF for a viewer that will be in the CSV
    dummy_viewer_elf_path = "test_data_dir/dummy_eog_elf"
    # Create a minimal valid ELF header for a 64-bit executable (just enough to pass readelf -h)
    # This is a highly simplified dummy ELF, just to make readelf -h not fail immediately.
    # A real dummy ELF would be much more complex. For robust testing, using /bin/ls is better.
    # For the purpose of this test, we'll create a file that readelf will *try* to parse.
    # If readelf fails on this minimal file, it will return zeros, which is also a valid test case.
    # Let's just copy /bin/ls to test_data_dir/eog for a more reliable test.
    if os.path.exists(ls_path):
        import shutil
        shutil.copy(ls_path, dummy_viewer_elf_path)
        print(f"Copied {ls_path} to {dummy_viewer_elf_path} for testing 'eog' viewer.")
    else:
        print(f"WARNING: /bin/ls not found, cannot create dummy ELF for 'eog' viewer. ELF features for 'eog' might be zeros.")
        # Create an empty file if /bin/ls is not available, readelf will fail on it.
        with open(dummy_viewer_elf_path, "w") as f:
            f.write("")

    # Modify dummy_csv_content to include a viewer that will have an ELF
    dummy_csv_content_with_elf = """
timestamp,original_file,viewer,fuzz_type,payload_offset_attempted,status,reason
1678886400,test_image.png,eog,uaf,100,CRASHED,segfault
1678886401,test_image.png,firefox,overflow,200,SUCCESS,
1678886402,another_image.png,eog,uaf,50,FAILED,timeout
"""
    with open("test_data_dir/fuzzing_trajectory.csv", "w") as f:
        f.write(dummy_csv_content_with_elf) # Overwrite with content that includes 'eog'

    samples_with_elf = load_and_process_data(["test_data_dir"])
    eog_sample_found = False
    for sample in samples_with_elf:
        if sample.viewer_name == "eog":
            eog_sample_found = True
            print(f"  Integration test for 'eog' ELF features (first 5): {sample.elf_features[:5]}")
            assert len(sample.elf_features) == ELF_FEATURE_VECTOR_SIZE, "Integration ELF feature vector size mismatch for 'eog'"
            # If /bin/ls was copied, features should not be all zeros.
            # If /bin/ls was not found and dummy_viewer_elf_path is empty, features will be zeros, which is also correct.
            if os.path.exists(ls_path): # Only assert non-zero if we actually copied a valid ELF
                assert any(f != 0.0 for f in sample.elf_features), "Integration ELF features for 'eog' should not be all zeros if /bin/ls was copied"
            print(f"  Integration test for 'eog' ELF features: PASSED")
            break
    assert eog_sample_found, "Integration test failed: 'eog' sample not found."

    # Clean up dummy data
    os.remove("test_data_dir/fuzzing_trajectory.csv")
    os.remove("test_data_dir/test_image.png.eog.uaf.retry0.png.debug")
    os.remove("test_data_dir/test_image.png.firefox.overflow.retry0.png.debug")
    os.remove("test_data_dir/test_image.png.eog.uaf.retry0.png.crash.log")
    os.remove("test_data_dir/apport_eog_crash_test_image.crash")
    os.remove("test_data_dir/test_image.png")
    os.remove("test_data_dir/another_image.png")
    os.remove(dummy_non_elf_path) # Clean up dummy non-ELF file
    if os.path.exists(dummy_viewer_elf_path):
        os.remove(dummy_viewer_elf_path) # Clean up dummy ELF for viewer
    os.rmdir("test_data_dir")
    print("\nCleaned up test data directory.")
