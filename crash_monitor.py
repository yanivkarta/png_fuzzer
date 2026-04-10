from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Dict, Any
import os
import logging
import re
import subprocess
import shutil
import time
import json
from pathlib import Path

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

_CRASH_ANALYSIS_INITIALIZED = False
_CRASH_ANALYSIS_ENABLED = False
_ORIGINAL_UID = os.getuid()
_ORIGINAL_GID = os.getgid()

@dataclass
class ApportCrashInfo:
    """Information extracted from an Apport crash report."""
    report_path: str
    package: str = ""
    executable: str = ""
    signal: int = 0
    crash_time: Optional[float] = None
    problem_type: str = ""
    associated_file: str = ""
    pac_bti_trap: bool = False
    vop_trap: bool = False
    trap_details: List[str] = field(default_factory=list)
    backtrace_summary: str = ""
    registers: Dict[str, int] = field(default_factory=dict)
    payload_distance: Optional[int] = None
    fitting_suggestions: List[str] = field(default_factory=list)

@dataclass
class CrashpadDumpInfo:
    """Information extracted from a Crashpad minidump file."""
    dump_path: str
    copied_dump_path: str = ""
    executable: str = ""
    crash_time: Optional[float] = None
    signal: int = 0
    registers: Dict[str, int] = field(default_factory=dict)
    backtrace: List[str] = field(default_factory=list)
    memory_regions: List[Dict[str, Any]] = field(default_factory=list)
    pac_bti_trap: bool = False
    vop_trap: bool = False
    trap_details: List[str] = field(default_factory=list)
    payload_distance: Optional[int] = None
    fitting_suggestions: List[str] = field(default_factory=list)
    normalized_registers: Dict[str, int] = field(default_factory=dict)
    process_name: str = ""
    crash_reason: str = ""
    analysis_summary: str = ""


def _has_crash_analysis_access() -> bool:
    apport_log_path = "/var/log/apport.log"
    crash_dir = "/var/crash"
    return (
        os.access(apport_log_path, os.R_OK) and
        (os.access(crash_dir, os.R_OK) if os.path.exists(crash_dir) else False)
    )


def _drop_root_privileges_if_needed():
    if os.geteuid() != 0:
        return

    orig_uid = int(os.environ.get('SUDO_UID', _ORIGINAL_UID))
    orig_gid = int(os.environ.get('SUDO_GID', _ORIGINAL_GID))

    if orig_uid == 0:
        return

    try:
        os.setgid(orig_gid)
        os.setuid(orig_uid)
        logger.info("Dropped elevated privileges back to the original user after granting crash analysis access.")
    except Exception as e:
        logger.warning(f"Unable to drop root privileges: {e}")


def request_sudo_if_needed() -> bool:
    """Requests sudo once at startup for privileged crash analysis access."""
    global _CRASH_ANALYSIS_INITIALIZED, _CRASH_ANALYSIS_ENABLED

    if _CRASH_ANALYSIS_INITIALIZED:
        return _CRASH_ANALYSIS_ENABLED
    #initialize the flag to prevent multiple prompts 
    allow = input("Grant sudo access for crash analysis? (y/N): ").strip().lower()
    if allow not in ('y', 'yes'):
        logger.warning("Crash analysis access denied. Crash detection will be limited.")
        _CRASH_ANALYSIS_INITIALIZED = True
        _CRASH_ANALYSIS_ENABLED = False
        return False
    else:
        logger.info("Enabling crash analysis access...")
        # Attempt to validate sudo access immediately
        try:
            result = subprocess.run(['sudo', '-v'], capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                logger.error("Sudo access failed or was denied. Crash analysis will be limited.")
                _CRASH_ANALYSIS_INITIALIZED = True
                _CRASH_ANALYSIS_ENABLED = False
                return False
        except Exception as e:
            logger.error(f"Error requesting sudo access: {e}")
            _CRASH_ANALYSIS_INITIALIZED = True
            _CRASH_ANALYSIS_ENABLED = False
            return False
        
        _CRASH_ANALYSIS_INITIALIZED = True

    if _has_crash_analysis_access():
        logger.info("Crash analysis access already available.")
        _CRASH_ANALYSIS_ENABLED = True
        _drop_root_privileges_if_needed()
        return True

    logger.warning("Crash analysis requires elevated privileges for accessing system logs and crash dumps.")
    logger.warning("This will enable the crash monitor to read privileged system files.")
    logger.warning("The fuzzer itself will run without elevated privileges.")

    try:
        response = input("Grant sudo access for crash analysis? (y/N): ").strip().lower()
        if response not in ('y', 'yes'):
            logger.warning("Crash analysis access denied. Crash detection will be limited.")
            _CRASH_ANALYSIS_ENABLED = False
            return False

        logger.info("Enabling crash analysis access...")
        result = subprocess.run(['sudo', '-v'], capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            logger.error("Sudo access failed or was denied. Crash analysis will be limited.")
            _CRASH_ANALYSIS_ENABLED = False
            return False

        _CRASH_ANALYSIS_ENABLED = True
        _drop_root_privileges_if_needed()
        logger.info("Crash analysis access granted successfully.")
        return True

    except KeyboardInterrupt:
        logger.warning("Crash analysis access request cancelled.")
        _CRASH_ANALYSIS_ENABLED = False
        return False
    except Exception as e:
        logger.error(f"Error requesting crash analysis access: {e}")
        _CRASH_ANALYSIS_ENABLED = False
        return False


def monitor_apport_log(last_read_pos: int) -> Tuple[List[str], int]:
    """Monitors /var/log/apport.log for new entries."""
    apport_log_path = "/var/log/apport.log"
    new_log_lines = []
    new_last_read_pos = last_read_pos

    if not os.path.exists(apport_log_path):
        logger.warning(f"Apport log not found: {apport_log_path}")
        return [], last_read_pos

    try:
        with open(apport_log_path, 'r', errors='ignore') as f:
            f.seek(last_read_pos)
            for line in f:
                new_log_lines.append(line.strip())
            new_last_read_pos = f.tell()
    except PermissionError:
        if not _CRASH_ANALYSIS_ENABLED:
            logger.warning("Permission denied reading apport log and crash analysis access was not granted.")
            return [], last_read_pos

        logger.debug("Permission denied reading apport log, trying with sudo...")
        try:
            result = subprocess.run(['sudo', 'tail', '-n', '+1', apport_log_path], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                all_lines = result.stdout.strip().split('\n')
                if last_read_pos == 0:
                    new_log_lines = all_lines
                    new_last_read_pos = len(result.stdout.encode('utf-8'))
                else:
                    new_log_lines = all_lines
                    new_last_read_pos = len(result.stdout.encode('utf-8'))
            else:
                logger.warning("Failed to read apport log with sudo")
        except Exception as e:
            logger.error(f"Error reading apport log with sudo: {e}")
    except Exception as e:
        logger.error(f"Error reading apport log: {e}")

    return new_log_lines, new_last_read_pos


def _search_patterns_in_backtrace(lines: List[str], patterns: List[str]) -> List[str]:
    """Search backtrace for regex patterns."""
    matches = []
    for line in lines:
        for pattern in patterns:
            if re.search(pattern, line, re.IGNORECASE):
                matches.append(line)
                break
    return matches


def detect_pac_bti_trap(crash_info: ApportCrashInfo, backtrace_lines: List[str]):
    """Detects PAC/BTI-related traps."""
    patterns = [
        r'\b(pacia|pacib|autia|autib|paciasp|pacibsp)\b',
        r'\b(bti)\b',
        r'pointer authentication',
        r'branch target',
        r'authenticat',
        r'PAC',
    ]

    matches = _search_patterns_in_backtrace(backtrace_lines, patterns)

    if matches:
        crash_info.pac_bti_trap = True
        crash_info.trap_details.extend([f"PAC/BTI: {m}" for m in matches])
        logger.info(f"PAC/BTI trap detected in {crash_info.report_path}")


def detect_vop_trap(crash_info: ApportCrashInfo, backtrace_lines: List[str]):
    """Detects Vector Operation (VOP) related traps with enhanced register tracking.
    
    Captures FMOV operations and other vector register operations that may bypass
    standard ROP/JOP detection. Includes 64-bit (d0-d31) and 128-bit (q0-q31) registers.
    """
    # Enhanced pattern set including vector registers involved in FMOV
    patterns = [
        # FMOV operations with various register combinations
        r'\bfmov\s+([dq][0-9]+)\s*,\s*([xw][0-9]+)',  # FMOV d/q-reg, x/w-reg (x/w to vector)
        r'\bfmov\s+([xw][0-9]+)\s*,\s*([dq][0-9]+)',  # FMOV x/w-reg, d/q-reg (vector to x/w)
        r'\bfmov\s+([dq][0-9]+)\s*,\s*#',  # FMOV d/q-reg, immediate
        # Other vector operations
        r'\b(fmla|fmls|fmul|fmuld|fmulx|fadd|fsub|fdiv)\s+([dqv][0-9]+)',  # FP arithmetic
        r'\b(ld1|ld1r|ld2|ld3|ld4)\s+\{?([dqv][0-9]+)',  # Vector loads
        r'\b(st1|st2|st3|st4)\s+\{?([dqv][0-9]+)',  # Vector stores
        r'\b(ldr|ldnp|ldp)\s+([qd][0-9]+)',  # Load to vector registers
        r'\b(str|stnp|stp)\s+([qd][0-9]+)',  # Store from vector registers
        r'\b(mov\s+[dq][0-9]+|dup\s+[qv][0-9]+|zip|uzp|trn)',  # Vector data movement
        r'\b(sqrdmulh|scvtf|fcvtzs|fcvtzu)\s+([dqv][0-9]+)',  # Conversion operations
        # General vector register references (as fallback)
        r'\b([qv][0-9]+|\{[dq][0-9]+(?:\s*-\s*[dq][0-9]+)?\})',  # q0-q31, v0-v31 registers
        r'\bd[0-9]+\b',  # d0-d31 (64-bit) floating point registers
        # NEON/SIMD specific patterns
        r'\b(neon|advsimd|simd|vector\s+operation|vop)',
    ]

    vop_operations = []
    vector_registers_found = set()
    
    for line in backtrace_lines:
        for pattern in patterns:
            matches = re.findall(pattern, line, re.IGNORECASE)
            if matches:
                # Extract and track vector registers
                for match in matches:
                    if isinstance(match, tuple):
                        for group in match:
                            if group and re.match(r'^[dqvxw][0-9]+$', group, re.IGNORECASE):
                                vector_registers_found.add(group.lower())
                    else:
                        if re.match(r'^[dqvxw][0-9]+$', match, re.IGNORECASE):
                            vector_registers_found.add(match.lower())
                
                # Record the operation with full context
                vop_operations.append({
                    'line': line.strip(),
                    'pattern_match': matches
                })

    if vop_operations:
        crash_info.vop_trap = True
        
        # Add detailed information about VOP operations found
        for op in vop_operations:
            trace_line = f"VOP: {op['line']}"
            crash_info.trap_details.append(trace_line)
        
        # Add summary of vector registers involved in the trap
        if vector_registers_found:
            reg_summary = f"VOP Registers involved: {', '.join(sorted(vector_registers_found))}"
            crash_info.trap_details.append(reg_summary)
        
        logger.info(f"VOP trap detected in {crash_info.report_path}: {len(vop_operations)} VOP operations, "
                   f"registers: {', '.join(sorted(vector_registers_found)) if vector_registers_found else 'none'}")


def parse_apport_report(report_path: str) -> Optional[ApportCrashInfo]:
    """Parses an Apport crash report file."""
    if not os.path.exists(report_path):
        logger.warning(f"Report not found: {report_path}")
        return None

    crash_info = ApportCrashInfo(report_path=report_path)
    backtrace_lines = []

    try:
        with open(report_path, 'r', errors='ignore') as f:
            content = f.read()
            
            # Extract key fields
            pkg_match = re.search(r'Package:\s*(.+)', content)
            if pkg_match:
                crash_info.package = pkg_match.group(1).strip()
            
            exe_match = re.search(r'ExecutablePath:\s*(.+)', content)
            if exe_match:
                crash_info.executable = exe_match.group(1).strip()
            
            sig_match = re.search(r'Signal:\s*(\d+)', content)
            if sig_match:
                crash_info.signal = int(sig_match.group(1))
            
            prob_match = re.search(r'ProblemType:\s*(.+)', content)
            if prob_match:
                crash_info.problem_type = prob_match.group(1).strip()
            
            # Extract registers if available
            _extract_registers_from_apport(crash_info, content)
            
            # Extract backtrace
            bt_start = content.find("Traceback")
            if bt_start != -1:
                bt_end = content.find("\n\n", bt_start)
                if bt_end == -1:
                    bt_end = len(content)
                bt_section = content[bt_start:bt_end]
                backtrace_lines = bt_section.split('\n')[:10]  # First 10 lines
                crash_info.backtrace_summary = "\n".join(backtrace_lines)
            
            # Detect trap types
            detect_pac_bti_trap(crash_info, backtrace_lines)
            detect_vop_trap(crash_info, backtrace_lines)
            
            # Calculate distances and fitting suggestions if registers available
            if crash_info.registers:
                _calculate_apport_distances_and_fitting(crash_info)
    
    except PermissionError:
        if not _CRASH_ANALYSIS_ENABLED:
            logger.warning(f"Permission denied reading {report_path} and crash analysis access was not granted.")
            return None

        logger.debug(f"Permission denied reading {report_path}, trying with sudo...")
        try:
            result = subprocess.run(['sudo', 'cat', report_path], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                content = result.stdout
                pkg_match = re.search(r'Package:\s*(.+)', content)
                if pkg_match:
                    crash_info.package = pkg_match.group(1).strip()
                
                exe_match = re.search(r'ExecutablePath:\s*(.+)', content)
                if exe_match:
                    crash_info.executable = exe_match.group(1).strip()
                
                sig_match = re.search(r'Signal:\s*(\d+)', content)
                if sig_match:
                    crash_info.signal = int(sig_match.group(1))
                
                prob_match = re.search(r'ProblemType:\s*(.+)', content)
                if prob_match:
                    crash_info.problem_type = prob_match.group(1).strip()
                
                _extract_registers_from_apport(crash_info, content)
                
                bt_start = content.find("Traceback")
                if bt_start != -1:
                    bt_end = content.find("\n\n", bt_start)
                    if bt_end == -1:
                        bt_end = len(content)
                    bt_section = content[bt_start:bt_end]
                    backtrace_lines = bt_section.split('\n')[:10]
                    crash_info.backtrace_summary = "\n".join(backtrace_lines)
                
                detect_pac_bti_trap(crash_info, backtrace_lines)
                detect_vop_trap(crash_info, backtrace_lines)
                
                if crash_info.registers:
                    _calculate_apport_distances_and_fitting(crash_info)
            else:
                logger.warning(f"Failed to read apport report {report_path} with sudo")
        except Exception as e:
            logger.error(f"Error reading apport report {report_path} with sudo: {e}")
    except Exception as e:
        logger.error(f"Error parsing apport report: {e}")

    return crash_info


def copy_crashpad_dump_for_analysis(dump_path: str, analysis_dir: str = "crash_analysis") -> str:
    """Copies a crashpad dump file to analysis directory with timestamp."""
    os.makedirs(analysis_dir, exist_ok=True)
    
    timestamp = int(time.time())
    dump_filename = os.path.basename(dump_path)
    copied_path = os.path.join(analysis_dir, f"{timestamp}_{dump_filename}")
    
    try:
        shutil.copy2(dump_path, copied_path)
        logger.info(f"Copied crash dump {dump_path} to {copied_path}")
        return copied_path
    except Exception as e:
        logger.error(f"Failed to copy crash dump {dump_path}: {e}")
        return dump_path  # Return original if copy fails


def parse_crashpad_dump(dump_path: str) -> Optional[CrashpadDumpInfo]:
    """Parses a Crashpad minidump file using external tools."""
    if not os.path.exists(dump_path):
        logger.warning(f"Dump file not found: {dump_path}")
        return None
    
    # Copy dump for analysis
    copied_dump = copy_crashpad_dump_for_analysis(dump_path)
    
    dump_info = CrashpadDumpInfo(
        dump_path=dump_path,
        copied_dump_path=copied_dump,
        crash_time=os.path.getmtime(dump_path)
    )
    
    try:
        # Try to use minidump_stackwalk if available
        stackwalk_output = _run_minidump_stackwalk(copied_dump)
        if stackwalk_output:
            _parse_stackwalk_output(dump_info, stackwalk_output)
        else:
            # Fallback to basic minidump parsing
            _parse_minidump_basic(dump_info, copied_dump)
        
        # Extract executable name from dump path or metadata
        dump_info.executable = _extract_executable_from_dump_path(dump_path)
        
        # Normalize registers and calculate distances
        _normalize_registers_and_distances(dump_info)
        
        # Detect trap types
        detect_pac_bti_trap_crashpad(dump_info)
        detect_vop_trap_crashpad(dump_info)
        
        logger.info(f"Parsed crashpad dump: {dump_path} -> {len(dump_info.registers)} registers, {len(dump_info.backtrace)} frames")
        
    except Exception as e:
        logger.error(f"Error parsing crashpad dump {dump_path}: {e}")
        return None
    
    return dump_info


def monitor_crashpad_dumps(last_check_time: float, dump_dirs: List[str] = None) -> Tuple[List[str], float]:
    """Monitors for new Crashpad minidump files in specified directories."""
    if dump_dirs is None:
        # Default crashpad dump locations for eog and firefox
        dump_dirs = [
            "/var/crashpad",  # System crashpad directory
            os.path.expanduser("~/.config/google-chrome/Crash Reports"),  # Chrome/Chromium
            os.path.expanduser("~/.mozilla/firefox/Crash Reports"),  # Firefox
            "/tmp",  # Temporary dumps
        ]
    
    new_dumps = []
    current_time = time.time()
    
    for dump_dir in dump_dirs:
        if not os.path.exists(dump_dir):
            continue
            
        try:
            for file_path in Path(dump_dir).rglob("*.dmp"):
                if os.path.getmtime(file_path) > last_check_time:
                    new_dumps.append(str(file_path))
        except (OSError, PermissionError) as e:
            logger.debug(f"Error scanning {dump_dir}: {e}")
    
    return new_dumps, current_time


def _run_minidump_stackwalk(dump_path: str) -> Optional[str]:
    """Runs minidump_stackwalk on the dump file if available."""
    try:
        # Try to find minidump_stackwalk in PATH
        result = subprocess.run(['which', 'minidump_stackwalk'], 
                              capture_output=True, text=True, timeout=5)
        if result.returncode != 0:
            logger.debug("minidump_stackwalk not found in PATH")
            return None
            
        # Run minidump_stackwalk
        result = subprocess.run(['minidump_stackwalk', dump_path], 
                              capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            return result.stdout
        else:
            logger.debug(f"minidump_stackwalk failed: {result.stderr}")
            return None
            
    except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError) as e:
        logger.debug(f"Error running minidump_stackwalk: {e}")
        return None

def _parse_stackwalk_output(dump_info: CrashpadDumpInfo, output: str):
    """Parses the output from minidump_stackwalk."""
    lines = output.split('\n')
    
    # Parse CPU context (registers)
    in_cpu_section = False
    for line in lines:
        line = line.strip()
        
        if line.startswith('CPU:'):
            in_cpu_section = True
            continue
        elif in_cpu_section and line.startswith('Crash reason:'):
            # Extract signal from crash reason
            if 'SIG' in line:
                sig_match = re.search(r'SIG(\w+)', line)
                if sig_match:
                    signal_name = sig_match.group(1)
                    # Map signal names to numbers
                    signal_map = {'SEGV': 11, 'ABRT': 6, 'BUS': 7, 'ILL': 4, 'FPE': 8, 'SYS': 31}
                    dump_info.signal = signal_map.get(signal_name, 0)
            continue
        elif in_cpu_section and not line:
            in_cpu_section = False
            continue
        elif in_cpu_section:
            # Parse register lines like "x0 = 0x0000000000000000"
            reg_match = re.match(r'(\w+)\s*=\s*(0x[0-9a-fA-F]+)', line)
            if reg_match:
                reg_name = reg_match.group(1).lower()
                reg_value = int(reg_match.group(2), 16)
                dump_info.registers[reg_name] = reg_value
                
                # Also store in normalized_registers for Q/D register support
                dump_info.normalized_registers[reg_name] = reg_value
        
        # Parse thread stacks for backtrace
        if line.startswith('Thread') and 'Stack:' in line:
            # Extract backtrace frames
            continue
        elif line.startswith('0x') and (' in ' in line or ' at ' in line):
            # Frame line like "0x00007f8b8c0d4f60 in foo() at bar.c:123"
            dump_info.backtrace.append(line)

def _parse_minidump_basic(dump_info: CrashpadDumpInfo, dump_path: str):
    """Basic minidump parsing as fallback when minidump_stackwalk is not available."""
    try:
        # Read first few KB of the dump to extract basic info
        with open(dump_path, 'rb') as f:
            header = f.read(1024)
            
        # Minidump header is 32 bytes, but we can try to extract some basic info
        # This is a very basic fallback - real minidump parsing requires proper libraries
        
        # For now, just set some defaults and note that full parsing requires minidump_stackwalk
        logger.warning(f"Basic minidump parsing for {dump_path} - install minidump_stackwalk for full analysis")
        
        # Try to extract executable name from path
        dump_info.executable = _extract_executable_from_dump_path(dump_path)
        
    except Exception as e:
        logger.error(f"Error in basic minidump parsing: {e}")

def _extract_executable_from_dump_path(dump_path: str) -> str:
    """Extracts executable name from dump path or filename."""
    filename = os.path.basename(dump_path)
    
    # Try to extract from filename patterns
    # Firefox dumps often have format like: bp-uuid.dmp
    # Chrome dumps: chrome.dmp
    # EOG might have different patterns
    
    if 'firefox' in filename.lower() or 'bp-' in filename:
        return 'firefox'
    elif 'chrome' in filename.lower():
        return 'chrome'
    elif 'eog' in filename.lower():
        return 'eog'
    else:
        # Try to infer from directory path
        dirname = os.path.dirname(dump_path)
        if 'firefox' in dirname.lower():
            return 'firefox'
        elif 'chrome' in dirname.lower() or 'chromium' in dirname.lower():
            return 'chrome'
        elif 'eog' in dirname.lower():
            return 'eog'
    
    return 'unknown'

def _normalize_registers_and_distances(dump_info: CrashpadDumpInfo, payload_marker: str = "PAYLOAD_MARKER"):
    """Normalizes register values and calculates distances to payload addresses."""
    # Look for payload markers in memory or registers
    payload_addresses = []
    
    # Check registers for potential payload addresses
    for reg_name, reg_value in dump_info.registers.items():
        # Look for ASCII markers in memory around register values
        if _check_memory_for_payload(dump_info, reg_value, payload_marker):
            payload_addresses.append(reg_value)
    
    if not payload_addresses:
        # Try to find payload in memory regions
        payload_addresses = _scan_memory_for_payload(dump_info, payload_marker)
    
    if payload_addresses:
        # Calculate distances from registers to nearest payload
        nearest_payload = min(payload_addresses, key=lambda addr: min(
            abs(addr - reg_val) for reg_val in dump_info.registers.values()
        ))
        
        dump_info.payload_distance = min(
            abs(nearest_payload - reg_val) for reg_val in dump_info.registers.values()
        )
        
        # Generate fitting suggestions based on register distances
        _generate_fitting_suggestions(dump_info, nearest_payload)
    
    # Normalize Q/D registers for VOP analysis
    _normalize_vector_registers(dump_info)

def _check_memory_for_payload(dump_info: CrashpadDumpInfo, address: int, marker: str) -> bool:
    """Checks if memory around an address contains a payload marker."""
    # This would require reading the minidump memory regions
    # For now, return False as we don't have full memory access
    # In a real implementation, this would scan memory regions in the dump
    return False

def _scan_memory_for_payload(dump_info: CrashpadDumpInfo, marker: str) -> List[int]:
    """Scans memory regions in the dump for payload markers."""
    # This is a placeholder - real implementation would need to parse
    # memory regions from the minidump and search for markers
    return []

def _generate_fitting_suggestions(dump_info: CrashpadDumpInfo, payload_addr: int):
    """Generates fitting suggestions based on register distances to payload."""
    suggestions = []
    
    for reg_name, reg_value in dump_info.registers.items():
        distance = abs(payload_addr - reg_value)
        if distance < 0x1000:  # Within 4KB
            suggestions.append(f"Register {reg_name} is {distance} bytes from payload (0x{reg_value:016x} -> 0x{payload_addr:016x})")
            
            # Suggest adjustments for fitting
            if distance > 0:
                suggestions.append(f"Adjust payload offset by -{distance} to align with {reg_name}")
            elif distance < 0:
                suggestions.append(f"Adjust payload offset by +{abs(distance)} to align with {reg_name}")
    
    # Check for register patterns that suggest VOP/DOP operations
    vop_suggestions = _analyze_vop_register_patterns(dump_info)
    suggestions.extend(vop_suggestions)
    
    dump_info.fitting_suggestions = suggestions

def _normalize_vector_registers(dump_info: CrashpadDumpInfo):
    """Normalizes Q/D register values for VOP analysis."""
    # Q registers are 128-bit, D registers are 64-bit
    # Normalize to common format for analysis
    
    for reg_name, reg_value in dump_info.registers.items():
        dump_info.normalized_registers[reg_name] = reg_value
        
        # For Q registers, we might have high/low parts
        if reg_name.startswith('q'):
            # Q register is 128-bit, but we might only have 64-bit values
            # Store as-is for now
            pass
        elif reg_name.startswith('d'):
            # D register is 64-bit floating point
            pass

def detect_pac_bti_trap_crashpad(dump_info: CrashpadDumpInfo):
    """Detects PAC/BTI-related traps in crashpad dumps."""
    patterns = [
        r'\b(pacia|pacib|autia|autib|paciasp|pacibsp)\b',
        r'\b(bti)\b',
        r'pointer authentication',
        r'branch target',
        r'authenticat',
        r'PAC',
    ]

    matches = []
    for frame in dump_info.backtrace:
        for pattern in patterns:
            if re.search(pattern, frame, re.IGNORECASE):
                matches.append(frame)
                break

    if matches:
        dump_info.pac_bti_trap = True
        dump_info.trap_details.extend([f"PAC/BTI: {m}" for m in matches])
        logger.info(f"PAC/BTI trap detected in crashpad dump {dump_info.dump_path}")

def detect_vop_trap_crashpad(dump_info: CrashpadDumpInfo):
    """Detects Vector Operation (VOP) related traps in crashpad dumps with enhanced register tracking."""
    # Enhanced pattern set including vector registers involved in FMOV and other operations
    patterns = [
        # FMOV operations with various register combinations
        r'\bfmov\s+([dq][0-9]+)\s*,\s*([xw][0-9]+)',  # FMOV d/q-reg, x/w-reg (x/w to vector)
        r'\bfmov\s+([xw][0-9]+)\s*,\s*([dq][0-9]+)',  # FMOV x/w-reg, d/q-reg (vector to x/w)
        r'\bfmov\s+([dq][0-9]+)\s*,\s*#',  # FMOV d/q-reg, immediate
        # Other vector operations
        r'\b(fmla|fmls|fmul|fmuld|fmulx|fadd|fsub|fdiv)\s+([dqv][0-9]+)',  # FP arithmetic
        r'\b(ld1|ld1r|ld2|ld3|ld4)\s+\{?([dqv][0-9]+)',  # Vector loads
        r'\b(st1|st2|st3|st4)\s+\{?([dqv][0-9]+)',  # Vector stores
        r'\b(ldr|ldnp|ldp)\s+([qd][0-9]+)',  # Load to vector registers
        r'\b(str|stnp|stp)\s+([qd][0-9]+)',  # Store from vector registers
        r'\b(mov\s+[dq][0-9]+|dup\s+[qv][0-9]+|zip|uzp|trn)',  # Vector data movement
        r'\b(sqrdmulh|scvtf|fcvtzs|fcvtzu)\s+([dqv][0-9]+)',  # Conversion operations
        # General vector register references (as fallback)
        r'\b([qv][0-9]+|\{[dq][0-9]+(?:\s*-\s*[dq][0-9]+)?\})',  # q0-q31, v0-v31 registers
        r'\bd[0-9]+\b',  # d0-d31 (64-bit) floating point registers
        # NEON/SIMD specific patterns
        r'\b(neon|advsimd|simd|vector\s+operation|vop)',
    ]

    vop_operations = []
    vector_registers_found = set()
    
    # Check backtrace for VOP patterns
    for frame in dump_info.backtrace:
        for pattern in patterns:
            matches = re.findall(pattern, frame, re.IGNORECASE)
            if matches:
                # Extract and track vector registers
                for match in matches:
                    if isinstance(match, tuple):
                        for group in match:
                            if group and re.match(r'^[dqvxw][0-9]+$', group, re.IGNORECASE):
                                vector_registers_found.add(group.lower())
                    else:
                        if re.match(r'^[dqvxw][0-9]+$', match, re.IGNORECASE):
                            vector_registers_found.add(match.lower())
                
                # Record the operation with full context
                vop_operations.append({
                    'frame': frame.strip(),
                    'pattern_match': matches
                })
    
    # Also check register values for VOP patterns
    for reg_name, reg_value in dump_info.registers.items():
        if reg_name.startswith(('q', 'd', 'v')):
            vector_registers_found.add(reg_name.lower())
            vop_operations.append({
                'frame': f"Register {reg_name} = 0x{reg_value:016x}",
                'pattern_match': [reg_name]
            })

    if vop_operations:
        dump_info.vop_trap = True
        
        # Add detailed information about VOP operations found
        for op in vop_operations:
            trace_line = f"VOP: {op['frame']}"
            dump_info.trap_details.append(trace_line)
        
        # Add summary of vector registers involved in the trap
        if vector_registers_found:
            reg_summary = f"VOP Registers involved: {', '.join(sorted(vector_registers_found))}"
            dump_info.trap_details.append(reg_summary)
        
def _extract_registers_from_apport(crash_info: ApportCrashInfo, content: str):
    """Extracts register values from Apport crash report content."""
    # Look for register sections in the crash report
    reg_patterns = [
        r'x(\d+)\s*:\s*(0x[0-9a-fA-F]+)',  # x0: 0x0000000000000000
        r'(\w+)\s*=\s*(0x[0-9a-fA-F]+)',   # reg = 0x0000000000000000
    ]
    
    for pattern in reg_patterns:
        for match in re.finditer(pattern, content, re.IGNORECASE):
            reg_name = match.group(1).lower()
            try:
                reg_value = int(match.group(2), 16)
                crash_info.registers[reg_name] = reg_value
            except ValueError:
                continue

def _calculate_apport_distances_and_fitting(crash_info: ApportCrashInfo):
    """Calculates payload distances and fitting suggestions for Apport crashes."""
    # This is a simplified version - in practice, you'd need payload markers
    # For now, just generate basic fitting suggestions based on register proximity
    
    suggestions = []
    gp_regs = [name for name in crash_info.registers.keys() if name.startswith(('x', 'w'))]
    
    # Look for registers that might be close to each other (potential payload alignment)
    for i, reg1 in enumerate(gp_regs):
        for reg2 in gp_regs[i+1:]:
            val1 = crash_info.registers[reg1]
            val2 = crash_info.registers[reg2]
            distance = abs(val1 - val2)
            
            if distance < 0x1000:  # Within 4KB
                suggestions.append(f"Registers {reg1} (0x{val1:016x}) and {reg2} (0x{val2:016x}) are {distance} bytes apart")
    
    crash_info.fitting_suggestions = suggestions
    """Unified crash monitoring for both Apport and Crashpad systems."""
    apport_crashes = []
    crashpad_dumps = []
    
    # Monitor Apport logs
    new_apport_lines, new_apport_pos = monitor_apport_log(last_apport_pos)
    
    for line in new_apport_lines:
        # Look for crash report creation
        match = re.search(r"Report '(/var/crash/_usr_bin_.*?\.crash)'", line)
        if match:
            report_path = match.group(1)
            crash_info = parse_apport_report(report_path)
            if crash_info:
                apport_crashes.append(crash_info)
                logger.info(f"Detected new Apport crash: {report_path}")
    
    # Monitor Crashpad dumps
    new_dumps, new_crashpad_time = monitor_crashpad_dumps(last_crashpad_time)
    
    for dump_path in new_dumps:
        dump_info = parse_crashpad_dump(dump_path)
        if dump_info:
            crashpad_dumps.append(dump_info)
            logger.info(f"Detected new Crashpad dump: {dump_path}")
    
    return apport_crashes, crashpad_dumps, new_apport_pos, new_crashpad_time


def export_crashpad_analysis_json(crashpad_dumps, output_path):
    """
    Export Crashpad dump analysis results to JSON format.
    
    Args:
        crashpad_dumps: List of CrashpadDumpInfo objects
        output_path: Path to output JSON file
    """
    export_data = []
    
    for dump in crashpad_dumps:
        dump_data = {
            "dump_path": str(dump.dump_path),
            "crash_time": dump.crash_time,
            "process_name": dump.process_name,
            "crash_reason": dump.crash_reason,
            "registers": {reg: f"0x{val:016x}" for reg, val in dump.registers.items()},
            "backtrace": dump.backtrace,
            "vop_trap": dump.vop_trap,
            "pac_bti_trap": dump.pac_bti_trap,
            "fitting_suggestions": dump.fitting_suggestions,
            "analysis_summary": dump.analysis_summary
        }
        export_data.append(dump_data)
    
    with open(output_path, 'w') as f:
        json.dump(export_data, f, indent=2)
    
    logger.info(f"Exported {len(crashpad_dumps)} Crashpad dump analyses to {output_path}")
