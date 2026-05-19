import subprocess
import re
import sys

def parse_gdb_crash(binary, core_path=None):
    """
    Automates GDB to extract the Exception Syndrome Register (ESR)
    to identify the specific mitigation that killed the process.
    """
    gdb_cmds = [
        "run",
        "info registers x30 pc esr far",
        "backtrace",
        "quit"
    ]
    
    cmd = ["gdb", "-batch"]
    for c in gdb_cmds:
        cmd += ["-ex", c]
    cmd.append(binary)

    result = subprocess.run(cmd, capture_output=True, text=True)
    output = result.stdout

    # Heuristic for AArch64 Mitigation Traps
    if "0x000000000000001c" in output.lower(): # ESR for BTI
        return "CRASH: BTI Violation (Landing Pad Missing)"
    if "SIGSEGV" in output and "autia" in output.lower():
        return "CRASH: PAC Violation (Pointer Signature Mismatch)"
    if "DOP Success" in output:
        return "SUCCESS: Hijack Confirmed"
    
    return "UNKNOWN: Check manual GDB output."

if __name__ == "__main__":
    print(f"[*] Analyzing crash state for {sys.argv[1]}...")
    print(parse_gdb_crash(sys.argv[1]))
