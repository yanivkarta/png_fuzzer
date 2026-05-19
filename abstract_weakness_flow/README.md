# abstract_weakness_flow
AArch64 Control-Flow Hijack Research Suite 

Quick PoC used for the png_fuzzer and other projects
Not originally designed for mobile devices but supports thumb mode. 
This was used only to validate the exploitability of VOP payloads flag changing for privilege escalation purposes , not remote code execution demonstrated in png_fuzzer.

For RCE payloads,take a look at the root folder of the png_fuzzer.   


## Quick Start
1. **Compile:** `make all`
2. **Scan:** `python3 scripts/analyze_all.py target_aarch64 target_hardened`
3. **Exploit:** `python3 scripts/gen_payload.py target_aarch64 && ./target_aarch64`
4. **Listen (Remote):** `python3 scripts/listener.py 4444`

## Research Directions
- **PAC/BTI Bypass:** Analyze temporal race windows in `target_race` using GDB to monitor $x30$ corruption post-`AUTIA`.
- **Privilege Escalation:** Target SUID binaries to execute `setuid(0)` via DOP gadgets.
- **Remote Exfiltration:** Use `dup2` stubs to redirect I/O to `/dev/tcp/{IP}/{PORT}`.
- **Crash Analyis:** Monitor `dmesg` for SIGILL (BTI fault) vs SIGSEGV (PAC fault).



To demonstrate the full success/failure monitoring chain:

Launch Listener: ```python3 scripts/listener.py 4444 in one terminal.```

Generate Exploits: ```python3 scripts/gen_payload.py target_aarch64.```

Run with Monitoring: ```python3 scripts/monitor.py ./target_aarch64.```

Analyze Failure: If a crash occurs, GDB will launch, the .gdbinit will trigger, and the ESR_ELx will tell you exactly which mitigation (PAC or BTI) blocked the flow.

This abstract flow is fully implemented as instrumentation method to bypass existing control flow mitigation methods.
