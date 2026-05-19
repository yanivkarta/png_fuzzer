import sys, csv
from capstone import *
from elftools.elf.elffile import ELFFile

def audit_binary(path):
    results = {"file": path, "arch": "Unknown", "dispatchers": 0, "guarded": 0, "status": "Secure"}
    with open(path, 'rb') as f:
        elf = ELFFile(f)
        arch = elf.get_machine_arch()
        results["arch"] = arch
        md = Cs(CS_ARCH_ARM64, CS_MODE_ARM) if arch == 'AArch64' else Cs(CS_ARCH_ARM, CS_MODE_THUMB)
        
        for section in elf.iter_sections():
            if section['sh_flags'] & 0x4:
                insns = list(md.disasm(section.data(), section['sh_addr']))
                for i in range(len(insns)):
                    is_dispatcher = False
                    if arch == 'AArch64' and insns[i].mnemonic == "ret":
                        if i > 0 and "x30" in insns[i-1].op_str: is_dispatcher = True
                    elif arch == 'ARM' and insns[i].mnemonic == "pop" and "pc" in insns[i].op_str:
                        is_dispatcher = True
                    
                    if is_dispatcher:
                        results["dispatchers"] += 1
                        if any("autia" in insns[j].mnemonic for j in range(max(0, i-5), i)):
                            results["guarded"] += 1
    results["status"] = "VULNERABLE" if results["dispatchers"] > results["guarded"] else "PROTECTED"
    return results

if __name__ == "__main__":
    with open('assessment_report.csv', 'w') as f:
        w = csv.DictWriter(f, fieldnames=["file", "arch", "dispatchers", "guarded", "status"])
        w.writeheader()
        for b in sys.argv[1:]: w.writerow(audit_binary(b))
