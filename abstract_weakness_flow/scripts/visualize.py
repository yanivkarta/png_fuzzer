import sys

def generate_visual_flow(binary_name, offset_hex):
    dot_content = f"""
    digraph AbstractWeaknessFlow {{
        rankdir=LR;
        node [shape=box, fontname="Helvetica", style=filled];
        
        Trigger [label="trigger.bin", fillcolor="#ffcccc"];
        Struct [label="Config Struct\\n(Offset {offset_hex})", fillcolor="#fff3cd"];
        Reg_X30 [label="LR (x30)\\nHijacked", fillcolor="#d1ecf1", penwidth=2];
        Sink [label="win_gadget()", fillcolor="#d4edda", shape=doubleoctagon];
        
        Trigger -> Struct [label="Data-Only Map"];
        Struct -> Reg_X30 [label="LDR + MOV"];
        Reg_X30 -> Sink [label="RET Instruction"];
        
        label = "Taint Flow: {binary_name}";
        fontsize = 20;
    }}
    """
    with open("taint_flow.dot", "w") as f:
        f.write(dot_content)
    print("[+] Visualization 'taint_flow.dot' generated.")

if __name__ == "__main__":
    name = sys.argv[1] if len(sys.argv) > 1 else "target_aarch64"
    generate_visual_flow(name, "0x40")
