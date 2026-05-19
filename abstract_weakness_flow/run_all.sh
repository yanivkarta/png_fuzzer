#!/bin/bash

# Usage: ./run_all.sh [aarch64 | arm32 | thumb | race | clean]
TARGET_MODE=${1:-aarch64}

# Configuration
BINARY="target_$TARGET_MODE"
if [ "$TARGET_MODE" == "race" ]; then BINARY="target_race"; fi

# 1. Clean up previous artifacts
if [ "$TARGET_MODE" == "clean" ]; then
    make clean
    rm -f trigger.bin assessment_report.csv taint_flow.dot taint_flow.png exfiltration_log.txt
    exit 0
fi

echo "--- [1/5] Compiling: $TARGET_MODE ---"
make $BINARY

if [ ! -f "$BINARY" ]; then
    echo "[!] Compilation failed. Check your toolchain."
    exit 1
fi

echo "--- [2/5] Static Analysis & Heuristic Scanning ---"
python3 scripts/analyze_all.py "$BINARY"

echo "--- [3/5] Mapping Struct & Generating Trigger Payload ---"
python3 scripts/gen_payload.py "$BINARY"

echo "--- [4/5] Executing & Monitoring Feedback ---"
# We use the monitor script to catch PAC/BTI traps via GDB/ESR
python3 scripts/monitor.py "$BINARY"

echo "--- [5/5] Visualizing Abstract Weakness Flow ---"
python3 scripts/visualize.py "$BINARY"
if command -v dot &> /dev/null; then
    dot -Tpng taint_flow.dot -o taint_flow.png
    echo "[+] Visualization saved to taint_flow.png"
else
    echo "[*] Graphviz 'dot' not found. Skip PNG generation."
fi

echo "--- Process Complete: Check assessment_report.csv for results ---"
