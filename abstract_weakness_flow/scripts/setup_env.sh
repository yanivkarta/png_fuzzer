#!/bin/bash

echo "--- [abstract_weakness_flow] Environment Setup ---"

# 1. Update Package Lists
sudo apt-get update

# 2. Install Cross-Compilation Toolchains
echo "[*] Installing AArch64 and ARMhf toolchains..."
sudo apt-get install -y \
    gcc-aarch64-linux-gnu \
    gcc-arm-linux-gnueabihf \
    libc6-dev-arm64-cross \
    libc6-dev-armhf-cross

# 3. Install Debugging and Analysis Utilities
echo "[*] Installing GDB, QEMU, and Graphviz..."
sudo apt-get install -y \
    gdb-multiarch \
    qemu-user \
    qemu-user-static \
    graphviz \
    make \
    nm

# 4. Install Python Dependencies
echo "[*] Installing Python analysis libraries..."
sudo apt-get install -y python3-pip
pip3 install --upgrade pip
pip3 install capstone pyelftools

# 5. Finalize GDB Integration
if [ ! -f ~/.gdbinit ]; then
    cp .gdbinit ~/
    echo "[+] .gdbinit copied to home directory."
else
    echo "[!] Warning: ~/.gdbinit already exists. Manual merge recommended."
fi

echo "--- Setup Complete. You are ready to run ./run_all.sh ---"
