#!/bin/bash
# Installation script for Debian Chain Compiler
# Only runs on Debian systems

set -e

echo "=== Debian Chain Compiler Installation ==="

# Check if running on Debian
if [ ! -f /etc/os-release ]; then
    echo "ERROR: Cannot determine OS. This tool only runs on Debian."
    exit 1
fi

if ! grep -qi "debian" /etc/os-release; then
    echo "ERROR: This tool only runs on Debian Linux"
    echo "Detected OS: $(grep PRETTY_NAME /etc/os-release | cut -d'"' -f2)"
    exit 1
fi

echo "[+] Debian detected. Proceeding with installation..."

# Check Python version
if ! command -v python3 &> /dev/null; then
    echo "[*] Installing Python 3..."
    sudo apt-get update
    sudo apt-get install -y python3 python3-pip python3-venv
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2 | cut -d'.' -f1,2)
echo "[+] Python version: $(python3 --version)"

# Create virtual environment
if [ ! -d "venv" ]; then
    echo "[*] Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "[*] Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo "[*] Upgrading pip..."
pip install --upgrade pip

# Install dependencies
echo "[*] Installing Python dependencies..."
pip install -r requirements.txt

echo ""
echo "[+] Installation complete!"
echo ""
echo "To use the compiler:"
echo "  1. Activate virtual environment: source venv/bin/activate"
echo "  2. Run compiler: python3 chain_compiler.py <input_file>"
echo ""
