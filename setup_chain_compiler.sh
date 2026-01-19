#!/bin/bash
# Setup script for Debian Chain Compiler
# Wrapper around install.sh with better error handling

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/processor/debian_chain_compiler"

echo "=== Setting up Debian Chain Compiler ==="
echo ""

# Check if install.sh exists
if [ ! -f "install.sh" ]; then
    echo "ERROR: install.sh not found in processor/debian_chain_compiler/"
    exit 1
fi

# Make install.sh executable
chmod +x install.sh

# Run install.sh
echo "[*] Running installation script..."
./install.sh

echo ""
echo "[+] Setup complete!"
echo ""
echo "To use the chain compiler:"
echo "  1. Activate virtual environment: source venv/bin/activate"
echo "  2. Run compiler: python3 chain_compiler.py <input_file> -o <output_file>"
echo ""
