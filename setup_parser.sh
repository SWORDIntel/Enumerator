#!/bin/bash
# Setup script for Processor Parser
# Installs Python dependencies

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/processor/parser"

echo "=== Setting up Processor Parser ==="
echo ""

# Check Python version
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python 3 not found"
    echo "Please install Python 3.8 or higher"
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
echo "[+] Python version: $PYTHON_VERSION"

# Check Python version >= 3.8
PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d'.' -f1)
PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d'.' -f2)
if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 8 ]); then
    echo "ERROR: Python 3.8 or higher required"
    exit 1
fi

# Check if requirements.txt exists
if [ ! -f "requirements.txt" ]; then
    echo "ERROR: requirements.txt not found in processor/parser/"
    exit 1
fi

# Create virtual environment (optional but recommended)
if [ ! -d "venv" ]; then
    echo "[*] Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "[*] Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo "[*] Upgrading pip..."
pip install --upgrade pip > /dev/null 2>&1

# Install dependencies
echo "[*] Installing Python dependencies..."
pip install -r requirements.txt

echo ""
echo "[+] Setup complete!"
echo ""
echo "To use the parser:"
echo "  1. Activate virtual environment: source venv/bin/activate"
echo "  2. Run parser: python3 parser.py <pastebin_url> --password <password>"
echo ""
echo "Or use without venv:"
echo "  python3 parser.py <pastebin_url> --password <password>"
echo ""
