#!/bin/bash
# Build script for C Enumerator
# Works on Windows (MSYS2/MinGW) and Linux (cross-compile)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/c_enumerator"

echo "=== Building C Enumerator ==="
echo ""

# Check for compiler
if command -v gcc &> /dev/null; then
    CC="gcc"
    echo "[+] Found GCC compiler"
elif command -v x86_64-w64-mingw32-gcc &> /dev/null; then
    CC="x86_64-w64-mingw32-gcc"
    echo "[+] Found MinGW cross-compiler"
else
    echo "ERROR: No suitable compiler found"
    echo "Please install MinGW (Windows) or MinGW-w64 (Linux cross-compile)"
    exit 1
fi

# Check if Makefile exists
if [ ! -f "Makefile" ]; then
    echo "ERROR: Makefile not found in c_enumerator/"
    exit 1
fi

# Clean previous build
echo "[*] Cleaning previous build..."
make clean 2>/dev/null || true

# Build
echo "[*] Building enumerator.exe..."
make CC="$CC"

# Check if build succeeded
if [ -f "enumerator.exe" ]; then
    echo ""
    echo "[+] Build successful!"
    echo "[+] Executable: $(pwd)/enumerator.exe"
    echo ""
    echo "To run:"
    echo "  cd c_enumerator"
    echo "  ./enumerator.exe"
else
    echo ""
    echo "ERROR: Build failed - enumerator.exe not found"
    exit 1
fi
