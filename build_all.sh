#!/bin/bash
# Master build script - Builds/setups all ENUMERATOR components
# Usage: ./build_all.sh [component]
#   component: c_enumerator, parser, chain_compiler, or all (default)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

COMPONENT="${1:-all}"

echo "=== ENUMERATOR Build Script ==="
echo ""

case "$COMPONENT" in
    c_enumerator)
        echo "Building C Enumerator..."
        ./build_c_enumerator.sh
        ;;
    parser)
        echo "Setting up Processor Parser..."
        ./setup_parser.sh
        ;;
    chain_compiler)
        echo "Setting up Debian Chain Compiler..."
        ./setup_chain_compiler.sh
        ;;
    all)
        echo "Building/setting up all components..."
        echo ""
        
        # Build C enumerator (if on Windows/MinGW)
        if command -v gcc &> /dev/null || command -v x86_64-w64-mingw32-gcc &> /dev/null; then
            echo "[1/3] Building C Enumerator..."
            ./build_c_enumerator.sh || echo "[!] C Enumerator build skipped (no compiler or not on Windows)"
            echo ""
        else
            echo "[1/3] C Enumerator: Skipped (no compiler found)"
            echo ""
        fi
        
        # Setup parser
        echo "[2/3] Setting up Processor Parser..."
        ./setup_parser.sh
        echo ""
        
        # Setup chain compiler (only on Debian)
        if [ -f /etc/os-release ] && grep -qi "debian" /etc/os-release; then
            echo "[3/3] Setting up Debian Chain Compiler..."
            ./setup_chain_compiler.sh
        else
            echo "[3/3] Debian Chain Compiler: Skipped (not on Debian)"
            echo "      Run ./setup_chain_compiler.sh manually on Debian systems"
        fi
        
        echo ""
        echo "[+] All components processed!"
        ;;
    *)
        echo "Usage: $0 [component]"
        echo ""
        echo "Components:"
        echo "  c_enumerator   - Build C enumerator (Windows/MinGW)"
        echo "  parser         - Setup processor parser (Python)"
        echo "  chain_compiler - Setup chain compiler (Debian only)"
        echo "  all            - Build/setup all components (default)"
        echo ""
        exit 1
        ;;
esac

echo ""
echo "=== Build Complete ==="
