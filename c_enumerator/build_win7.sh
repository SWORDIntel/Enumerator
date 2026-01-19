#!/bin/bash
# Cross-compilation build script for Windows 7
# This script builds the enumerator for Windows 7 using MinGW-w64 cross-compiler
# Usage: ./build_win7.sh [clean]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
TARGET="enumerator.exe"
CROSS_PREFIX="${CROSS_PREFIX:-x86_64-w64-mingw32-}"
CC="${CROSS_PREFIX}gcc"
CXX="${CROSS_PREFIX}g++"
AR="${CROSS_PREFIX}ar"
STRIP="${CROSS_PREFIX}strip"

# Windows 7 target flags
WIN7_CFLAGS="-DWINVER=0x0601 -D_WIN32_WINNT=0x0601 -DNTDDI_VERSION=0x06010000"
CFLAGS="-Wall -Wextra -std=c99 -O2 -static ${WIN7_CFLAGS}"
LDFLAGS="-static -lws2_32 -liphlpapi -ladvapi32 -lole32 -loleaut32 -lwbemuuid -lwininet -lnetapi32 -lcrypt32 -lwldap32 -lm -lpsapi -lmpr"

# Source files
SOURCES=(
    "enumerator.c"
    "token_acquisition.c"
    "progress.c"
    "pastebin.c"
    "network_recursive.c"
    "mdm_detection.c"
    "mdm_neutralization.c"
    "edr_detection.c"
    "edr_evasion.c"
    "defensive_blinding.c"
)

# Check if clean requested
if [ "$1" == "clean" ]; then
    echo -e "${YELLOW}[ENUMERATOR] Cleaning build artifacts...${NC}"
    rm -f *.o *.exe *.obj
    echo -e "${GREEN}[ENUMERATOR] Clean complete.${NC}"
    exit 0
fi

# Check for cross-compiler
if ! command -v "$CC" &> /dev/null; then
    echo -e "${RED}[ENUMERATOR] ERROR: Cross-compiler '$CC' not found!${NC}"
    echo -e "${YELLOW}[ENUMERATOR] Please install MinGW-w64 cross-compiler:${NC}"
    echo -e "${YELLOW}  Ubuntu/Debian: sudo apt-get install mingw-w64${NC}"
    echo -e "${YELLOW}  Fedora: sudo dnf install mingw64-gcc${NC}"
    echo -e "${YELLOW}  Arch: sudo pacman -S mingw-w64-gcc${NC}"
    echo -e "${YELLOW}  Or set CROSS_PREFIX environment variable${NC}"
    exit 1
fi

echo -e "${GREEN}[ENUMERATOR] Building for Windows 7 (x86_64)...${NC}"
echo -e "${YELLOW}[ENUMERATOR] Using compiler: $CC${NC}"

# Compile all source files
OBJECTS=()
for source in "${SOURCES[@]}"; do
    if [ ! -f "$source" ]; then
        echo -e "${RED}[ENUMERATOR] ERROR: Source file '$source' not found!${NC}"
        exit 1
    fi
    
    object="${source%.c}.o"
    echo -e "${YELLOW}[ENUMERATOR] Compiling $source...${NC}"
    "$CC" $CFLAGS -c "$source" -o "$object"
    OBJECTS+=("$object")
done

# Link executable
echo -e "${YELLOW}[ENUMERATOR] Linking $TARGET...${NC}"
"$CC" "${OBJECTS[@]}" -o "$TARGET" $LDFLAGS

# Strip symbols (optional, reduces size)
if command -v "$STRIP" &> /dev/null; then
    echo -e "${YELLOW}[ENUMERATOR] Stripping symbols...${NC}"
    "$STRIP" --strip-all "$TARGET"
fi

# Check if build succeeded
if [ -f "$TARGET" ]; then
    SIZE=$(stat -c%s "$TARGET" 2>/dev/null || stat -f%z "$TARGET" 2>/dev/null || echo "unknown")
    echo -e "${GREEN}[ENUMERATOR] Build successful!${NC}"
    echo -e "${GREEN}[ENUMERATOR] Output: $TARGET (size: $SIZE bytes)${NC}"
    echo -e "${GREEN}[ENUMERATOR] Target: Windows 7 (x86_64)${NC}"
    
    # Clean up object files
    rm -f "${OBJECTS[@]}"
    
    exit 0
else
    echo -e "${RED}[ENUMERATOR] Build failed!${NC}"
    exit 1
fi
