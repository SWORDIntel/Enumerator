# Building for Windows 7

This document describes how to cross-compile the Windows System Enumerator for Windows 7.

## Windows 7 Compatibility

The enumerator has been configured for Windows 7 compatibility:
- **Target Version**: Windows 7 (NT 6.1)
- **WINVER**: 0x0601
- **NTDDI_VERSION**: 0x06010000
- **snprintf compatibility**: Automatic fallback to `_snprintf` for older MSVC

## Cross-Compilation from Linux/Unix

### Prerequisites

Install MinGW-w64 cross-compiler:

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install mingw-w64
```

**Fedora:**
```bash
sudo dnf install mingw64-gcc
```

**Arch Linux:**
```bash
sudo pacman -S mingw-w64-gcc
```

### Build Methods

#### Method 1: Using the Shell Script (Recommended)

```bash
./build_win7.sh
```

To clean build artifacts:
```bash
./build_win7.sh clean
```

#### Method 2: Using Makefile

```bash
make -f Makefile.win7
```

Check for cross-compiler:
```bash
make -f Makefile.win7 check
```

Clean build artifacts:
```bash
make -f Makefile.win7 clean
```

#### Method 3: Manual Compilation

```bash
# Set cross-compiler prefix (adjust if needed)
export CROSS_PREFIX=x86_64-w64-mingw32-

# Compile
$CROSS_PREFIX-gcc -Wall -Wextra -std=c99 -O2 -static \
  -DWINVER=0x0601 -D_WIN32_WINNT=0x0601 -DNTDDI_VERSION=0x06010000 \
  -c enumerator.c token_acquisition.c progress.c pastebin.c \
     network_recursive.c mdm_detection.c mdm_neutralization.c \
     edr_detection.c edr_evasion.c defensive_blinding.c

# Link
$CROSS_PREFIX-gcc *.o -o enumerator.exe -static \
  -lws2_32 -liphlpapi -ladvapi32 -lole32 -loleaut32 -lwbemuuid \
  -lwininet -lnetapi32 -lcrypt32 -lwldap32 -lm -lpsapi -lmpr

# Strip (optional)
$CROSS_PREFIX-strip --strip-all enumerator.exe
```

## Native Build on Windows 7

### Using MinGW

```cmd
build_win7.bat
```

Or manually:
```cmd
gcc -Wall -Wextra -std=c99 -O2 -static -DWINVER=0x0601 -D_WIN32_WINNT=0x0601 -DNTDDI_VERSION=0x06010000 enumerator.c token_acquisition.c progress.c pastebin.c network_recursive.c mdm_detection.c mdm_neutralization.c edr_detection.c edr_evasion.c defensive_blinding.c -o enumerator.exe -static -lws2_32 -liphlpapi -ladvapi32 -lole32 -loleaut32 -lwbemuuid -lwininet -lnetapi32 -lcrypt32 -lwldap32 -lm -lpsapi -lmpr
```

### Using MSVC

```cmd
cl /W4 /O2 /MT /DWINVER=0x0601 /D_WIN32_WINNT=0x0601 /DNTDDI_VERSION=0x06010000 /Fe:enumerator.exe enumerator.c token_acquisition.c progress.c pastebin.c network_recursive.c mdm_detection.c mdm_neutralization.c edr_detection.c edr_evasion.c defensive_blinding.c ws2_32.lib iphlpapi.lib advapi32.lib ole32.lib oleaut32.lib wbemuuid.lib wininet.lib netapi32.lib crypt32.lib wldap32.lib psapi.lib mpr.lib
```

## Build Output

The build process produces:
- **enumerator.exe**: Windows 7 compatible executable
- Static linking ensures no external DLL dependencies (except system DLLs)

## Verification

To verify Windows 7 compatibility:
1. Check that `WINVER=0x0601` and `_WIN32_WINNT=0x0601` are defined
2. Test on Windows 7 system or Windows 7 virtual machine
3. Verify all APIs used are available in Windows 7

## Troubleshooting

### Cross-compiler not found
- Install MinGW-w64 package for your distribution
- Or set `CROSS_PREFIX` environment variable to your cross-compiler prefix

### Missing libraries
- Ensure all required Windows libraries are available
- For static linking, MinGW-w64 should include all necessary libraries

### snprintf errors
- The `win7_compat.h` header automatically handles `snprintf` compatibility
- For MSVC < 2015, it uses `_snprintf` with proper null termination

## Files Modified for Windows 7

All source files include `win7_compat.h` which provides:
- Windows 7 version defines
- snprintf compatibility macros
- vsnprintf compatibility macros

## See Also

- `README.md` - General build instructions
- `build.bat` - Original Windows build script
- `Makefile` - Original Makefile
