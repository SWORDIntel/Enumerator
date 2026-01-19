# Quick Build Instructions for Windows 7

## Prerequisites

Install MinGW-w64 cross-compiler:

```bash
sudo apt-get update
sudo apt-get install -y mingw-w64
```

## Build

```bash
cd tools/ENUMERATOR/c_enumerator
./build_win7.sh
```

## Alternative: Custom Cross-Compiler Location

If MinGW-w64 is installed in a non-standard location:

```bash
export CROSS_PREFIX=/path/to/mingw64/bin/x86_64-w64-mingw32-
./build_win7.sh
```

## Output

The build will produce `enumerator.exe` - a Windows 7 compatible executable.

## Verify Build

After building, you should see:
```
[ENUMERATOR] Build successful!
[ENUMERATOR] Output: enumerator.exe (size: X bytes)
[ENUMERATOR] Target: Windows 7 (x86_64)
```

## Troubleshooting

### Cross-compiler not found
- Install MinGW-w64: `sudo apt-get install -y mingw-w64`
- Or set `CROSS_PREFIX` environment variable to your compiler path

### Build errors
- Ensure all source files are present
- Check that you have write permissions in the directory
- Verify MinGW-w64 installation: `x86_64-w64-mingw32-gcc --version`
