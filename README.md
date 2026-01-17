# Windows System Enumerator

A comprehensive Windows enumeration tool suite with multiple implementations and a Linux-based attack chain processor.

## Repository Structure

This repository is organized into three main components:

### 1. C Enumerator (`c_enumerator/`)

Full-featured C implementation for Windows 10 systems.

- **Files**: C source code, headers, Makefile, build scripts
- **Output**: Compiled `enumerator.exe` executable
- **Platform**: Windows 10
- **Documentation**: See `c_enumerator/README.md`

### 2. PowerShell Enumerator (`powershell_enumerator/`)

PowerShell script-based version for environments without C compiler.

- **Files**: `enumerator.ps1` PowerShell script
- **Output**: Runs directly as PowerShell script
- **Platform**: Windows 10 (PowerShell 5.1+ or PowerShell Core 7+)
- **Documentation**: See `powershell_enumerator/README.md`

### 3. Processor (`processor/`)

Linux-based tools for processing enumeration data and generating attack chains.

- **Parser**: Downloads, parses, and visualizes enumeration data
- **Debian Chain Compiler**: Compiles enumeration data into executable attack chains (Debian Linux only)
- **Platform**: Cross-platform (Python) for parser, Debian-only for chain compiler
- **Documentation**: 
  - `processor/parser/README.md` - Parser toolkit documentation
  - `processor/debian_chain_compiler/README.md` - Chain compiler documentation

## Quick Start

### Windows 10: Run Enumerator

**Option A: C Version**
```cmd
cd c_enumerator
make
enumerator.exe
```

**Option B: PowerShell Version**
```powershell
cd powershell_enumerator
.\enumerator.ps1
```

Both versions upload enumeration data to Pastebin.

### Linux: Process Enumeration Data

**Step 1: Download and Parse**
```bash
cd processor/parser
python3 parser.py https://pastebin.com/XXXXX --password ducknipples
```

**Step 2: Compile Attack Chains (Debian only)**
```bash
cd processor/debian_chain_compiler
python3 chain_compiler.py ../parser/output/parsed_data.json -o compiled_chains.json
```

## Features

### Enumerator Features (Both C and PowerShell)

- **SYSTEM Token Acquisition**: PE5-based, Windows API, service token stealing
- **Defensive Feature Blinding**: Firewall, Defender, Security Center
- **MDM Detection & Neutralization**: Detects and neutralizes MDM software
- **EDR Detection & Evasion**: Detects 16+ EDR products with continuous evasion
- **Comprehensive Enumeration**: System, network, processes, services, users, VLANs
- **Enhanced Enumeration**: Post-exploitation indicators, AD infrastructure, WAF detection, C2 opportunities, steganography
- **Recursive Network Discovery**: W-SLAM-style recursive enumeration
- **Pastebin Upload**: Automatic upload with password protection and fallback services
- **Self-Deletion**: Automatically deletes itself after completion

### Processor Features

- **Parser**: Downloads, parses, and visualizes enumeration data
- **Attack Chain Generation**: CVE chains, technique patterns, multi-stage chains, ML suggestions
- **MITRE ATT&CK Mapping**: Automatically maps enumeration activities to MITRE techniques
- **CVE Correlation**: Matches software versions to high-ranking CVEs
- **Network Topology**: Builds interactive network topology visualizations
- **Chain Compiler**: Compiles enumeration data into executable attack chains (Debian only)

## Complete Workflow

1. **Windows 10**: Run enumerator (C or PowerShell) → Uploads to Pastebin
2. **Linux**: Download enumeration data using parser
3. **Debian**: Compile attack chains using chain compiler
4. **Any Platform**: Generate visualizations and documentation using parser

## License

See project license file.
