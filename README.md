# Windows System Enumerator

A comprehensive Windows enumeration tool suite with multiple implementations and a Linux-based attack chain processor. This tool suite provides complete system enumeration, defensive evasion, and automated attack chain generation capabilities.

> 📖 **New to ENUMERATOR?** Start with the [**HOWTO Guide**](HOWTO.md) for step-by-step instructions.

## Overview

The ENUMERATOR tool suite consists of three main components:

1. **C Enumerator** - Full-featured C implementation for Windows 10 systems
2. **PowerShell Enumerator** - PowerShell script-based version for environments without C compiler
3. **Processor** - Linux-based tools for processing enumeration data and generating attack chains

## Repository Structure

```
ENUMERATOR/
├── c_enumerator/              # C implementation (Windows 10)
│   ├── enumerator.c/h         # Main program
│   ├── token_acquisition.c/h  # SYSTEM token acquisition
│   ├── defensive_blinding.c/h # Firewall/Defender blinding
│   ├── mdm_detection.c/h      # MDM detection
│   ├── mdm_neutralization.c/h # MDM neutralization
│   ├── edr_detection.c/h      # EDR product detection
│   ├── edr_evasion.c/h        # EDR evasion techniques
│   ├── network_recursive.c/h  # Recursive network discovery
│   ├── pastebin.c/h           # Pastebin upload
│   └── progress.c/h           # Progress display
├── powershell_enumerator/     # PowerShell implementation
│   └── enumerator.ps1         # Main PowerShell script
└── processor/                 # Linux-based processing tools
    ├── parser/                # Enumeration data parser
    │   ├── parser.py          # Main parser
    │   ├── vlan_diagram.py    # VLAN topology generation
    │   ├── doc_generator.py   # Documentation generation
    │   ├── cve_correlator.py  # CVE correlation
    │   ├── mitre_mapper.py    # MITRE ATT&CK mapping
    │   ├── topology_builder.py # Network topology
    │   ├── cve_chain_generator.py # CVE-based chains
    │   ├── technique_pattern_matcher.py # Technique matching
    │   ├── multi_stage_chain_builder.py # Multi-stage chains
    │   ├── ml_chain_suggester.py # ML-guided suggestions
    │   ├── chain_browser_tui.py # TUI interface
    │   ├── chain_explorer.py  # Graph-based explorer
    │   └── web_interface/     # Web-based interface
    └── debian_chain_compiler/ # Attack chain compiler (Debian only)
        └── chain_compiler.py  # Chain compiler
```

## Build Scripts

The ENUMERATOR tool suite includes convenient build/setup scripts for each component:

### Available Scripts

- **`build_c_enumerator.sh`** - Build C enumerator (Linux/Windows with MSYS2/MinGW)
- **`build_c_enumerator.bat`** - Build C enumerator (Windows Batch)
- **`setup_parser.sh`** - Setup processor parser (installs Python dependencies)
- **`setup_chain_compiler.sh`** - Setup chain compiler (Debian only, installs dependencies)
- **`build_all.sh`** - Master script to build/setup all components

### Usage Examples

```bash
# Build C enumerator
./build_c_enumerator.sh

# Setup parser (creates venv and installs dependencies)
./setup_parser.sh

# Setup chain compiler (Debian only)
./setup_chain_compiler.sh

# Build/setup everything
./build_all.sh              # All components
./build_all.sh parser       # Just parser
./build_all.sh c_enumerator # Just C enumerator
```

**Note:** Make scripts executable with `chmod +x *.sh` if needed.

## Components

### 1. C Enumerator (`c_enumerator/`)

Full-featured C implementation for Windows 10 systems with comprehensive system enumeration and defensive evasion capabilities.

**Key Features:**
- **SYSTEM Token Acquisition**: PE5-based, Windows API, service token stealing
- **Defensive Feature Blinding**: Firewall, Defender, Security Center
- **MDM Detection & Neutralization**: Detects and neutralizes MDM software
- **EDR Detection & Evasion**: Detects 16+ EDR products with continuous evasion
- **Comprehensive Enumeration**: System, network, processes, services, users, VLANs
- **Recursive Network Discovery**: W-SLAM-style recursive enumeration
- **Pastebin Upload**: Automatic upload with password protection
- **Self-Deletion**: Automatically deletes itself after completion

**Platform:** Windows 10 (Windows 7 support available via `Makefile.win7`)

**Documentation:** See `c_enumerator/README.md`

### 2. PowerShell Enumerator (`powershell_enumerator/`)

PowerShell script-based version providing identical functionality to the C version, making it easier to deploy in environments without C compilation.

**Key Features:**
- **Full Feature Parity** with C version
- **SYSTEM Token Acquisition**: Windows API and service token stealing
- **Defensive Feature Blinding**: Firewall, Defender, Security Center, WFP
- **MDM Detection & Neutralization**: Intune, AirWatch, MobileIron, Workspace ONE
- **EDR Detection & Evasion**: 16+ EDR products with comprehensive evasion
- **Enhanced Enumeration**: Post-exploitation indicators, AD infrastructure, WAF detection, C2 opportunities, steganography
- **Recursive Network Discovery**: W-SLAM-style with continuous EDR evasion
- **Pastebin Upload**: Automatic upload with fallback services
- **Self-Deletion**: Automatically deletes itself after completion

**Platform:** Windows 10 (PowerShell 5.1+ or PowerShell Core 7+)

**Documentation:** See `powershell_enumerator/README.md`

### 3. Processor (`processor/`)

Linux-based tools for processing enumeration data and generating sophisticated attack chains.

#### Parser (`processor/parser/`)

Downloads, parses, and visualizes enumeration data from Windows enumerators.

**Features:**
- Downloads enumeration data from Pastebin
- Parses enumeration data into structured format
- Generates VLAN diagrams (Mermaid, Graphviz, HTML)
- Creates documentation (Markdown, HTML)
- Correlates CVEs (local and network-wide)
- Maps to MITRE ATT&CK techniques
- Builds network topology visualizations
- Generates attack chains (CVE, technique, multi-stage, ML)
- Interactive browsing interfaces (TUI, Web, Graph-based)

**Platform:** Cross-platform (Python)

**Documentation:** See `processor/parser/README.md`

#### Debian Chain Compiler (`processor/debian_chain_compiler/`)

Compiles enumeration data into executable attack chains.

**Features:**
- Multi-source chain compilation (CVE, technique, multi-stage, ML)
- Chain optimization and risk assessment
- Execution graph building
- Detailed execution plan generation
- Multiple export formats (JSON, Markdown)

**Platform:** Debian Linux only (automatically checks OS compatibility)

**Documentation:** See `processor/debian_chain_compiler/README.md`

## Quick Start

### Building/Setting Up Components

**Quick Build Scripts Available:**

- **Build C Enumerator:**
  ```bash
  # Linux/Windows (MSYS2/MinGW)
  ./build_c_enumerator.sh
  
  # Windows (Batch)
  build_c_enumerator.bat
  ```

- **Setup Processor Parser:**
  ```bash
  ./setup_parser.sh
  ```

- **Setup Chain Compiler (Debian only):**
  ```bash
  ./setup_chain_compiler.sh
  ```

- **Build/Setup All Components:**
  ```bash
  ./build_all.sh [component]
  # component: c_enumerator, parser, chain_compiler, or all (default)
  ```

### Windows 10: Run Enumerator

**Option A: C Version**
```cmd
# Using build script
build_c_enumerator.bat

# Or manually
cd c_enumerator
make
enumerator.exe
```

**Option B: PowerShell Version**
```powershell
cd powershell_enumerator
.\enumerator.ps1
```

Both versions upload enumeration data to Pastebin with password "ducknipples" by default.

### Linux: Process Enumeration Data

**Step 1: Setup and Download/Parse**
```bash
# Setup parser (first time only)
./setup_parser.sh

# Parse enumeration data
cd processor/parser
python3 parser.py https://pastebin.com/XXXXX --password ducknipples
```

**Step 2: Compile Attack Chains (Debian only)**
```bash
# Setup chain compiler (first time only)
./setup_chain_compiler.sh

# Compile chains
cd processor/debian_chain_compiler
python3 chain_compiler.py ../parser/output/parsed_data.json -o compiled_chains.json
```

## Complete Workflow

### Phase 1: Enumeration (Windows 10)

1. **Run Enumerator** (C or PowerShell version)
   - Acquires SYSTEM token
   - Blinds defensive features
   - Detects and neutralizes MDM
   - Performs comprehensive enumeration
   - Uploads results to Pastebin
   - Displays URL and password
   - Self-deletes after confirmation

2. **Copy Pastebin URL** from output

### Phase 2: Processing (Linux)

1. **Download and Parse** enumeration data
   ```bash
   cd processor/parser
   python3 parser.py <PASTEBIN_URL> --password ducknipples
   ```

2. **Review Generated Outputs** in `processor/parser/output/`:
   - `parsed_data.json` - Structured enumeration data
   - `diagrams/` - VLAN and network topology diagrams
   - `docs/` - System and network documentation
   - `reports/` - CVE and MITRE ATT&CK reports

### Phase 3: Attack Chain Generation (Debian Linux)

1. **Compile Attack Chains**
   ```bash
   cd processor/debian_chain_compiler
   python3 chain_compiler.py ../parser/output/parsed_data.json -o compiled_chains.json
   ```

2. **Generate Execution Plan** for specific chain
   ```bash
   python3 chain_compiler.py ../parser/output/parsed_data.json --chain-id cve_chain_1
   ```

### Phase 4: Analysis and Visualization

1. **Browse Attack Chains** using interactive interfaces:
   - **TUI Interface**: `python3 processor/parser/chain_browser_tui.py`
   - **Web Interface**: `python3 processor/parser/web_interface/app.py`
   - **Graph Explorer**: `python3 processor/parser/chain_explorer.py`

2. **Review Generated Reports**:
   - CVE correlation reports
   - MITRE ATT&CK technique mappings
   - Network topology visualizations
   - Attack chain documentation

## Features

### Enumerator Features (Both C and PowerShell)

#### Privilege Escalation
- SYSTEM token acquisition via multiple methods
- Service token stealing
- PE5-based privilege escalation

#### Defensive Evasion
- Windows Firewall disabling
- Windows Defender neutralization
- Security Center blinding
- WFP (Windows Filtering Platform) manipulation (PowerShell)

#### MDM Detection & Neutralization
- Detects: Intune, AirWatch, MobileIron, Workspace ONE
- Neutralizes via callback zeroing and minifilter detachment

#### EDR Detection & Evasion
- **Detects 16+ EDR Products**: CrowdStrike, SentinelOne, Defender, Carbon Black, Trend Micro, Bitdefender, Sophos, Cylance, FireEye, Palo Alto, Elastic, Cybereason, Secureworks, F-Secure, Kaspersky, Symantec
- **Evasion Techniques**: Zero callbacks, detach minifilters, blind ETW, direct syscalls, AMSI bypass, API unhooking

#### System Enumeration
- OS information and version
- Hardware details (CPU, RAM, BIOS, disks)
- Processes with command lines
- Services and their states
- Registry keys (including protected keys with SYSTEM token)
- Filesystem enumeration (important directories)
- User accounts and groups
- Security information
- LSASS memory access (with SYSTEM token)

#### Network Enumeration
- Network interfaces and configurations
- Routing tables
- ARP tables
- Active connections
- Network discovery
- **Recursive Network Discovery**: W-SLAM-style recursive enumeration with continuous EDR evasion

#### VLAN Structure Enumeration
- VLAN IDs
- Tagged/untagged ports
- Trunk information
- WMI and network adapter queries

#### Enhanced Enumeration (PowerShell)
- **Post-Exploitation Indicators**: AMSI, ETW, WFP, COM hijacking, WMI persistence, Kerberos opportunities, rootkit indicators
- **AD Infrastructure**: Domain controllers, Netlogon, Certificate Services, ADCS web enrollment, certificate template vulnerabilities
- **WAF Detection**: Cloudflare, AWS WAF, Sucuri, Imperva
- **Web Application Technology**: IIS, Apache
- **C2 Opportunities**: Outbound connectivity, proxy configuration, SSH tunnels, DNS tunneling
- **Steganography Opportunities**: Image file enumeration for LSB steganography

#### Data Exfiltration
- Automatic Pastebin upload with password protection
- Fallback services (Hastebin, 0x0.st)
- Self-deletion after completion

### Processor Features

#### Parser Capabilities
- Downloads enumeration data from Pastebin
- Parses structured enumeration data
- Generates multiple output formats

#### Visualization
- **VLAN Diagrams**: Mermaid, Graphviz, HTML formats
- **Network Topology**: Interactive visualizations with MITRE ATT&CK and CVE overlays
- **Attack Chain Visualizations**: Graph-based chain representations

#### Documentation
- System documentation (Markdown, HTML)
- Network documentation
- CVE correlation reports
- MITRE ATT&CK technique reports

#### CVE Correlation
- Local CVE correlation (matches software versions to CVEs)
- Network-wide CVE correlation (identifies common vulnerabilities across network)
- CVSS score filtering
- Exploit availability tracking

#### MITRE ATT&CK Mapping
- Automatic mapping of enumeration activities to MITRE techniques
- Technique detection reports
- Integration with attack chain generation

#### Attack Chain Generation
- **CVE Chains**: SWORD integration for CVE-based attack chains
- **Technique Chains**: Matches enumeration data to attack techniques from integrated tools (W-SLAM, ROGUEPILOT, ROCKHAMMER, CORTISOL, ACTIVEGAME, SLEEPYMONEY, WINCLOAK)
- **Multi-Stage Chains**: Complete attack chains with conditional paths, fallbacks, and alternatives
- **ML-Guided Suggestions**: Optional integration with ML models for attack chain ideas

#### Interactive Interfaces
- **TUI Interface**: Textual user interface using Rich/Textual libraries
- **Web Interface**: Modern web-based interface with Cytoscape.js visualization
- **Chain Explorer**: Graph-based traversal and analysis of attack chains

#### Chain Compiler (Debian)
- Multi-source chain compilation
- Chain optimization and risk assessment
- Execution graph building
- Detailed execution plan generation
- Multiple export formats (JSON, Markdown)

## Architecture

### C Enumerator Architecture

The C enumerator consists of modular components:

- **`enumerator.c/h`**: Main program and orchestration
- **`token_acquisition.c/h`**: SYSTEM token acquisition (PE5, Windows API, service stealing)
- **`defensive_blinding.c/h`**: Firewall and defensive feature blinding
- **`mdm_detection.c/h`**: MDM software detection
- **`mdm_neutralization.c/h`**: MDM neutralization via callback zeroing
- **`edr_detection.c/h`**: EDR product detection
- **`edr_evasion.c/h`**: EDR evasion techniques
- **`network_recursive.c/h`**: Recursive network discovery with W-SLAM techniques
- **`progress.c/h`**: Progress bar display
- **`pastebin.c/h`**: Pastebin upload with fallback services

### Processor Architecture

The processor consists of two main components:

1. **Parser**: Modular Python toolkit with specialized modules for different analysis tasks
2. **Chain Compiler**: Debian-specific compiler that processes parsed data and generates executable attack chains

## Integration Points

### Enumerator → Processor
- Enumerators upload data to Pastebin
- Parser downloads and processes Pastebin data
- Structured JSON output feeds into chain compiler

### Parser → Chain Compiler
- Parser generates `parsed_data.json` with attack chain data
- Chain compiler reads parsed data and compiles executable chains
- Chain compiler integrates parser modules for chain generation

### External Integrations
- **SWORD**: CVE chaining capabilities
- **MITRE ATT&CK**: Technique mapping and reporting
- **NVD API**: CVE correlation (optional API key)
- **ML Models**: Optional ML-guided attack chain suggestions

## Requirements

### C Enumerator
- Windows 10 (Windows 7 support available)
- MinGW or MSVC compiler
- Windows SDK
- Required libraries: ws2_32, iphlpapi, advapi32, ole32, oleaut32, wbemuuid, netapi32, crypt32, wldap32

### PowerShell Enumerator
- Windows 10
- PowerShell 5.1+ or PowerShell Core 7+
- Administrator privileges
- Network access

### Parser
- Python 3.8+
- See `processor/parser/requirements.txt` for dependencies

### Chain Compiler
- Debian Linux (Debian 11/12 tested)
- Python 3.8+
- See `processor/debian_chain_compiler/requirements.txt` for dependencies

## Security Notes

⚠️ **Important Security Considerations:**

- Requires administrator privileges on Windows
- Performs system modifications (firewall, defender)
- Self-deletes after execution
- Uploads sensitive enumeration data to cloud services
- Chain compiler generates executable attack chains

**Use responsibly and only on systems you own or have explicit permission to test.**

## License

See project license file.

## Documentation

- **[HOWTO.md](HOWTO.md)** - Comprehensive step-by-step usage guide ⭐ **START HERE**
- `c_enumerator/README.md` - C enumerator documentation
- `c_enumerator/QUICK_BUILD.md` - Quick build guide
- `c_enumerator/BUILD_WIN7.md` - Windows 7 build instructions
- `powershell_enumerator/README.md` - PowerShell enumerator documentation
- `processor/README.md` - Processor overview
- `processor/parser/README.md` - Parser toolkit documentation
- `processor/debian_chain_compiler/README.md` - Chain compiler documentation
