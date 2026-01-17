# Processor

Linux-based tools for processing Windows enumeration data and generating sophisticated attack chains.

## Components

### Parser (`parser/`)

Downloads, parses, and visualizes enumeration data from Windows enumerators.

**Features:**
- Downloads enumeration data from Pastebin
- Parses enumeration data into structured format
- Generates VLAN diagrams (Mermaid, Graphviz, HTML)
- Creates documentation (Markdown, HTML, PDF)
- Correlates CVEs (local and network-wide)
- Maps to MITRE ATT&CK techniques
- Builds network topology visualizations
- Generates attack chains

**Platform:** Cross-platform (Python)

**Documentation:** See `parser/README.md`

### Debian Chain Compiler (`debian_chain_compiler/`)

Compiles enumeration data into executable attack chains.

**Features:**
- Multi-source chain compilation (CVE, technique, multi-stage, ML)
- Chain optimization and risk assessment
- Execution graph building
- Detailed execution plan generation
- Multiple export formats (JSON, Markdown)

**Platform:** Debian Linux only (automatically checks OS compatibility)

**Documentation:** See `debian_chain_compiler/README.md`

## Quick Start

### Parse Enumeration Data

```bash
cd parser
python3 parser.py https://pastebin.com/XXXXX --password ducknipples
```

### Compile Attack Chains (Debian only)

```bash
cd debian_chain_compiler
python3 chain_compiler.py ../parser/output/parsed_data.json -o compiled_chains.json
```

## Installation

### Parser

```bash
cd parser
pip install -r requirements.txt
```

### Debian Chain Compiler

```bash
cd debian_chain_compiler
./install.sh
```

## Workflow

1. **Windows 10**: Run enumerator (C or PowerShell) → Uploads to Pastebin
2. **Linux**: Download enumeration data using parser
3. **Debian**: Compile attack chains using chain compiler
4. **Any Platform**: Generate visualizations and documentation using parser

## See Also

- `../c_enumerator/` - C enumerator for Windows
- `../powershell_enumerator/` - PowerShell enumerator for Windows
