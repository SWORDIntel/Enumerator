# Debian Chain Compiler

**Debian Linux Only** - Attack chain compiler that processes Windows enumeration data and constructs sophisticated, executable attack chains.

## Requirements

- **OS**: Debian Linux (tested on Debian 11/12)
- **Python**: Python 3.8 or higher
- **Dependencies**: See `requirements.txt`

## Installation

### On Debian System

```bash
# Install system dependencies
sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-venv

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt
```

### Verify Debian Compatibility

The compiler automatically checks if it's running on Debian. If you see:

```
ERROR: This tool only runs on Debian Linux
```

You're not on a Debian system. The tool will exit.

## Usage

### Basic Compilation

```bash
# Compile chains from Windows enumeration data
python3 chain_compiler.py ../parser/output/parsed_data.json

# Specify output file and format
python3 chain_compiler.py ../parser/output/parsed_data.json -o compiled_chains.json -f json

# Export as Markdown
python3 chain_compiler.py ../parser/output/parsed_data.json -f markdown -o chains.md
```

### Generate Execution Plan

```bash
# Generate detailed execution plan for specific chain
python3 chain_compiler.py ../parser/output/parsed_data.json --chain-id cve_chain_1
```

## Input Format

The compiler expects JSON enumeration data from the Windows enumerator (C or PowerShell version). The data should be in the format produced by `parser/parser.py`:

```json
{
  "timestamp": "2024-01-01 12:00:00",
  "system_info": {
    "os_version": "Windows 10",
    "computer_name": "TARGET-PC",
    "current_user": "user"
  },
  "network_cves": {
    "CVE-2023-1234": {
      "cvss_score": 9.8,
      "exploit_available": true,
      "affected_software": ["Software 1.0"]
    }
  },
  "techniques": [...],
  "attack_chains": [...],
  "multi_stage_chains": [...]
}
```

## Output Format

### JSON Output

```json
{
  "compiled_at": "2024-01-01T12:00:00",
  "source_data": {
    "timestamp": "2024-01-01 12:00:00",
    "computer_name": "TARGET-PC"
  },
  "chains": [
    {
      "chain_id": "cve_chain_1",
      "name": "Attack Chain for CVE-2023-1234",
      "description": "...",
      "source": "cve",
      "steps": [...],
      "success_probability": 0.85,
      "risk_level": "high",
      "cves": ["CVE-2023-1234"],
      "mitre_techniques": ["T1190", "T1068"]
    }
  ],
  "statistics": {
    "total_chains": 10,
    "by_source": {...},
    "by_risk": {...}
  }
}
```

### Markdown Output

Markdown report with formatted chain descriptions, steps, and metadata.

## Chain Sources

1. **CVE Chains**: Generated from discovered CVEs using SWORD integration
2. **Technique Chains**: Built from matched attack techniques (W-SLAM, ROGUEPILOT, etc.)
3. **Multi-Stage Chains**: Complete attack chains with all stages
4. **ML Chains**: ML-guided suggestions (if ai/ directory available)

## Risk Levels

- **Critical**: Success probability ≥ 90%
- **High**: Success probability ≥ 70%
- **Medium**: Success probability ≥ 50%
- **Low**: Success probability < 50%

## Integration with Parser

The compiler integrates with the parser modules from `../parser/`:
- `cve_chain_generator.py`: CVE-based chain generation
- `technique_pattern_matcher.py`: Technique pattern matching
- `multi_stage_chain_builder.py`: Multi-stage chain building
- `ml_chain_suggester.py`: ML-guided suggestions

## Complete Workflow

### Step 1: Run Windows Enumerator (Windows 10)

**Option A: C Version**
```cmd
enumerator.exe
```

**Option B: PowerShell Version**
```powershell
.\enumerator.ps1
```

Both upload enumeration data to Pastebin.

### Step 2: Download and Parse (Debian)

```bash
cd parser
python3 parser.py https://pastebin.com/XXXXX --password ducknipples
```

### Step 3: Compile Attack Chains (Debian)

```bash
cd ../debian_chain_compiler
python3 chain_compiler.py ../parser/output/parsed_data.json -o compiled_chains.json
```

### Step 4: Generate Execution Plan (Debian)

```bash
python3 chain_compiler.py ../parser/output/parsed_data.json --chain-id cve_chain_1
```

## Troubleshooting

### "Parser directory not found"

If you see this warning, make sure you're running from the correct directory and the `../parser/` path exists.

### "This tool only runs on Debian Linux"

The compiler checks for Debian before running. If you're on a different Linux distribution, you'll need to run it on Debian.

### Missing Dependencies

```bash
pip3 install --upgrade -r requirements.txt
```

## License

See project license file.
