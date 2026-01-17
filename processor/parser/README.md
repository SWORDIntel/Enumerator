# Enumeration Parser Toolkit

Python toolkit for processing, analyzing, and visualizing Windows System Enumerator data.

## Features

- **Parser**: Downloads and parses enumeration data from Pastebin
- **VLAN Diagrams**: Generates VLAN topology diagrams (Mermaid, Graphviz, HTML)
- **Documentation**: Creates easy-to-review documentation (Markdown, HTML)
- **CVE Correlation**: Matches software versions to high-ranking CVEs (local and network-wide)
- **Network Topology**: Builds interactive network topology visualizations with MITRE ATT&CK and CVE overlays
- **MITRE ATT&CK Mapping**: Automatically maps enumeration activities to MITRE ATT&CK techniques
- **Recursive Network Discovery**: W-SLAM-style recursive network enumeration (SMB, WMI, RDP, WinRM, SSH)
- **Attack Chain Generation**: Generates sophisticated attack chains from discovered vulnerabilities and techniques
  - **CVE Chain Generator**: Integrates SWORD's CVE chaining capabilities
  - **Technique Pattern Matcher**: Matches enumeration data to attack techniques from W-SLAM, ROGUEPILOT, ROCKHAMMER, CORTISOL, ACTIVEGAME, SLEEPYMONEY, WINCLOAK
  - **Multi-Stage Chain Builder**: Builds complete attack chains with conditional paths, fallbacks, and alternatives
  - **ML-Guided Suggestions**: Optional integration with ai/ directory for ML-driven attack chain ideas
- **Rich Browsing Interfaces**: Interactive exploration of attack chains
  - **TUI Interface**: Textual user interface using Rich/Textual libraries
  - **Web Interface**: Modern web-based interface with Cytoscape.js visualization
  - **Chain Explorer**: Graph-based traversal and analysis of attack chains

## Installation

```bash
cd tools/ENUMERATOR/parser
pip install -r requirements.txt
```

## Usage

### Parse Enumeration Data

```bash
# From Pastebin URL
python parser.py https://pastebin.com/XXXXX --password ducknipples

# From local file
python parser.py --file enumeration_data.txt
```

### Generate All Outputs

```python
from parser import EnumerationParser
from vlan_diagram import VLANDiagramGenerator
from doc_generator import DocumentationGenerator
from cve_correlator import CVECorrelator
from network_cve_correlator import NetworkCVECorrelator
from topology_builder import TopologyBuilder
from mitre_mapper import MITREMapper

# Parse data
parser = EnumerationParser()
parser.download_from_pastebin("https://pastebin.com/XXXXX", "ducknipples")
data = parser.parse()

# Map to MITRE ATT&CK techniques
mitre_mapper = MITREMapper()
mitre_techniques = mitre_mapper.map_enumeration_data({
    "raw_data": data.raw_data,
    "has_system_token": data.token_result.get("success", False)
})
mitre_mapper.generate_report()

# Correlate network-wide CVEs
network_cve_corr = NetworkCVECorrelator()
network_cves = network_cve_corr.correlate_network(data, min_cvss=7.0)
network_cve_corr.generate_network_report(network_cves)

# Generate VLAN diagram
vlan_gen = VLANDiagramGenerator()
vlan_gen.generate(data, ["mermaid", "html"])

# Generate documentation
doc_gen = DocumentationGenerator()
doc_gen.generate(data, ["markdown", "html"])

# Correlate local CVEs
cve_corr = CVECorrelator()
cves = cve_corr.correlate(data, min_cvss=7.0)
cve_corr.generate_report(cves)

# Build topology with MITRE and CVE data
topo_builder = TopologyBuilder()
topo_builder.build(data, 
                  mitre_data={"mitre_techniques": mitre_techniques},
                  cve_data={"network_cves": network_cves},
                  output_formats=["mermaid", "html"])
```

## Output Files

All outputs are saved to `output/` directory:

- `diagrams/vlan_topology.mmd` - Mermaid VLAN diagram
- `diagrams/vlan_topology.html` - Interactive HTML VLAN diagram
- `diagrams/network_topology.mmd` - Mermaid network topology
- `diagrams/network_topology.html` - Interactive HTML network topology
- `docs/system_report.md` - System documentation (Markdown)
- `docs/system_report.html` - System documentation (HTML)
- `docs/network_topology.md` - Network documentation (Markdown)
- `reports/cve_report.md` - Local CVE correlation report
- `reports/critical_cves.md` - Critical CVEs only
- `reports/network_cve_report.md` - Network-wide CVE correlation report
- `reports/mitre_techniques.md` - MITRE ATT&CK technique detection report
- `parsed_data.json` - Parsed enumeration data (JSON with MITRE, CVE, and attack chain data)
- Attack chain data included in `parsed_data.json`:
  - `attack_chains`: CVE-based attack chains (SWORD integration)
  - `techniques`: Matched attack techniques from integrated tools
  - `multi_stage_chains`: Multi-stage attack chains with conditional paths
  - `ml_suggestions`: ML-guided attack chain suggestions (if available)

## Configuration

### NVD API Key (Optional)

For better CVE correlation, set NVD API key:

```python
correlator = CVECorrelator()
correlator.nvd_api_key = "your_nvd_api_key"
```

Get API key from: https://nvd.nist.gov/developers/request-an-api-key

## Dependencies

See `requirements.txt` for full list of Python dependencies.

## License

See project license file.
