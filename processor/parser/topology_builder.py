#!/usr/bin/env python3
"""
Network Topology Builder
Builds comprehensive network topology visualizations
"""

import json
from pathlib import Path
from typing import Dict, List, Any, Optional

class TopologyBuilder:
    """Build network topology visualizations with MITRE ATT&CK and CVE data"""
    
    def __init__(self, output_dir: str = "output/diagrams"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def build(self, data: Dict[str, Any], mitre_data: Dict[str, Any] = None, cve_data: Dict[str, Any] = None, attack_chains: List[Dict[str, Any]] = None, output_formats: List[str] = ["mermaid", "html"]) -> bool:
        """Build network topology with attack chain visualization"""
        interfaces = data.get("network_interfaces", [])
        vlans = data.get("vlans", [])
        processes = data.get("processes", [])
        services = data.get("services", [])
        
        if not interfaces:
            print("No network interface data found")
            return False
        
        # Build topology structure
        topology = self._build_topology_structure(interfaces, vlans, processes, services)
        
        # Enhance with MITRE and CVE data
        if mitre_data:
            topology["mitre_techniques"] = mitre_data.get("mitre_techniques", [])
        
        if cve_data:
            topology["network_cves"] = cve_data.get("network_cves", {})
        
        # Add attack chains for visualization
        if attack_chains:
            topology["attack_chains"] = attack_chains
        
        # Generate visualizations
        if "mermaid" in output_formats:
            self._generate_mermaid_topology(topology, mitre_data, cve_data, attack_chains)
        
        if "html" in output_formats:
            self._generate_html_topology(topology, mitre_data, cve_data, attack_chains)
        
        return True
    
    def _build_topology_structure(self, interfaces: List[Dict], vlans: List[Dict], 
                                  processes: List[Dict], services: List[Dict]) -> Dict[str, Any]:
        """Build topology structure from enumeration data"""
        topology = {
            "nodes": [],
            "edges": [],
            "vlans": [],
            "services": []
        }
        
        # Add network interface nodes
        for iface in interfaces:
            node = {
                "id": iface.get("name", "").replace(" ", "_"),
                "label": f"{iface.get('description', iface.get('name', 'Unknown'))}\\n{iface.get('ip_address', 'N/A')}",
                "type": "interface",
                "ip": iface.get("ip_address", ""),
                "mac": iface.get("mac_address", "")
            }
            topology["nodes"].append(node)
        
        # Add VLAN nodes
        for vlan in vlans:
            vlan_node = {
                "id": f"VLAN_{vlan.get('vlan_id', 'Unknown')}",
                "label": f"VLAN {vlan.get('vlan_id', 'Unknown')}\\n{vlan.get('name', '')}",
                "type": "vlan",
                "vlan_id": vlan.get("vlan_id", "")
            }
            topology["vlans"].append(vlan_node)
            
            # Connect VLAN to adapter
            adapter_id = vlan.get("adapter", "").replace(" ", "_")
            topology["edges"].append({
                "from": vlan_node["id"],
                "to": adapter_id,
                "type": "vlan_connection"
            })
        
        # Add service nodes
        for svc in services:
            if svc.get("state", "").lower() == "running":
                service_node = {
                    "id": f"Service_{svc.get('name', '').replace(' ', '_')}",
                    "label": f"{svc.get('display_name', svc.get('name', 'Unknown'))}\\nPID: {svc.get('pid', 'N/A')}",
                    "type": "service",
                    "pid": svc.get("pid", 0)
                }
                topology["services"].append(service_node)
        
        return topology
    
    def _generate_mermaid_topology(self, topology: Dict[str, Any], mitre_data: Dict[str, Any] = None, cve_data: Dict[str, Any] = None, attack_chains: List[Dict[str, Any]] = None):
        """Generate Mermaid topology diagram with MITRE, CVE, and attack chain annotations"""
        output_file = self.output_dir / "network_topology.mmd"
        
        lines = ["graph TD"]
        
        # Add nodes
        for node in topology["nodes"]:
            node_id = node["id"]
            label = node["label"].replace("\\n", "<br/>")
            lines.append(f'    {node_id}["{label}"]')
        
        for vlan in topology["vlans"]:
            vlan_id = vlan["id"]
            label = vlan["label"].replace("\\n", "<br/>")
            lines.append(f'    {vlan_id}["{label}"]')
        
        for service in topology["services"]:
            service_id = service["id"]
            label = service["label"].replace("\\n", "<br/>")
            lines.append(f'    {service_id}["{label}"]')
        
        # Add edges
        for edge in topology["edges"]:
            lines.append(f'    {edge["from"]} --> {edge["to"]}')
        
        # Connect services to interfaces based on process associations
        for service in topology["services"]:
            # Find interface that might host this service (based on PID or name matching)
            for node in topology["nodes"]:
                # Connect service to primary interface
                if node["type"] == "interface":
                    lines.append(f'    {service["id"]} -.-> {node["id"]}')
                    break
        
        # Add MITRE technique annotations
        if mitre_data and "mitre_techniques" in mitre_data:
            lines.append("\n    %% MITRE ATT&CK Techniques")
            for tech in mitre_data["mitre_techniques"][:10]:  # Limit to 10 for readability
                tech_id = tech.get("technique_id", "").replace(".", "_")
                tech_name = tech.get("name", "")[:30]
                lines.append(f'    MITRE_{tech_id}["{tech_id}: {tech_name}"]')
                lines.append(f'    MITRE_{tech_id} -.-> {topology["nodes"][0]["id"] if topology["nodes"] else "N1"}')
        
        # Add CVE annotations
        if cve_data and "network_cves" in cve_data:
            lines.append("\n    %% Critical CVEs")
            critical_cves = [cve for cve_id, cve in cve_data["network_cves"].items() if cve.get("cvss_score", 0) >= 9.0]
            for cve in critical_cves[:5]:  # Limit to 5 critical CVEs
                cve_id = cve.get("cve_id", "CVE").replace("-", "_")
                lines.append(f'    CVE_{cve_id}["{cve_id}<br/>CVSS: {cve.get("cvss_score", 0)}"]')
                lines.append(f'    CVE_{cve_id} -.-> {topology["nodes"][0]["id"] if topology["nodes"] else "N1"}')
        
        # Add attack chain paths
        if attack_chains:
            lines.append("\n    %% Attack Chain Paths")
            for i, chain in enumerate(attack_chains[:5]):  # Limit to 5 chains
                chain_id = f"Chain_{i+1}"
                chain_name = chain.get("name", f"Chain {i+1}")[:40]
                lines.append(f'    {chain_id}["{chain_name}<br/>Success: {chain.get("success_probability", 0)*100:.1f}%"]')
                # Connect chain to primary target node
                if topology["nodes"]:
                    lines.append(f'    {chain_id} -.->|"Attack Path"| {topology["nodes"][0]["id"]}')
        
        with open(output_file, 'w') as f:
            f.write('\n'.join(lines))
        
        print(f"Mermaid topology saved to: {output_file}")
    
    def _generate_html_topology(self, topology: Dict[str, Any], mitre_data: Dict[str, Any] = None, cve_data: Dict[str, Any] = None, attack_chains: List[Dict[str, Any]] = None):
        """Generate interactive HTML topology with MITRE, CVE, and attack chain overlays"""
        output_file = self.output_dir / "network_topology.html"
        
        # Build Mermaid diagram content
        mermaid_content = "graph TD\n"
        
        for node in topology["nodes"]:
            node_id = node["id"]
            label = node["label"].replace("\\n", "<br/>")
            mermaid_content += f'    {node_id}["{label}"]\n'
        
        for vlan in topology["vlans"]:
            vlan_id = vlan["id"]
            label = vlan["label"].replace("\\n", "<br/>")
            mermaid_content += f'    {vlan_id}["{label}"]\n'
        
        for edge in topology["edges"]:
            mermaid_content += f'    {edge["from"]} --> {edge["to"]}\n'
        
        # Add attack chain paths to Mermaid
        if attack_chains:
            for i, chain in enumerate(attack_chains[:5]):
                chain_id = f"Chain_{i+1}"
                chain_name = chain.get("name", f"Chain {i+1}")[:40]
                mermaid_content += f'    {chain_id}["{chain_name}<br/>Success: {chain.get("success_probability", 0)*100:.1f}%"]\n'
                if topology["nodes"]:
                    mermaid_content += f'    {chain_id} -.->|"Attack Path"| {topology["nodes"][0]["id"]}\n'
        
        # Build MITRE and CVE sections
        mitre_section = ""
        if mitre_data and "mitre_techniques" in mitre_data:
            mitre_section = f"""
        <div class="info">
            <h2>MITRE ATT&CK Techniques Detected</h2>
            <ul>
"""
            for tech in mitre_data["mitre_techniques"][:15]:
                mitre_section += f"                <li><strong>{tech.get('technique_id', 'N/A')}</strong>: {tech.get('name', 'N/A')} ({tech.get('tactic', 'N/A')})</li>\n"
            mitre_section += "            </ul>\n        </div>"
        
        cve_section = ""
        if cve_data and "network_cves" in cve_data:
            critical_cves = [cve for cve_id, cve in cve_data["network_cves"].items() if cve.get("cvss_score", 0) >= 9.0]
            cve_section = f"""
        <div class="info">
            <h2>Critical Network CVEs (CVSS 9.0+)</h2>
            <ul>
"""
            for cve_id, cve in list(cve_data["network_cves"].items())[:10]:
                if cve.get("cvss_score", 0) >= 9.0:
                    cve_section += f"                <li><strong>{cve_id}</strong>: CVSS {cve.get('cvss_score', 0)} - {cve.get('affected_software', 'N/A')} - Affects {len(cve.get('affected_hosts', []))} host(s)</li>\n"
            cve_section += "            </ul>\n        </div>"
        
        # Build attack chain section
        attack_chain_section = ""
        if attack_chains:
            attack_chain_section = f"""
        <div class="info">
            <h2>Attack Chains</h2>
            <ul>
"""
            for chain in attack_chains[:10]:
                chain_name = chain.get("name", "Unknown Chain")
                success_prob = chain.get("success_probability", 0) * 100
                steps_count = len(chain.get("steps", []))
                attack_chain_section += f"                <li><strong>{chain_name}</strong>: {success_prob:.1f}% success probability, {steps_count} steps</li>\n"
            attack_chain_section += "            </ul>\n        </div>"
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Network Topology with MITRE ATT&CK & CVEs</title>
    <script src="https://cdn.jsdelivr.net/npm/mermaid/dist/mermaid.min.js"></script>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #1e1e1e; color: #fff; }}
        .container {{ max-width: 1600px; margin: 0 auto; }}
        h1 {{ color: #4CAF50; }}
        h2 {{ color: #2196F3; }}
        .mermaid {{ background: #2d2d2d; padding: 20px; border-radius: 8px; }}
        .info {{ background: #2d2d2d; padding: 15px; border-radius: 5px; margin-top: 20px; }}
        .info ul {{ margin-left: 20px; }}
        .info li {{ margin: 5px 0; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Network Topology Diagram</h1>
        <div class="mermaid">
{mermaid_content}
        </div>
        <div class="info">
            <h2>Topology Information</h2>
            <p><strong>Network Interfaces:</strong> {len(topology['nodes'])}</p>
            <p><strong>VLANs:</strong> {len(topology['vlans'])}</p>
            <p><strong>Services:</strong> {len(topology['services'])}</p>
            <p><strong>Connections:</strong> {len(topology['edges'])}</p>
        </div>
{mitre_section}
{cve_section}
{attack_chain_section}
    </div>
    <script>
        mermaid.initialize({{ startOnLoad: true, theme: 'dark' }});
    </script>
</body>
</html>"""
        
        with open(output_file, 'w') as f:
            f.write(html)
        
        print(f"HTML topology saved to: {output_file}")

if __name__ == "__main__":
    # Test with sample data
    sample_data = {
        "network_interfaces": [
            {"name": "eth0", "description": "Ethernet", "ip_address": "192.168.1.100", "mac_address": "00:11:22:33:44:55"},
            {"name": "eth1", "description": "Wireless", "ip_address": "192.168.1.101", "mac_address": "00:11:22:33:44:56"}
        ],
        "vlans": [
            {"vlan_id": "10", "name": "Management", "adapter": "eth0", "ip_address": "192.168.1.1"}
        ],
        "services": [
            {"name": "WinRM", "display_name": "Windows Remote Management", "state": "Running", "pid": 1234}
        ],
        "processes": []
    }
    
    builder = TopologyBuilder()
    builder.build(sample_data, ["mermaid", "html"])
