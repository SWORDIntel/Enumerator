#!/usr/bin/env python3
"""
VLAN Diagram Generator
Generates VLAN topology diagrams in multiple formats
"""

import json
from pathlib import Path
from typing import Dict, List, Any
from dataclasses import dataclass

@dataclass
class VLANNode:
    """VLAN node for diagram"""
    vlan_id: str
    name: str
    adapters: List[str]
    ip_addresses: List[str]

class VLANDiagramGenerator:
    """Generate VLAN diagrams"""
    
    def __init__(self, output_dir: str = "output/diagrams"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate(self, data: Dict[str, Any], output_formats: List[str] = ["mermaid", "html"]) -> bool:
        """Generate VLAN diagrams from parsed data"""
        vlans = data.get("vlans", [])
        network_interfaces = data.get("network_interfaces", [])
        
        if not vlans and not network_interfaces:
            print("No VLAN or network interface data found")
            return False
        
        # Build VLAN structure
        vlan_nodes = self._build_vlan_structure(vlans, network_interfaces)
        
        # Generate diagrams
        if "mermaid" in output_formats:
            self._generate_mermaid(vlan_nodes, network_interfaces)
        
        if "html" in output_formats:
            self._generate_html(vlan_nodes, network_interfaces)
        
        if "graphviz" in output_formats:
            self._generate_graphviz(vlan_nodes, network_interfaces)
        
        return True
    
    def _build_vlan_structure(self, vlans: List[Dict], interfaces: List[Dict]) -> List[VLANNode]:
        """Build VLAN node structure"""
        vlan_nodes = []
        
        # Group interfaces by VLAN
        vlan_map = {}
        for vlan in vlans:
            vlan_id = vlan.get("vlan_id", "Unknown")
            if vlan_id not in vlan_map:
                vlan_map[vlan_id] = VLANNode(
                    vlan_id=vlan_id,
                    name=vlan.get("name", f"VLAN {vlan_id}"),
                    adapters=[],
                    ip_addresses=[]
                )
            vlan_map[vlan_id].adapters.append(vlan.get("adapter", ""))
            vlan_map[vlan_id].ip_addresses.append(vlan.get("ip_address", ""))
        
        # Add interfaces that might be VLAN-related
        for interface in interfaces:
            desc = interface.get("description", "").upper()
            if "VLAN" in desc:
                # Extract VLAN ID from description
                vlan_id = "Unknown"
                import re
                vlan_match = re.search(r'VLAN\s*(\d+)', desc)
                if vlan_match:
                    vlan_id = vlan_match.group(1)
                
                if vlan_id not in vlan_map:
                    vlan_map[vlan_id] = VLANNode(
                        vlan_id=vlan_id,
                        name=f"VLAN {vlan_id}",
                        adapters=[],
                        ip_addresses=[]
                    )
                vlan_map[vlan_id].adapters.append(interface.get("name", ""))
                vlan_map[vlan_id].ip_addresses.append(interface.get("ip_address", ""))
        
        return list(vlan_map.values())
    
    def _generate_mermaid(self, vlan_nodes: List[VLANNode], interfaces: List[Dict]):
        """Generate Mermaid diagram"""
        output_file = self.output_dir / "vlan_topology.mmd"
        
        lines = ["graph TD"]
        
        # Add VLAN nodes
        for vlan in vlan_nodes:
            node_id = f"VLAN{vlan.vlan_id}".replace(" ", "_")
            label = f"VLAN {vlan.vlan_id}"
            if vlan.name:
                label += f"\\n{vlan.name}"
            lines.append(f'    {node_id}["{label}"]')
        
        # Add interface nodes
        for interface in interfaces:
            iface_id = interface.get("name", "").replace(" ", "_").replace("-", "_")
            if iface_id:
                label = f"{interface.get('description', iface_id)}\\n{interface.get('ip_address', '')}"
                lines.append(f'    {iface_id}["{label}"]')
        
        # Add connections
        for vlan in vlan_nodes:
            vlan_id = f"VLAN{vlan.vlan_id}".replace(" ", "_")
            for adapter in vlan.adapters:
                adapter_id = adapter.replace(" ", "_").replace("-", "_")
                if adapter_id:
                    lines.append(f'    {vlan_id} --> {adapter_id}')
        
        with open(output_file, 'w') as f:
            f.write('\n'.join(lines))
        
        print(f"Mermaid diagram saved to: {output_file}")
    
    def _generate_html(self, vlan_nodes: List[VLANNode], interfaces: List[Dict]):
        """Generate interactive HTML diagram"""
        output_file = self.output_dir / "vlan_topology.html"
        
        html = """<!DOCTYPE html>
<html>
<head>
    <title>VLAN Topology</title>
    <script src="https://cdn.jsdelivr.net/npm/mermaid/dist/mermaid.min.js"></script>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #1e1e1e; color: #fff; }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 { color: #4CAF50; }
        .mermaid { background: #2d2d2d; padding: 20px; border-radius: 8px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>VLAN Topology Diagram</h1>
        <div class="mermaid">
graph TD
"""
        
        # Add nodes and connections (same as Mermaid)
        for vlan in vlan_nodes:
            node_id = f"VLAN{vlan.vlan_id}".replace(" ", "_")
            label = f"VLAN {vlan.vlan_id}"
            if vlan.name:
                label += f"<br/>{vlan.name}"
            html += f'    {node_id}["{label}"]\n'
        
        for interface in interfaces:
            iface_id = interface.get("name", "").replace(" ", "_").replace("-", "_")
            if iface_id:
                label = f"{interface.get('description', iface_id)}<br/>{interface.get('ip_address', '')}"
                html += f'    {iface_id}["{label}"]\n'
        
        for vlan in vlan_nodes:
            vlan_id = f"VLAN{vlan.vlan_id}".replace(" ", "_")
            for adapter in vlan.adapters:
                adapter_id = adapter.replace(" ", "_").replace("-", "_")
                if adapter_id:
                    html += f'    {vlan_id} --> {adapter_id}\n'
        
        html += """        </div>
    </div>
    <script>
        mermaid.initialize({ startOnLoad: true, theme: 'dark' });
    </script>
</body>
</html>"""
        
        with open(output_file, 'w') as f:
            f.write(html)
        
        print(f"HTML diagram saved to: {output_file}")
    
    def _generate_graphviz(self, vlan_nodes: List[VLANNode], interfaces: List[Dict]):
        """Generate Graphviz DOT format"""
        try:
            import graphviz
        except ImportError:
            print("Graphviz not available, skipping Graphviz diagram")
            return
        
        output_file = self.output_dir / "vlan_topology.dot"
        
        dot = graphviz.Digraph(comment='VLAN Topology')
        dot.attr(rankdir='TB')
        dot.attr('node', shape='box', style='rounded')
        
        # Add VLAN nodes
        for vlan in vlan_nodes:
            node_id = f"VLAN{vlan.vlan_id}".replace(" ", "_")
            label = f"VLAN {vlan.vlan_id}\\n{vlan.name}"
            dot.node(node_id, label)
        
        # Add interface nodes
        for interface in interfaces:
            iface_id = interface.get("name", "").replace(" ", "_").replace("-", "_")
            if iface_id:
                label = f"{interface.get('description', iface_id)}\\n{interface.get('ip_address', '')}"
                dot.node(iface_id, label)
        
        # Add connections
        for vlan in vlan_nodes:
            vlan_id = f"VLAN{vlan.vlan_id}".replace(" ", "_")
            for adapter in vlan.adapters:
                adapter_id = adapter.replace(" ", "_").replace("-", "_")
                if adapter_id:
                    dot.edge(vlan_id, adapter_id)
        
        dot.render(str(output_file.with_suffix('')), format='svg', cleanup=True)
        print(f"Graphviz diagram saved to: {output_file}")

if __name__ == "__main__":
    # Test with sample data
    sample_data = {
        "vlans": [
            {"vlan_id": "10", "name": "Management", "adapter": "eth0", "ip_address": "192.168.1.1"},
            {"vlan_id": "20", "name": "Production", "adapter": "eth1", "ip_address": "192.168.2.1"}
        ],
        "network_interfaces": [
            {"name": "eth0", "description": "VLAN 10 Adapter", "ip_address": "192.168.1.1"},
            {"name": "eth1", "description": "VLAN 20 Adapter", "ip_address": "192.168.2.1"}
        ]
    }
    
    generator = VLANDiagramGenerator()
    generator.generate(sample_data, ["mermaid", "html"])
