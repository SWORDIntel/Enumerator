#!/usr/bin/env python3
"""
Documentation Generator
Generates easy-to-review documentation in Markdown and HTML formats
"""

import json
from pathlib import Path
from typing import Dict, List, Any
from datetime import datetime
from jinja2 import Template

class DocumentationGenerator:
    """Generate documentation from enumeration data"""
    
    def __init__(self, output_dir: str = "output/docs"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate(self, data: Dict[str, Any], formats: List[str] = ["markdown", "html"]) -> bool:
        """Generate documentation"""
        # System report
        if "markdown" in formats:
            self._generate_system_report_md(data)
        if "html" in formats:
            self._generate_system_report_html(data)
        
        # Network topology report
        if "markdown" in formats:
            self._generate_network_report_md(data)
        if "html" in formats:
            self._generate_network_report_html(data)
        
        # Per-host reports
        self._generate_host_reports(data, formats)
        
        return True
    
    def _generate_system_report_md(self, data: Dict[str, Any]):
        """Generate system report in Markdown"""
        output_file = self.output_dir / "system_report.md"
        
        sys_info = data.get("system_info", {})
        token_result = data.get("token_result", {})
        processes = data.get("processes", [])
        services = data.get("services", [])
        
        md = f"""# System Enumeration Report

**Generated:** {data.get('timestamp', 'Unknown')}

## Executive Summary

- **Computer Name:** {sys_info.get('computer_name', 'Unknown')}
- **OS Version:** {sys_info.get('os_version', 'Unknown')}
- **Build Number:** {sys_info.get('build_number', 'Unknown')}
- **Architecture:** {sys_info.get('architecture', 'Unknown')}
- **Current User:** {sys_info.get('current_user', 'Unknown')}
- **SYSTEM Token:** {'Acquired' if token_result.get('success') else 'Not Acquired'}

## System Information

### Operating System
- **Version:** {sys_info.get('os_version', 'Unknown')}
- **Build:** {sys_info.get('build_number', 'Unknown')}
- **Architecture:** {sys_info.get('architecture', 'Unknown')}

### Hardware
- System architecture and hardware details from enumeration

## Running Processes

Total Processes: {len(processes)}

"""
        
        # Add top 20 processes
        for proc in processes[:20]:
            md += f"- **PID {proc.get('pid', 'N/A')}:** {proc.get('name', 'Unknown')}\n"
        
        md += f"""
## Services

Total Services: {len(services)}

"""
        
        # Add services
        for svc in services[:30]:
            md += f"- **{svc.get('name', 'Unknown')}** ({svc.get('display_name', 'N/A')}): {svc.get('state', 'Unknown')} (PID: {svc.get('pid', 'N/A')})\n"
        
        md += """
## Security Assessment

### Privilege Status
"""
        
        if token_result.get('success'):
            md += f"- **SYSTEM Token:** Acquired via {token_result.get('method', 'Unknown')}\n"
            md += f"- **User SID:** {token_result.get('user_sid', 'N/A')}\n"
        else:
            md += f"- **SYSTEM Token:** Not acquired\n"
            md += f"- **Error:** {token_result.get('error_details', 'N/A')}\n"
        
        with open(output_file, 'w') as f:
            f.write(md)
        
        print(f"System report (Markdown) saved to: {output_file}")
    
    def _generate_system_report_html(self, data: Dict[str, Any]):
        """Generate system report in HTML"""
        output_file = self.output_dir / "system_report.html"
        
        # Read markdown and convert to HTML
        md_file = self.output_dir / "system_report.md"
        if md_file.exists():
            with open(md_file, 'r') as f:
                md_content = f.read()
            
            # Simple markdown to HTML conversion
            html = f"""<!DOCTYPE html>
<html>
<head>
    <title>System Enumeration Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #1e1e1e; color: #fff; line-height: 1.6; }}
        h1 {{ color: #4CAF50; }}
        h2 {{ color: #2196F3; margin-top: 30px; }}
        h3 {{ color: #FF9800; }}
        code {{ background: #2d2d2d; padding: 2px 6px; border-radius: 3px; }}
        pre {{ background: #2d2d2d; padding: 15px; border-radius: 5px; overflow-x: auto; }}
        ul, ol {{ margin-left: 20px; }}
    </style>
</head>
<body>
{self._md_to_html(md_content)}
</body>
</html>"""
            
            with open(output_file, 'w') as f:
                f.write(html)
            
            print(f"System report (HTML) saved to: {output_file}")
    
    def _generate_network_report_md(self, data: Dict[str, Any]):
        """Generate network report in Markdown"""
        output_file = self.output_dir / "network_topology.md"
        
        interfaces = data.get("network_interfaces", [])
        vlans = data.get("vlans", [])
        
        md = f"""# Network Topology Report

**Generated:** {data.get('timestamp', 'Unknown')}

## Network Interfaces

Total Interfaces: {len(interfaces)}

"""
        
        for iface in interfaces:
            md += f"""### {iface.get('description', iface.get('name', 'Unknown'))}

- **Name:** {iface.get('name', 'N/A')}
- **MAC Address:** {iface.get('mac_address', 'N/A')}
- **IP Address:** {iface.get('ip_address', 'N/A')}
- **Subnet Mask:** {iface.get('subnet_mask', 'N/A')}
- **Gateway:** {iface.get('gateway', 'N/A')}
- **DHCP:** {'Enabled' if iface.get('dhcp_enabled') else 'Disabled'}

"""
        
        if vlans:
            md += "## VLAN Structure\n\n"
            for vlan in vlans:
                md += f"- **VLAN {vlan.get('vlan_id', 'Unknown')}:** {vlan.get('adapter', 'N/A')} - {vlan.get('ip_address', 'N/A')}\n"
        
        with open(output_file, 'w') as f:
            f.write(md)
        
        print(f"Network report (Markdown) saved to: {output_file}")
    
    def _generate_network_report_html(self, data: Dict[str, Any]):
        """Generate network report in HTML"""
        md_file = self.output_dir / "network_topology.md"
        if md_file.exists():
            with open(md_file, 'r', encoding='utf-8') as f:
                md_content = f.read()
            
            html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Network Topology Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #1e1e1e; color: #fff; line-height: 1.6; }}
        h1 {{ color: #4CAF50; }}
        h2 {{ color: #2196F3; }}
        h3 {{ color: #FF9800; }}
    </style>
</head>
<body>
{self._md_to_html(md_content)}
</body>
</html>"""
            
            output_file = self.output_dir / "network_topology.html"
            with open(output_file, 'w') as f:
                f.write(html)
            
            print(f"Network report (HTML) saved to: {output_file}")
    
    def _generate_host_reports(self, data: Dict[str, Any], formats: List[str]):
        """Generate per-host reports"""
        # Extract host information from network interfaces
        interfaces = data.get("network_interfaces", [])
        
        for iface in interfaces:
            ip = iface.get("ip_address", "")
            if ip and ip != "0.0.0.0":
                host_file = self.output_dir / f"host_{ip.replace('.', '_')}.md"
                with open(host_file, 'w') as f:
                    f.write(f"# Host Report: {ip}\n\n")
                    f.write(f"**Interface:** {iface.get('description', 'Unknown')}\n")
                    f.write(f"**MAC Address:** {iface.get('mac_address', 'N/A')}\n")
                    f.write(f"**IP Address:** {ip}\n")
                    f.write(f"**Subnet Mask:** {iface.get('subnet_mask', 'N/A')}\n")
                    f.write(f"**Gateway:** {iface.get('gateway', 'N/A')}\n")
                    f.write(f"**DHCP:** {'Enabled' if iface.get('dhcp_enabled') else 'Disabled'}\n")
                
                if "html" in formats:
                    html_file = self.output_dir / f"host_{ip.replace('.', '_')}.html"
                    with open(host_file, 'r') as f:
                        md_content = f.read()
                    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Host Report: {ip}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #1e1e1e; color: #fff; }}
        h1 {{ color: #4CAF50; }}
    </style>
</head>
<body>
{self._md_to_html(md_content)}
</body>
</html>"""
                    with open(html_file, 'w') as f:
                        f.write(html)
    
    def _md_to_html(self, md: str) -> str:
        """Simple markdown to HTML converter"""
        html = md
        html = html.replace('# ', '<h1>').replace('\n# ', '</h1>\n<h1>')
        html = html.replace('## ', '<h2>').replace('\n## ', '</h2>\n<h2>')
        html = html.replace('### ', '<h3>').replace('\n### ', '</h3>\n<h3>')
        html = html.replace('\n- ', '\n<li>')
        html = html.replace('**', '<strong>').replace('**', '</strong>')
        html = html.replace('\n\n', '</p><p>')
        return f'<p>{html}</p>'

if __name__ == "__main__":
    # Test with sample data
    sample_data = {
        "timestamp": datetime.now().isoformat(),
        "system_info": {
            "os_version": "10.0.19045",
            "build_number": "19045",
            "computer_name": "TEST-PC",
            "current_user": "Administrator",
            "architecture": "x64"
        },
        "token_result": {"success": True, "method": "Windows API"},
        "processes": [{"pid": 1234, "name": "explorer.exe"}],
        "services": [{"name": "WinRM", "display_name": "Windows Remote Management", "state": "Running", "pid": 5678}],
        "network_interfaces": [
            {"name": "eth0", "description": "Ethernet", "ip_address": "192.168.1.100", "mac_address": "00:11:22:33:44:55"}
        ],
        "vlans": []
    }
    
    generator = DocumentationGenerator()
    generator.generate(sample_data)
