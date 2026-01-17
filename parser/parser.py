#!/usr/bin/env python3
"""
Main parser for Windows System Enumerator data
Downloads and parses enumeration data from Pastebin
"""

import sys
import re
import json
import requests
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime

# Import attack chain modules
from cve_chain_generator import CVEChainGenerator, AttackChain as CVEAttackChain
from technique_pattern_matcher import TechniquePatternMatcher
from multi_stage_chain_builder import MultiStageChainBuilder, AttackChain as MultiStageAttackChain
from ml_chain_suggester import MLChainSuggester

@dataclass
class SystemInfo:
    """System information"""
    os_version: str = ""
    build_number: str = ""
    computer_name: str = ""
    current_user: str = ""
    architecture: str = ""
    uptime: str = ""

@dataclass
class NetworkInterface:
    """Network interface information"""
    name: str = ""
    description: str = ""
    mac_address: str = ""
    ip_address: str = ""
    subnet_mask: str = ""
    gateway: str = ""
    dhcp_enabled: bool = False

@dataclass
class Process:
    """Process information"""
    pid: int = 0
    name: str = ""
    path: str = ""

@dataclass
class Service:
    """Service information"""
    name: str = ""
    display_name: str = ""
    state: str = ""
    pid: int = 0

@dataclass
class VLANInfo:
    """VLAN information"""
    vlan_id: str = ""
    name: str = ""
    adapter: str = ""
    ip_address: str = ""

@dataclass
class EnumerationData:
    """Complete enumeration data structure"""
    timestamp: str = ""
    system_info: SystemInfo = field(default_factory=SystemInfo)
    network_interfaces: List[NetworkInterface] = field(default_factory=list)
    processes: List[Process] = field(default_factory=list)
    services: List[Service] = field(default_factory=list)
    vlans: List[VLANInfo] = field(default_factory=list)
    token_result: Dict[str, Any] = field(default_factory=dict)
    raw_data: str = ""

class EnumerationParser:
    """Parser for enumeration data"""
    
    def __init__(self):
        self.data = EnumerationData()
    
    def download_from_pastebin(self, url: str, password: str = "ducknipples") -> bool:
        """Download enumeration data from Pastebin URL"""
        try:
            # Extract paste ID from URL
            paste_id_match = re.search(r'pastebin\.com/([a-zA-Z0-9]+)', url)
            if not paste_id_match:
                print(f"Error: Invalid Pastebin URL: {url}")
                return False
            
            paste_id = paste_id_match.group(1)
            
            # Download paste (password-protected)
            response = requests.post(
                "https://pastebin.com/api/api_raw.php",
                data={
                    "api_dev_key": "YOUR_API_KEY_HERE",  # User should set this
                    "api_user_key": "",  # Optional
                    "api_option": "show_paste",
                    "api_paste_key": paste_id,
                    "api_paste_password": password
                },
                timeout=30
            )
            
            if response.status_code == 200:
                self.data.raw_data = response.text
                return True
            else:
                print(f"Error downloading from Pastebin: {response.status_code}")
                print(f"Response: {response.text}")
                return False
                
        except Exception as e:
            print(f"Error downloading from Pastebin: {e}")
            return False
    
    def parse_from_file(self, filepath: str) -> bool:
        """Parse enumeration data from local file"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                self.data.raw_data = f.read()
            return True
        except Exception as e:
            print(f"Error reading file: {e}")
            return False
    
    def parse(self) -> EnumerationData:
        """Parse enumeration data"""
        if not self.data.raw_data:
            print("Error: No data to parse")
            return self.data
        
        # Extract timestamp
        timestamp_match = re.search(r'Generated:\s*(.+)', self.data.raw_data)
        if timestamp_match:
            self.data.timestamp = timestamp_match.group(1).strip()
        
        # Parse system information
        self._parse_system_info()
        
        # Parse network interfaces
        self._parse_network_interfaces()
        
        # Parse processes
        self._parse_processes()
        
        # Parse services
        self._parse_services()
        
        # Parse VLANs
        self._parse_vlans()
        
        # Parse token result
        self._parse_token_result()
        
        return self.data
    
    def _parse_system_info(self):
        """Parse system information section"""
        section_match = re.search(r'=== SYSTEM INFORMATION ===(.*?)===', self.data.raw_data, re.DOTALL)
        if not section_match:
            return
        
        section = section_match.group(1)
        
        # OS Version
        os_match = re.search(r'OS Version:\s*(.+)', section)
        if os_match:
            self.data.system_info.os_version = os_match.group(1).strip()
        
        # Build Number
        build_match = re.search(r'Build Number:\s*(.+)', section)
        if build_match:
            self.data.system_info.build_number = build_match.group(1).strip()
        
        # Computer Name
        comp_match = re.search(r'Computer Name:\s*(.+)', section)
        if comp_match:
            self.data.system_info.computer_name = comp_match.group(1).strip()
        
        # Current User
        user_match = re.search(r'Current User:\s*(.+)', section)
        if user_match:
            self.data.system_info.current_user = user_match.group(1).strip()
        
        # Architecture
        arch_match = re.search(r'Processor Architecture:\s*(.+)', section)
        if arch_match:
            self.data.system_info.architecture = arch_match.group(1).strip()
    
    def _parse_network_interfaces(self):
        """Parse network interfaces section"""
        section_match = re.search(r'=== NETWORK INTERFACES ===(.*?)===', self.data.raw_data, re.DOTALL)
        if not section_match:
            return
        
        section = section_match.group(1)
        
        # Find all adapters
        adapter_blocks = re.split(r'Adapter:\s*', section)[1:]  # Skip first empty
        
        for block in adapter_blocks:
            iface = NetworkInterface()
            
            # Extract adapter name (first line)
            lines = block.split('\n')
            if lines:
                iface.name = lines[0].strip()
            
            # Description
            desc_match = re.search(r'Description:\s*(.+)', block)
            if desc_match:
                iface.description = desc_match.group(1).strip()
            
            # MAC Address
            mac_match = re.search(r'MAC Address:\s*(.+)', block)
            if mac_match:
                iface.mac_address = mac_match.group(1).strip()
            
            # IP Address
            ip_match = re.search(r'IP Address:\s*(.+)', block)
            if ip_match:
                iface.ip_address = ip_match.group(1).strip()
            
            # Subnet Mask
            subnet_match = re.search(r'Subnet Mask:\s*(.+)', block)
            if subnet_match:
                iface.subnet_mask = subnet_match.group(1).strip()
            
            # Gateway
            gateway_match = re.search(r'Gateway:\s*(.+)', block)
            if gateway_match:
                iface.gateway = gateway_match.group(1).strip()
            
            # DHCP
            dhcp_match = re.search(r'DHCP Enabled:\s*(.+)', block)
            if dhcp_match:
                iface.dhcp_enabled = dhcp_match.group(1).strip().lower() == "yes"
            
            if iface.name:
                self.data.network_interfaces.append(iface)
    
    def _parse_processes(self):
        """Parse processes section"""
        section_match = re.search(r'=== PROCESS INFORMATION ===(.*?)===', self.data.raw_data, re.DOTALL)
        if not section_match:
            return
        
        section = section_match.group(1)
        
        # Find all PID entries
        pid_pattern = r'PID:\s*(\d+),\s*Name:\s*(.+)'
        for match in re.finditer(pid_pattern, section):
            proc = Process()
            proc.pid = int(match.group(1))
            proc.name = match.group(2).strip()
            self.data.processes.append(proc)
    
    def _parse_services(self):
        """Parse services section"""
        section_match = re.search(r'=== SERVICE INFORMATION ===(.*?)===', self.data.raw_data, re.DOTALL)
        if not section_match:
            return
        
        section = section_match.group(1)
        
        # Find all service entries
        service_pattern = r'Service:\s*([^,]+),\s*Display:\s*([^,]+),\s*State:\s*([^,]+),\s*PID:\s*(\d+)'
        for match in re.finditer(service_pattern, section):
            svc = Service()
            svc.name = match.group(1).strip()
            svc.display_name = match.group(2).strip()
            svc.state = match.group(3).strip()
            svc.pid = int(match.group(4))
            self.data.services.append(svc)
    
    def _parse_vlans(self):
        """Parse VLAN information"""
        section_match = re.search(r'=== VLAN STRUCTURE ===(.*?)===', self.data.raw_data, re.DOTALL)
        if not section_match:
            return
        
        section = section_match.group(1)
        
        # Find VLAN adapters
        vlan_pattern = r'VLAN Adapter:\s*(.+?)\n\s*IP:\s*(.+)'
        for match in re.finditer(vlan_pattern, section):
            vlan = VLANInfo()
            vlan.adapter = match.group(1).strip()
            vlan.ip_address = match.group(2).strip()
            self.data.vlans.append(vlan)
    
    def _parse_token_result(self):
        """Parse token acquisition result"""
        section_match = re.search(r'=== SYSTEM TOKEN ACQUISITION ===(.*?)===', self.data.raw_data, re.DOTALL)
        if not section_match:
            return
        
        section = section_match.group(1)
        
        self.data.token_result = {
            "success": "SUCCESS" in section,
            "method": "",
            "user_sid": "",
            "error_details": ""
        }
        
        method_match = re.search(r'Method:\s*(.+)', section)
        if method_match:
            self.data.token_result["method"] = method_match.group(1).strip()
        
        sid_match = re.search(r'User SID:\s*(.+)', section)
        if sid_match:
            self.data.token_result["user_sid"] = sid_match.group(1).strip()
        
        error_match = re.search(r'Error Details:\s*(.+)', section)
        if error_match:
            self.data.token_result["error_details"] = error_match.group(1).strip()

def main():
    """Main entry point"""
    if len(sys.argv) < 2:
        print("Usage: python parser.py <pastebin_url> [--password PASSWORD] [--file FILE]")
        print("  --password: Pastebin password (default: ducknipples)")
        print("  --file: Parse from local file instead of URL")
        sys.exit(1)
    
    parser = EnumerationParser()
    
    # Parse arguments
    password = "ducknipples"
    file_path = None
    url = None
    
    i = 1
    while i < len(sys.argv):
        if sys.argv[i] == "--password" and i + 1 < len(sys.argv):
            password = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == "--file" and i + 1 < len(sys.argv):
            file_path = sys.argv[i + 1]
            i += 2
        elif sys.argv[i].startswith("http"):
            url = sys.argv[i]
            i += 1
        else:
            i += 1
    
    # Download or read data
    if file_path:
        if not parser.parse_from_file(file_path):
            sys.exit(1)
    elif url:
        if not parser.download_from_pastebin(url, password):
            sys.exit(1)
    else:
        print("Error: Must provide either URL or --file path")
        sys.exit(1)
    
    # Parse data
    data = parser.parse()
    
    # Map to MITRE ATT&CK techniques
    from mitre_mapper import MitreMapper as MITREMapper
    mitre_mapper = MITREMapper()
    mitre_techniques = mitre_mapper.map_enumeration_data({
        "raw_data": data.raw_data,
        "has_system_token": data.token_result.get("success", False)
    })
    mitre_mapper.generate_report()
    
    # Correlate network-wide CVEs
    from network_cve_correlator import NetworkCVECorrelator
    network_cve_corr = NetworkCVECorrelator()
    network_cves = network_cve_corr.correlate_network({
        "raw_data": data.raw_data,
        "system_info": {
            "os_version": data.system_info.os_version,
            "computer_name": data.system_info.computer_name
        }
    })
    network_cve_corr.generate_network_report(network_cves)
    
    # Phase 2: Attack Chain Suggestion Engine
    print("\nGenerating attack chains...")
    
    # Prepare enumeration data for chain generation
    enum_data_for_chains = {
        "system_info": {
            "os_version": data.system_info.os_version,
            "computer_name": data.system_info.computer_name,
            "current_user": data.system_info.current_user,
            "architecture": data.system_info.architecture
        },
        "network_cves": network_cves,
        "raw_data": data.raw_data,
        "services": [{"name": s.name, "state": s.state} for s in data.services],
        "processes": [{"name": p.name, "pid": p.pid} for p in data.processes]
    }
    
    # Generate CVE-based attack chains
    cve_chain_gen = CVEChainGenerator(enum_data_for_chains)
    cve_chains = cve_chain_gen.generate_chains()
    
    # Match technique patterns
    pattern_matcher = TechniquePatternMatcher()
    techniques = pattern_matcher.match_all_patterns(enum_data_for_chains)
    
    # Build multi-stage chains
    multi_stage_builder = MultiStageChainBuilder(enum_data_for_chains)
    multi_stage_chains = multi_stage_builder.build_chains()
    
    # Optional ML suggestions
    ml_suggester = MLChainSuggester()
    ml_chains = []
    if ml_suggester.is_available():
        context = {
            "objective": "full_compromise",
            "target": data.system_info.computer_name
        }
        ml_chains = ml_suggester.suggest_chains(enum_data_for_chains, context)
    
    # Output JSON
    output = {
        "timestamp": data.timestamp,
        "system_info": {
            "os_version": data.system_info.os_version,
            "build_number": data.system_info.build_number,
            "computer_name": data.system_info.computer_name,
            "current_user": data.system_info.current_user,
            "architecture": data.system_info.architecture
        },
        "network_interfaces": [
            {
                "name": iface.name,
                "description": iface.description,
                "mac_address": iface.mac_address,
                "ip_address": iface.ip_address,
                "subnet_mask": iface.subnet_mask,
                "gateway": iface.gateway,
                "dhcp_enabled": iface.dhcp_enabled
            }
            for iface in data.network_interfaces
        ],
        "processes": [
            {"pid": p.pid, "name": p.name}
            for p in data.processes
        ],
        "services": [
            {"name": s.name, "display_name": s.display_name, "state": s.state, "pid": s.pid}
            for s in data.services
        ],
        "vlans": [
            {"adapter": v.adapter, "ip_address": v.ip_address}
            for v in data.vlans
        ],
        "token_result": data.token_result,
        "mitre_techniques": [
            {
                "technique_id": tech.technique_id,
                "name": tech.name,
                "tactic": tech.tactic,
                "detected": tech.detected,
                "evidence": tech.evidence
            }
            for tech in mitre_techniques
        ],
        "network_cves": {
            cve_id: {
                "cvss_score": cve.cvss_score,
                "severity": cve.severity,
                "affected_hosts": cve.affected_hosts,
                "affected_software": cve.affected_software,
                "exploit_available": cve.exploit_available
            }
            for cve_id, cve in network_cves.items()
        },
        "attack_chains": [
            {
                "chain_id": chain.chain_id,
                "name": chain.name,
                "description": chain.description,
                "steps": chain.steps,
                "success_probability": chain.success_probability,
                "compatibility_score": chain.compatibility_score if hasattr(chain, 'compatibility_score') else 0.0,
                "source_tool": chain.source_tool if hasattr(chain, 'source_tool') else "ENUMERATOR",
                "cves": chain.cves if hasattr(chain, 'cves') else []
            }
            for chain in cve_chains
        ],
        "techniques": [
            {
                "technique_id": tech.technique_id,
                "name": tech.name,
                "tool_source": tech.tool_source,
                "description": tech.description,
                "mitre_id": tech.mitre_id,
                "confidence": tech.confidence,
                "evidence": tech.evidence
            }
            for tech in techniques
        ],
        "multi_stage_chains": [
            {
                "chain_id": chain.chain_id,
                "name": chain.name,
                "description": chain.description,
                "stages": {
                    stage.value: [
                        {
                            "step_id": step.step_id,
                            "technique": step.technique,
                            "description": step.description,
                            "success_probability": step.success_probability
                        }
                        for step in steps
                    ]
                    for stage, steps in chain.stages.items()
                },
                "overall_success_probability": chain.overall_success_probability
            }
            for chain in multi_stage_chains
        ],
        "ml_suggestions": [
            {
                "chain_id": chain.chain_id,
                "name": chain.name,
                "description": chain.description,
                "steps": chain.steps,
                "success_probability": chain.success_probability,
                "confidence": chain.confidence
            }
            for chain in ml_chains
        ] if ml_chains else None
    }
    
    print(json.dumps(output, indent=2))
    
    # Save to file
    output_file = Path("output") / "parsed_data.json"
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, 'w') as f:
        json.dump(output, f, indent=2)
    
    print(f"\nParsed data saved to: {output_file}")
    
    # Generate additional outputs
    print("\nGenerating additional outputs...")
    
    # Generate VLAN diagram
    from vlan_diagram import VLANDiagramGenerator
    vlan_gen = VLANDiagramGenerator()
    vlan_gen.generate(output, ["mermaid", "html"])
    
    # Generate documentation
    from doc_generator import DocumentationGenerator
    doc_gen = DocumentationGenerator()
    doc_gen.generate(output, ["markdown", "html"])
    
    # Build topology with MITRE, CVE, and attack chain data
    from topology_builder import TopologyBuilder
    topo_builder = TopologyBuilder()
    topo_builder.build(output,
                      mitre_data={"mitre_techniques": output.get("mitre_techniques", [])},
                      cve_data={"network_cves": output.get("network_cves", {})},
                      attack_chains=output.get("attack_chains", []),
                      output_formats=["mermaid", "html"])
    
    print("\nAll outputs generated successfully!")
    print(f"Generated {len(cve_chains)} CVE-based attack chains")
    print(f"Matched {len(techniques)} attack techniques")
    print(f"Built {len(multi_stage_chains)} multi-stage attack chains")
    if ml_chains:
        print(f"Generated {len(ml_chains)} ML-suggested attack chains")

if __name__ == "__main__":
    main()
