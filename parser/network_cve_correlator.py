#!/usr/bin/env python3
"""
Network-Wide CVE Correlator
Correlates CVEs across all discovered network hosts
"""

import json
import requests
from pathlib import Path
from typing import Dict, List, Any, Set
from dataclasses import dataclass
from collections import defaultdict

@dataclass
class NetworkCVE:
    """Network-wide CVE information"""
    cve_id: str
    cvss_score: float
    severity: str
    affected_hosts: List[str]
    affected_software: str
    exploit_available: bool
    description: str

class NetworkCVECorrelator:
    """Correlate CVEs across network hosts"""
    
    def __init__(self, output_dir: str = "output/reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.nvd_api_key = None
    
    def correlate_network(self, data: Dict[str, Any], min_cvss: float = 7.0) -> Dict[str, Any]:
        """Correlate CVEs across all network hosts"""
        network_cves = {}
        
        # Extract all hosts and their software
        hosts = self._extract_network_hosts(data)
        
        # Correlate CVEs for each host
        for host_ip, software_list in hosts.items():
            for software, version in software_list.items():
                cves = self._query_cves(software, version, min_cvss)
                for cve in cves:
                    if cve.cve_id not in network_cves:
                        network_cves[cve.cve_id] = NetworkCVE(
                            cve_id=cve.cve_id,
                            cvss_score=cve.cvss_score,
                            severity=cve.severity,
                            affected_hosts=[],
                            affected_software=software,
                            exploit_available=cve.exploit_available,
                            description=cve.description
                        )
                    if host_ip not in network_cves[cve.cve_id].affected_hosts:
                        network_cves[cve.cve_id].affected_hosts.append(host_ip)
        
        return network_cves
    
    def _extract_network_hosts(self, data: Dict[str, Any]) -> Dict[str, Dict[str, str]]:
        """Extract network hosts and their software from enumeration data"""
        hosts = {}
        
        # Parse raw enumeration data for network hosts
        raw_data = data.get("raw_data", "")
        
        # Extract IP addresses and associated software
        import re
        
        # Find all IP addresses
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = re.findall(ip_pattern, raw_data)
        
        for ip in set(ips):
            if ip not in hosts:
                hosts[ip] = {}
            
            # Try to extract OS version near this IP
            ip_context = self._get_ip_context(raw_data, ip)
            
            # Extract Windows version
            win_match = re.search(r'Windows\s+(\d+\.\d+)', ip_context, re.IGNORECASE)
            if win_match:
                hosts[ip]["Windows"] = win_match.group(1)
            
            # Extract service versions
            if "sql" in ip_context.lower():
                sql_match = re.search(r'SQL\s+Server\s+(\d+\.\d+)', ip_context, re.IGNORECASE)
                if sql_match:
                    hosts[ip]["SQL Server"] = sql_match.group(1)
                else:
                    hosts[ip]["SQL Server"] = "Unknown"
            
            if "iis" in ip_context.lower() or "w3svc" in ip_context.lower():
                iis_match = re.search(r'IIS\s+(\d+\.\d+)', ip_context, re.IGNORECASE)
                if iis_match:
                    hosts[ip]["IIS"] = iis_match.group(1)
                else:
                    hosts[ip]["IIS"] = "Unknown"
        
        # Add local host from system_info
        system_info = data.get("system_info", {})
        if system_info.get("computer_name"):
            hosts["LOCAL"] = {}
            os_version = system_info.get("os_version", "")
            if os_version:
                hosts["LOCAL"]["Windows"] = os_version
        
        return hosts
    
    def _get_ip_context(self, text: str, ip: str, context_chars: int = 500) -> str:
        """Get context around an IP address in text"""
        index = text.find(ip)
        if index == -1:
            return ""
        start = max(0, index - context_chars)
        end = min(len(text), index + len(ip) + context_chars)
        return text[start:end]
    
    def _query_cves(self, software: str, version: str, min_cvss: float) -> List[Any]:
        """Query CVEs for software (reuse from cve_correlator)"""
        from cve_correlator import CVECorrelator, CVE
        
        correlator = CVECorrelator()
        if self.nvd_api_key:
            correlator.nvd_api_key = self.nvd_api_key
        
        # Create minimal data structure
        sample_data = {
            "system_info": {"os_version": version if "Windows" in software else ""},
            "services": []
        }
        
        cves = correlator.correlate(sample_data, min_cvss)
        return cves
    
    def generate_network_report(self, network_cves: Dict[str, NetworkCVE]) -> str:
        """Generate network-wide CVE report"""
        output_file = self.output_dir / "network_cve_report.md"
        
        # Sort by CVSS score
        sorted_cves = sorted(network_cves.values(), key=lambda x: x.cvss_score, reverse=True)
        
        # Group by severity
        critical = [cve for cve in sorted_cves if cve.cvss_score >= 9.0]
        high = [cve for cve in sorted_cves if 7.0 <= cve.cvss_score < 9.0]
        
        md = f"""# Network-Wide CVE Correlation Report

**Total CVEs Found:** {len(network_cves)}
**Critical CVEs (CVSS 9.0+):** {len(critical)}
**High CVEs (CVSS 7.0-8.9):** {len(high)}
**Total Affected Hosts:** {len(set(host for cve in network_cves.values() for host in cve.affected_hosts))}

## Critical Vulnerabilities (CVSS 9.0+)

"""
        
        for cve in critical:
            md += f"""### {cve.cve_id}

- **CVSS Score:** {cve.cvss_score}
- **Severity:** {cve.severity}
- **Affected Software:** {cve.affected_software}
- **Affected Hosts:** {len(cve.affected_hosts)}
  {chr(10).join(f'  - {host}' for host in cve.affected_hosts[:10])}
- **Exploit Available:** {'Yes' if cve.exploit_available else 'No'}
- **Description:** {cve.description[:200]}...

"""
        
        md += "## High Vulnerabilities (CVSS 7.0-8.9)\n\n"
        
        for cve in high[:30]:
            md += f"- **{cve.cve_id}** ({cve.cvss_score}): {cve.affected_software} - Affects {len(cve.affected_hosts)} host(s)\n"
        
        md += "\n## Network-Wide Impact Analysis\n\n"
        
        # Hosts with most CVEs
        host_cve_count = defaultdict(int)
        for cve in network_cves.values():
            for host in cve.affected_hosts:
                host_cve_count[host] += 1
        
        md += "### Hosts with Most CVEs\n\n"
        for host, count in sorted(host_cve_count.items(), key=lambda x: x[1], reverse=True)[:10]:
            md += f"- **{host}**: {count} CVEs\n"
        
        # Most common CVEs across network
        md += "\n### Most Common CVEs Across Network\n\n"
        for cve in sorted_cves[:10]:
            md += f"- **{cve.cve_id}**: Affects {len(cve.affected_hosts)} host(s) - {cve.affected_software}\n"
        
        with open(output_file, 'w') as f:
            f.write(md)
        
        return str(output_file)

if __name__ == "__main__":
    # Test with sample data
    sample_data = {
        "raw_data": "Host 192.168.1.100: Windows 10.0.19045, IIS 10.0. Host 192.168.1.101: Windows 10.0.19045, SQL Server 2019",
        "system_info": {"os_version": "10.0.19045", "computer_name": "LOCAL-PC"}
    }
    
    correlator = NetworkCVECorrelator()
    network_cves = correlator.correlate_network(sample_data, min_cvss=7.0)
    print(f"Found {len(network_cves)} network-wide CVEs")
    
    report = correlator.generate_network_report(network_cves)
    print(f"Report saved to: {report}")
