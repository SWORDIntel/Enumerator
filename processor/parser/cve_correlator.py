#!/usr/bin/env python3
"""
CVE Correlation Engine
Matches software versions/services to high-ranking CVEs
"""

import json
import re
import requests
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime, timedelta

@dataclass
class CVE:
    """CVE information"""
    cve_id: str
    cvss_score: float
    severity: str
    description: str
    affected_software: str
    affected_version: str
    exploit_available: bool
    references: List[str]

class CVECorrelator:
    """Correlate software versions to CVEs"""
    
    def __init__(self, output_dir: str = "output/reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.nvd_api_key = None  # Optional NVD API key
    
    def correlate(self, data: Dict[str, Any], min_cvss: float = 7.0) -> List[CVE]:
        """Correlate enumeration data to CVEs"""
        cves = []
        
        # Extract software versions from data
        software_versions = self._extract_software_versions(data)
        
        # Query CVE databases for each software
        for software, version in software_versions.items():
            software_cves = self._query_cves(software, version, min_cvss)
            cves.extend(software_cves)
        
        # Sort by CVSS score (highest first)
        cves.sort(key=lambda x: x.cvss_score, reverse=True)
        
        return cves
    
    def _extract_software_versions(self, data: Dict[str, Any]) -> Dict[str, str]:
        """Extract software names and versions from enumeration data"""
        software = {}
        
        # Extract OS version
        sys_info = data.get("system_info", {})
        os_version = sys_info.get("os_version", "")
        if os_version:
            # Parse Windows version
            if "10.0" in os_version or "11.0" in os_version:
                software["Windows"] = os_version
        
        # Extract service versions from service enumeration data
        services = data.get("services", [])
        for svc in services:
            name = svc.get("name", "").lower()
            display_name = svc.get("display_name", "").lower()
            if "sql" in name or "sql" in display_name:
                # Attempt to extract version from display name or service name
                version_match = re.search(r'(\d+\.\d+)', svc.get("display_name", ""))
                version = version_match.group(1) if version_match else "Unknown"
                software["SQL Server"] = version
            elif "iis" in name or "w3svc" in name or "iis" in display_name:
                version_match = re.search(r'(\d+\.\d+)', svc.get("display_name", ""))
                version = version_match.group(1) if version_match else "Unknown"
                software["IIS"] = version
            elif "apache" in name or "apache" in display_name:
                version_match = re.search(r'(\d+\.\d+)', svc.get("display_name", ""))
                version = version_match.group(1) if version_match else "Unknown"
                software["Apache"] = version
        
        return software
    
    def _query_cves(self, software: str, version: str, min_cvss: float) -> List[CVE]:
        """Query CVE databases for software"""
        cves = []
        
        # Try NVD API
        nvd_cves = self._query_nvd(software, version, min_cvss)
        cves.extend(nvd_cves)
        
        # Try CVE Details (web scraping or API if available)
        # cve_details_cves = self._query_cve_details(software, version, min_cvss)
        # cves.extend(cve_details_cves)
        
        return cves
    
    def _check_exploit_db(self, cve_id: str) -> bool:
        """Check if exploit is available in Exploit-DB"""
        try:
            # Query Exploit-DB API or search
            url = f"https://www.exploit-db.com/search?q={cve_id}"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                # Check if CVE appears in results
                if cve_id.upper() in response.text.upper():
                    return True
        except Exception:
            pass
        return False
    
    def _query_nvd(self, software: str, version: str, min_cvss: float) -> List[CVE]:
        """Query NVD (National Vulnerability Database) API"""
        cves = []
        
        try:
            # Build search query
            # NVD API v2 endpoint
            url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            
            # Search parameters
            params = {
                "keywordSearch": software,
                "cvssV3Severity": "HIGH",  # Filter for high severity
            }
            
            headers = {}
            if self.nvd_api_key:
                headers["apiKey"] = self.nvd_api_key
            
            response = requests.get(url, params=params, headers=headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                
                # Parse CVE results
                vulnerabilities = data.get("vulnerabilities", [])
                for vuln in vulnerabilities[:50]:  # Limit to 50 results
                    cve_data = vuln.get("cve", {})
                    cve_id = cve_data.get("id", "")
                    
                    # Get CVSS score
                    metrics = cve_data.get("metrics", {})
                    cvss_v3 = metrics.get("cvssMetricV31", [])
                    if not cvss_v3:
                        cvss_v3 = metrics.get("cvssMetricV30", [])
                    if not cvss_v3:
                        cvss_v3 = metrics.get("cvssMetricV2", [])
                    
                    cvss_score = 0.0
                    if cvss_v3:
                        cvss_score = cvss_v3[0].get("cvssData", {}).get("baseScore", 0.0)
                    
                    if cvss_score >= min_cvss:
                        # Get description
                        descriptions = cve_data.get("descriptions", [])
                        description = descriptions[0].get("value", "") if descriptions else ""
                        
                        # Determine severity
                        if cvss_score >= 9.0:
                            severity = "CRITICAL"
                        elif cvss_score >= 7.0:
                            severity = "HIGH"
                        elif cvss_score >= 4.0:
                            severity = "MEDIUM"
                        else:
                            severity = "LOW"
                        
                        # Get references
                        references = cve_data.get("references", [])
                        ref_urls = [ref.get("url", "") for ref in references[:5]]
                        
                        cve = CVE(
                            cve_id=cve_id,
                            cvss_score=cvss_score,
                            severity=severity,
                            description=description[:500],  # Limit description length
                            affected_software=software,
                            affected_version=version,
                            exploit_available=self._check_exploit_db(cve_id),
                            references=ref_urls
                        )
                        cves.append(cve)
            
        except Exception as e:
            print(f"Error querying NVD: {e}")
        
        return cves
    
    def generate_report(self, cves: List[CVE], output_formats: List[str] = ["markdown"]) -> bool:
        """Generate CVE report"""
        if not cves:
            print("No CVEs found")
            return False
        
        # Filter by severity
        critical_cves = [cve for cve in cves if cve.cvss_score >= 9.0]
        high_cves = [cve for cve in cves if cve.cvss_score >= 7.0 and cve.cvss_score < 9.0]
        exploitable_cves = [cve for cve in cves if cve.exploit_available]
        
        if "markdown" in output_formats:
            self._generate_cve_report_md(cves, critical_cves, high_cves, exploitable_cves)
        
        return True
    
    def _generate_cve_report_md(self, all_cves: List[CVE], critical: List[CVE], high: List[CVE], exploitable: List[CVE]):
        """Generate CVE report in Markdown"""
        output_file = self.output_dir / "cve_report.md"
        
        md = f"""# CVE Correlation Report

**Generated:** {datetime.now().isoformat()}
**Total CVEs Found:** {len(all_cves)}
**Critical CVEs (CVSS 9.0+):** {len(critical)}
**High CVEs (CVSS 7.0-8.9):** {len(high)}
**Exploitable CVEs:** {len(exploitable)}

## Critical Vulnerabilities (CVSS 9.0+)

"""
        
        for cve in critical:
            md += f"""### {cve.cve_id}

- **CVSS Score:** {cve.cvss_score}
- **Severity:** {cve.severity}
- **Affected Software:** {cve.affected_software} {cve.affected_version}
- **Description:** {cve.description[:200]}...
- **Exploit Available:** {'Yes' if cve.exploit_available else 'No'}
- **References:**
"""
            for ref in cve.references[:3]:
                md += f"  - {ref}\n"
            md += "\n"
        
        md += "## High Vulnerabilities (CVSS 7.0-8.9)\n\n"
        
        for cve in high[:20]:  # Limit to 20
            md += f"- **{cve.cve_id}** ({cve.cvss_score}): {cve.affected_software} - {cve.description[:100]}...\n"
        
        md += "\n## All Vulnerabilities\n\n"
        
        for cve in all_cves[:50]:  # Limit to 50
            md += f"- **{cve.cve_id}** (CVSS: {cve.cvss_score}): {cve.affected_software}\n"
        
        with open(output_file, 'w') as f:
            f.write(md)
        
        print(f"CVE report saved to: {output_file}")
        
        # Generate critical CVEs report
        if critical:
            critical_file = self.output_dir / "critical_cves.md"
            with open(critical_file, 'w') as f:
                f.write(f"# Critical CVEs (CVSS 9.0+)\n\n")
                for cve in critical:
                    f.write(f"## {cve.cve_id}\n\n")
                    f.write(f"- **CVSS:** {cve.cvss_score}\n")
                    f.write(f"- **Software:** {cve.affected_software} {cve.affected_version}\n")
                    f.write(f"- **Description:** {cve.description}\n\n")
            print(f"Critical CVEs report saved to: {critical_file}")

if __name__ == "__main__":
    # Test with sample data
    sample_data = {
        "system_info": {
            "os_version": "10.0.19045"
        },
        "services": [
            {"name": "MSSQLSERVER", "display_name": "SQL Server"}
        ]
    }
    
    correlator = CVECorrelator()
    cves = correlator.correlate(sample_data, min_cvss=7.0)
    correlator.generate_report(cves)
