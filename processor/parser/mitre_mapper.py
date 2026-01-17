#!/usr/bin/env python3
"""
MITRE ATT&CK Technique Mapper
Maps enumeration activities to MITRE ATT&CK techniques
"""

import json
from typing import Dict, List, Any, Set
from dataclasses import dataclass, field

@dataclass
class MITRETechnique:
    """MITRE ATT&CK technique information"""
    technique_id: str
    name: str
    tactic: str
    description: str
    detected: bool = False
    evidence: List[str] = field(default_factory=list)

class MITREMapper:
    """Map enumeration data to MITRE ATT&CK techniques"""
    
    # MITRE ATT&CK technique mappings
    TECHNIQUE_MAP = {
        # Discovery Techniques
        "T1087.001": {"name": "Account Discovery: Local Account", "tactic": "Discovery", "keywords": ["user", "account", "net user", "local users"]},
        "T1087.002": {"name": "Account Discovery: Domain Account", "tactic": "Discovery", "keywords": ["domain", "ad", "ldap", "net user /domain"]},
        "T1082": {"name": "System Information Discovery", "tactic": "Discovery", "keywords": ["os version", "system info", "computer name", "architecture"]},
        "T1018": {"name": "Remote System Discovery", "tactic": "Discovery", "keywords": ["network scan", "ping", "host discovery", "subnet"]},
        "T1135": {"name": "Network Share Discovery", "tactic": "Discovery", "keywords": ["smb", "share", "net share", "network share"]},
        "T1518.001": {"name": "Software Discovery: Security Software Discovery", "tactic": "Discovery", "keywords": ["antivirus", "edr", "defender", "security software"]},
        "T1083": {"name": "File and Directory Discovery", "tactic": "Discovery", "keywords": ["directory", "file system", "folder", "path"]},
        "T1057": {"name": "Process Discovery", "tactic": "Discovery", "keywords": ["process", "tasklist", "ps", "running processes"]},
        "T1049": {"name": "System Network Connections Discovery", "tactic": "Discovery", "keywords": ["netstat", "connections", "network connections", "tcp", "udp"]},
        "T1046": {"name": "Network Service Scanning", "tactic": "Discovery", "keywords": ["port scan", "service scan", "open ports", "port enumeration"]},
        
        # Credential Access Techniques
        "T1003.001": {"name": "OS Credential Dumping: LSASS Memory", "tactic": "Credential Access", "keywords": ["lsass", "credential dump", "memory dump"]},
        "T1003.002": {"name": "OS Credential Dumping: SAM", "tactic": "Credential Access", "keywords": ["sam", "registry", "hive", "credential"]},
        "T1550.002": {"name": "Use Alternate Authentication Material: Pass the Hash", "tactic": "Credential Access", "keywords": ["ntlm", "hash", "pass the hash"]},
        "T1550.003": {"name": "Use Alternate Authentication Material: Pass the Ticket", "tactic": "Credential Access", "keywords": ["kerberos", "ticket", "pass the ticket"]},
        
        # Lateral Movement Techniques
        "T1021.002": {"name": "Remote Services: SMB/Windows Admin Shares", "tactic": "Lateral Movement", "keywords": ["smb", "admin share", "c$", "admin$"]},
        "T1021.006": {"name": "Remote Services: WinRM", "tactic": "Lateral Movement", "keywords": ["winrm", "5985", "5986", "powershell remoting"]},
        "T1021.001": {"name": "Remote Services: Remote Desktop Protocol", "tactic": "Lateral Movement", "keywords": ["rdp", "3389", "remote desktop", "mstsc"]},
        "T1047": {"name": "Windows Management Instrumentation", "tactic": "Lateral Movement", "keywords": ["wmi", "135", "remote wmi", "winmgmt"]},
        "T1569.002": {"name": "System Services: Service Execution", "tactic": "Lateral Movement", "keywords": ["service", "sc", "service control", "remote service"]},
        "T1053.005": {"name": "Scheduled Task/Job: Scheduled Task", "tactic": "Lateral Movement", "keywords": ["task", "scheduled task", "schtasks", "at"]},
        "T1570": {"name": "Lateral Tool Transfer", "tactic": "Lateral Movement", "keywords": ["file transfer", "copy", "upload", "download"]},
        
        # Privilege Escalation Techniques
        "T1068": {"name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation", "keywords": ["exploit", "cve", "vulnerability", "privilege escalation"]},
        "T1134.001": {"name": "Access Token Manipulation: Token Impersonation/Theft", "tactic": "Privilege Escalation", "keywords": ["token", "system token", "impersonation", "steal token"]},
        "T1548.002": {"name": "Abuse Elevation Control Mechanism: Bypass User Account Control", "tactic": "Privilege Escalation", "keywords": ["uac", "bypass", "elevation", "admin"]},
        "T1574.002": {"name": "Hijack Execution Flow: DLL Side-Loading", "tactic": "Privilege Escalation", "keywords": ["dll", "hijack", "side-load", "dll hijacking"]},
        
        # Defense Evasion Techniques
        "T1036": {"name": "Masquerading", "tactic": "Defense Evasion", "keywords": ["masquerade", "legitimate", "spoof", "impersonate"]},
        "T1027": {"name": "Obfuscated Files or Information", "tactic": "Defense Evasion", "keywords": ["obfuscate", "encode", "encrypt", "hide"]},
        "T1562.001": {"name": "Impair Defenses: Disable or Modify Tools", "tactic": "Defense Evasion", "keywords": ["disable", "bypass", "evade", "edr", "antivirus"]},
        "T1070.001": {"name": "Indicator Removal: Clear Windows Event Logs", "tactic": "Defense Evasion", "keywords": ["clear logs", "event log", "wevtutil", "log deletion"]},
        "T1055": {"name": "Process Injection", "tactic": "Defense Evasion", "keywords": ["injection", "inject", "process hollowing", "dll injection"]},
        
        # Persistence Techniques
        "T1053.005": {"name": "Scheduled Task/Job: Scheduled Task", "tactic": "Persistence", "keywords": ["task", "scheduled task", "schtasks", "persistence"]},
        "T1543": {"name": "Create or Modify System Process: Windows Service", "tactic": "Persistence", "keywords": ["service", "create service", "persistent service"]},
        "T1053.003": {"name": "Scheduled Task/Job: Cron", "tactic": "Persistence", "keywords": ["cron", "scheduled", "task scheduler"]},
        "T1112": {"name": "Modify Registry", "tactic": "Persistence", "keywords": ["registry", "reg", "modify registry", "registry key"]},
        "T1547": {"name": "Boot or Logon Autostart Execution", "tactic": "Persistence", "keywords": ["startup", "autostart", "run", "boot"]},
    }
    
    def __init__(self):
        self.detected_techniques: List[MITRETechnique] = []
    
    def map_enumeration_data(self, data: Dict[str, Any]) -> List[MITRETechnique]:
        """Map enumeration data to MITRE ATT&CK techniques"""
        raw_data = data.get("raw_data", "")
        raw_lower = raw_data.lower()
        
        detected = []
        
        # Check each technique
        for tech_id, tech_info in self.TECHNIQUE_MAP.items():
            technique = MITRETechnique(
                technique_id=tech_id,
                name=tech_info["name"],
                tactic=tech_info["tactic"],
                description=tech_info.get("description", ""),
                detected=False,
                evidence=[]
            )
            
            # Check for keywords
            for keyword in tech_info["keywords"]:
                if keyword.lower() in raw_lower:
                    technique.detected = True
                    technique.evidence.append(f"Keyword match: {keyword}")
                    break
            
            # Specific checks
            if tech_id == "T1018":
                if "network discovery" in raw_lower or "subnet" in raw_lower or "ping" in raw_lower:
                    technique.detected = True
                    technique.evidence.append("Network discovery activity detected")
            
            if tech_id == "T1135":
                if "smb" in raw_lower or "share" in raw_lower or "\\\\" in raw_data:
                    technique.detected = True
                    technique.evidence.append("SMB share enumeration detected")
            
            if tech_id == "T1047":
                if "wmi" in raw_lower or "135" in raw_data:
                    technique.detected = True
                    technique.evidence.append("WMI enumeration detected")
            
            if tech_id == "T1021.002":
                if "smb" in raw_lower or "admin$" in raw_lower or "c$" in raw_lower:
                    technique.detected = True
                    technique.evidence.append("SMB/Admin share access detected")
            
            if tech_id == "T1021.006":
                if "winrm" in raw_lower or "5985" in raw_data or "5986" in raw_data:
                    technique.detected = True
                    technique.evidence.append("WinRM enumeration detected")
            
            if tech_id == "T1021.001":
                if "rdp" in raw_lower or "3389" in raw_data or "remote desktop" in raw_lower:
                    technique.detected = True
                    technique.evidence.append("RDP enumeration detected")
            
            if tech_id == "T1003.001":
                if "lsass" in raw_lower and data.get("has_system_token", False):
                    technique.detected = True
                    technique.evidence.append("LSASS access with SYSTEM token")
            
            if tech_id == "T1134.001":
                if "system token" in raw_lower and "acquired" in raw_lower:
                    technique.detected = True
                    technique.evidence.append("SYSTEM token acquisition detected")
            
            if technique.detected:
                detected.append(technique)
        
        self.detected_techniques = detected
        return detected
    
    def generate_report(self, output_file: str = "output/reports/mitre_techniques.md") -> str:
        """Generate MITRE ATT&CK technique report"""
        from pathlib import Path
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Group by tactic
        by_tactic = {}
        for tech in self.detected_techniques:
            if tech.tactic not in by_tactic:
                by_tactic[tech.tactic] = []
            by_tactic[tech.tactic].append(tech)
        
        md = "# MITRE ATT&CK Technique Detection Report\n\n"
        md += f"**Total Techniques Detected:** {len(self.detected_techniques)}\n\n"
        
        for tactic, techniques in sorted(by_tactic.items()):
            md += f"## {tactic} ({len(techniques)} techniques)\n\n"
            for tech in techniques:
                md += f"### {tech.technique_id}: {tech.name}\n\n"
                md += f"**Evidence:**\n"
                for evidence in tech.evidence:
                    md += f"- {evidence}\n"
                md += "\n"
        
        with open(output_path, 'w') as f:
            f.write(md)
        
        return str(output_path)

if __name__ == "__main__":
    # Test with sample data
    sample_data = {
        "raw_data": "Network discovery: Found 10 hosts. SMB shares: \\\\192.168.1.1\\C$, WMI enumeration on 192.168.1.2, SYSTEM token acquired",
        "has_system_token": True
    }
    
    mapper = MITREMapper()
    techniques = mapper.map_enumeration_data(sample_data)
    print(f"Detected {len(techniques)} MITRE ATT&CK techniques")
    for tech in techniques:
        print(f"  {tech.technique_id}: {tech.name} ({tech.tactic})")
    
    mapper.generate_report()
