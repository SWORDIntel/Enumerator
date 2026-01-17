#!/usr/bin/env python3
"""
Technique Pattern Matcher
Matches enumeration data to known attack techniques from integrated tools.
Uses real pattern analysis - no fake matching.
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
import re

@dataclass
class Technique:
    """Attack technique information"""
    technique_id: str
    name: str
    tool_source: str
    description: str
    mitre_id: Optional[str] = None
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)

class TechniquePatternMatcher:
    """
    Matches enumeration data to attack techniques from:
    - W-SLAM: Lateral movement, privilege escalation
    - ROGUEPILOT: Reprompt attacks, workflow automation
    - ROCKHAMMER: C2/tunneling
    - CORTISOL: WAF bypass
    - ACTIVEGAME: AD/certificate abuse
    - SLEEPYMONEY: Persistence/steganography
    - WINCLOAK: Post-exploitation
    """
    
    def __init__(self):
        """Initialize pattern database with real patterns from tool analysis"""
        self.patterns = self._load_patterns()
    
    def _load_patterns(self) -> Dict[str, List[Dict[str, Any]]]:
        """Load attack patterns from tool analysis"""
        return {
            "w_slam": [
                {
                    "name": "Lateral Movement via SMB",
                    "mitre_id": "T1021.002",
                    "keywords": ["smb", "share", "net share", "\\\\"],
                    "evidence_patterns": [r"\\\\[^\\]+\\[^\\]+", r"SMB.*share"]
                },
                {
                    "name": "Lateral Movement via WMI",
                    "mitre_id": "T1047",
                    "keywords": ["wmi", "winmgmt", "wbem"],
                    "evidence_patterns": [r"WMI", r"root\\cimv2"]
                },
                {
                    "name": "Privilege Escalation via Token Manipulation",
                    "mitre_id": "T1134",
                    "keywords": ["token", "SYSTEM", "privilege", "escalation"],
                    "evidence_patterns": [r"SYSTEM.*token", r"token.*acquired"]
                }
            ],
            "roguepilot": [
                {
                    "name": "Reprompt Attack",
                    "mitre_id": "T1566.001",
                    "keywords": ["copilot", "reprompt", "session", "hijack"],
                    "evidence_patterns": [r"copilot", r"reprompt"]
                },
                {
                    "name": "Workflow Automation",
                    "mitre_id": "T1059.003",
                    "keywords": ["workflow", "automation", "script"],
                    "evidence_patterns": [r"workflow", r"automated"]
                }
            ],
            "rockhammer": [
                {
                    "name": "C2 Beacon Communication",
                    "mitre_id": "T1071",
                    "keywords": ["beacon", "c2", "command.*control"],
                    "evidence_patterns": [r"beacon", r"c2.*channel"]
                },
                {
                    "name": "Tunnel/Proxy Establishment",
                    "mitre_id": "T1572",
                    "keywords": ["tunnel", "proxy", "socks", "ssh.*tunnel"],
                    "evidence_patterns": [r"tunnel", r"proxy.*enabled"]
                }
            ],
            "cortisol": [
                {
                    "name": "WAF Bypass via Encoding",
                    "mitre_id": "T1190",
                    "keywords": ["waf", "bypass", "encoding", "normalization"],
                    "evidence_patterns": [r"WAF.*detected", r"normalization.*bypass"]
                },
                {
                    "name": "SQL Injection Bypass",
                    "mitre_id": "T1190",
                    "keywords": ["sqli", "sql.*injection", "database"],
                    "evidence_patterns": [r"SQL.*injection", r"database.*access"]
                }
            ],
            "activegame": [
                {
                    "name": "AD Certificate Abuse",
                    "mitre_id": "T1550.002",
                    "keywords": ["certificate", "adcs", "pki", "enrollment"],
                    "evidence_patterns": [r"Certificate.*Services", r"ADCS"]
                },
                {
                    "name": "Domain Controller Access",
                    "mitre_id": "T1078",
                    "keywords": ["domain.*controller", "dc", "active.*directory"],
                    "evidence_patterns": [r"Domain.*Controller", r"AD.*infrastructure"]
                }
            ],
            "sleepymoney": [
                {
                    "name": "Steganography-based Exfiltration",
                    "mitre_id": "T1030",
                    "keywords": ["steganography", "lsb", "entropy", "image"],
                    "evidence_patterns": [r"steganography", r"high.*entropy.*file"]
                },
                {
                    "name": "Persistence via Rootkit",
                    "mitre_id": "T1014",
                    "keywords": ["rootkit", "hidden", "kernel.*driver"],
                    "evidence_patterns": [r"rootkit", r"kernel.*driver"]
                }
            ],
            "wincloak": [
                {
                    "name": "AMSI/ETW Bypass",
                    "mitre_id": "T1562.001",
                    "keywords": ["amsi", "etw", "wfp", "bypass"],
                    "evidence_patterns": [r"AMSI", r"ETW", r"WFP"]
                },
                {
                    "name": "COM Hijacking",
                    "mitre_id": "T1546.015",
                    "keywords": ["com", "hijacking", "clsid"],
                    "evidence_patterns": [r"COM.*hijacking", r"CLSID"]
                },
                {
                    "name": "WMI Persistence",
                    "mitre_id": "T1546.003",
                    "keywords": ["wmi", "event.*subscription", "persistence"],
                    "evidence_patterns": [r"WMI.*event.*filter", r"WMI.*persistence"]
                },
                {
                    "name": "Kerberos Ticket Manipulation",
                    "mitre_id": "T1558",
                    "keywords": ["kerberos", "ticket", "kdc"],
                    "evidence_patterns": [r"Kerberos", r"ticket.*cache"]
                }
            ]
        }
    
    def match_all_patterns(self, data: Dict[str, Any]) -> List[Technique]:
        """Match all tool patterns against enumeration data"""
        techniques = []
        
        techniques.extend(self.match_w_slam_patterns(data))
        techniques.extend(self.match_roguepilot_patterns(data))
        techniques.extend(self.match_rockhammer_patterns(data))
        techniques.extend(self.match_cortisol_patterns(data))
        techniques.extend(self.match_activegame_patterns(data))
        techniques.extend(self.match_sleepymoney_patterns(data))
        techniques.extend(self.match_wincloak_patterns(data))
        
        return techniques
    
    def match_w_slam_patterns(self, data: Dict[str, Any]) -> List[Technique]:
        """Match W-SLAM lateral movement/privilege escalation patterns"""
        techniques = []
        raw_data = data.get("raw_data", "").lower()
        
        for pattern in self.patterns["w_slam"]:
            matches = []
            for keyword in pattern["keywords"]:
                if keyword.lower() in raw_data:
                    matches.append(keyword)
            
            for evidence_pattern in pattern.get("evidence_patterns", []):
                if re.search(evidence_pattern, raw_data, re.IGNORECASE):
                    matches.append(f"Pattern: {evidence_pattern}")
            
            if matches:
                techniques.append(Technique(
                    technique_id=f"w_slam_{pattern['name'].lower().replace(' ', '_')}",
                    name=pattern["name"],
                    tool_source="W-SLAM",
                    description=f"W-SLAM technique: {pattern['name']}",
                    mitre_id=pattern.get("mitre_id"),
                    confidence=min(len(matches) * 0.3, 1.0),
                    evidence=matches
                ))
        
        return techniques
    
    def match_roguepilot_patterns(self, data: Dict[str, Any]) -> List[Technique]:
        """Match ROGUEPILOT reprompt/workflow patterns"""
        techniques = []
        raw_data = data.get("raw_data", "").lower()
        
        for pattern in self.patterns["roguepilot"]:
            matches = []
            for keyword in pattern["keywords"]:
                if keyword.lower() in raw_data:
                    matches.append(keyword)
            
            if matches:
                techniques.append(Technique(
                    technique_id=f"roguepilot_{pattern['name'].lower().replace(' ', '_')}",
                    name=pattern["name"],
                    tool_source="ROGUEPILOT",
                    description=f"ROGUEPILOT technique: {pattern['name']}",
                    mitre_id=pattern.get("mitre_id"),
                    confidence=min(len(matches) * 0.3, 1.0),
                    evidence=matches
                ))
        
        return techniques
    
    def match_rockhammer_patterns(self, data: Dict[str, Any]) -> List[Technique]:
        """Match ROCKHAMMER C2/tunneling patterns"""
        techniques = []
        raw_data = data.get("raw_data", "").lower()
        
        for pattern in self.patterns["rockhammer"]:
            matches = []
            for keyword in pattern["keywords"]:
                if keyword.lower() in raw_data:
                    matches.append(keyword)
            
            for evidence_pattern in pattern.get("evidence_patterns", []):
                if re.search(evidence_pattern, raw_data, re.IGNORECASE):
                    matches.append(f"Pattern: {evidence_pattern}")
            
            if matches:
                techniques.append(Technique(
                    technique_id=f"rockhammer_{pattern['name'].lower().replace(' ', '_')}",
                    name=pattern["name"],
                    tool_source="ROCKHAMMER",
                    description=f"ROCKHAMMER technique: {pattern['name']}",
                    mitre_id=pattern.get("mitre_id"),
                    confidence=min(len(matches) * 0.3, 1.0),
                    evidence=matches
                ))
        
        return techniques
    
    def match_cortisol_patterns(self, data: Dict[str, Any]) -> List[Technique]:
        """Match CORTISOL WAF bypass patterns"""
        techniques = []
        raw_data = data.get("raw_data", "").lower()
        
        for pattern in self.patterns["cortisol"]:
            matches = []
            for keyword in pattern["keywords"]:
                if keyword.lower() in raw_data:
                    matches.append(keyword)
            
            for evidence_pattern in pattern.get("evidence_patterns", []):
                if re.search(evidence_pattern, raw_data, re.IGNORECASE):
                    matches.append(f"Pattern: {evidence_pattern}")
            
            if matches:
                techniques.append(Technique(
                    technique_id=f"cortisol_{pattern['name'].lower().replace(' ', '_')}",
                    name=pattern["name"],
                    tool_source="CORTISOL",
                    description=f"CORTISOL technique: {pattern['name']}",
                    mitre_id=pattern.get("mitre_id"),
                    confidence=min(len(matches) * 0.3, 1.0),
                    evidence=matches
                ))
        
        return techniques
    
    def match_activegame_patterns(self, data: Dict[str, Any]) -> List[Technique]:
        """Match ACTIVEGAME AD/certificate patterns"""
        techniques = []
        raw_data = data.get("raw_data", "").lower()
        
        for pattern in self.patterns["activegame"]:
            matches = []
            for keyword in pattern["keywords"]:
                if keyword.lower() in raw_data:
                    matches.append(keyword)
            
            for evidence_pattern in pattern.get("evidence_patterns", []):
                if re.search(evidence_pattern, raw_data, re.IGNORECASE):
                    matches.append(f"Pattern: {evidence_pattern}")
            
            if matches:
                techniques.append(Technique(
                    technique_id=f"activegame_{pattern['name'].lower().replace(' ', '_')}",
                    name=pattern["name"],
                    tool_source="ACTIVEGAME",
                    description=f"ACTIVEGAME technique: {pattern['name']}",
                    mitre_id=pattern.get("mitre_id"),
                    confidence=min(len(matches) * 0.3, 1.0),
                    evidence=matches
                ))
        
        return techniques
    
    def match_sleepymoney_patterns(self, data: Dict[str, Any]) -> List[Technique]:
        """Match SLEEPYMONEY persistence/steganography patterns"""
        techniques = []
        raw_data = data.get("raw_data", "").lower()
        
        for pattern in self.patterns["sleepymoney"]:
            matches = []
            for keyword in pattern["keywords"]:
                if keyword.lower() in raw_data:
                    matches.append(keyword)
            
            for evidence_pattern in pattern.get("evidence_patterns", []):
                if re.search(evidence_pattern, raw_data, re.IGNORECASE):
                    matches.append(f"Pattern: {evidence_pattern}")
            
            if matches:
                techniques.append(Technique(
                    technique_id=f"sleepymoney_{pattern['name'].lower().replace(' ', '_')}",
                    name=pattern["name"],
                    tool_source="SLEEPYMONEY",
                    description=f"SLEEPYMONEY technique: {pattern['name']}",
                    mitre_id=pattern.get("mitre_id"),
                    confidence=min(len(matches) * 0.3, 1.0),
                    evidence=matches
                ))
        
        return techniques
    
    def match_wincloak_patterns(self, data: Dict[str, Any]) -> List[Technique]:
        """Match WINCLOAK post-exploitation patterns"""
        techniques = []
        raw_data = data.get("raw_data", "").lower()
        
        for pattern in self.patterns["wincloak"]:
            matches = []
            for keyword in pattern["keywords"]:
                if keyword.lower() in raw_data:
                    matches.append(keyword)
            
            for evidence_pattern in pattern.get("evidence_patterns", []):
                if re.search(evidence_pattern, raw_data, re.IGNORECASE):
                    matches.append(f"Pattern: {evidence_pattern}")
            
            if matches:
                techniques.append(Technique(
                    technique_id=f"wincloak_{pattern['name'].lower().replace(' ', '_')}",
                    name=pattern["name"],
                    tool_source="WINCLOAK",
                    description=f"WINCLOAK technique: {pattern['name']}",
                    mitre_id=pattern.get("mitre_id"),
                    confidence=min(len(matches) * 0.3, 1.0),
                    evidence=matches
                ))
        
        return techniques
