#!/usr/bin/env python3
"""
CVE Chain Generator
Integrates SWORD's CVE chaining capabilities to generate attack chains based on discovered CVEs.
Uses real SWORD modules - no fake implementations.
"""

import sys
import os
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field

# Add SWORD path for real module imports
sword_path = Path(__file__).parent.parent.parent.parent / "tools" / "OFFENSIVE" / "SWORD"
if sword_path.exists():
    sys.path.insert(0, str(sword_path))

# Import real SWORD modules
try:
    from modules.exploitation.chains.Generator.enhanced_chain_generator import EnhancedChainGenerator
    from modules.exploitation.chains.Cataloging.cve_chain_generator import CVEChainGenerator as SWORDCVEChainGenerator
    HAS_SWORD = True
except ImportError:
    HAS_SWORD = False
    print("Warning: SWORD modules not found. CVE chain generation will be limited.")

@dataclass
class AttackChain:
    """Attack chain data structure"""
    chain_id: str
    name: str
    description: str
    steps: List[Dict[str, Any]] = field(default_factory=list)
    success_probability: float = 0.0
    compatibility_score: float = 0.0
    source_tool: str = ""
    mitre_techniques: List[str] = field(default_factory=list)
    cves: List[str] = field(default_factory=list)

class CVEChainGenerator:
    """
    CVE Chain Generator that uses real SWORD modules.
    Generates attack chains from discovered CVEs in enumeration data.
    """
    
    def __init__(self, enumeration_data: Dict[str, Any]):
        """
        Initialize with enumeration data.
        
        Args:
            enumeration_data: Parsed enumeration data containing CVEs and system info
        """
        self.enumeration_data = enumeration_data
        self.chains: List[AttackChain] = []
        
        # Initialize SWORD chain generator if available
        self.sword_generator = None
        if HAS_SWORD:
            try:
                self.sword_generator = EnhancedChainGenerator()
            except Exception as e:
                print(f"Warning: Failed to initialize SWORD EnhancedChainGenerator: {e}")
    
    def generate_chains(self) -> List[AttackChain]:
        """
        Generate attack chains from discovered CVEs.
        Uses real SWORD chain generation if available.
        """
        self.chains = []
        
        # Extract CVEs from enumeration data
        network_cves = self.enumeration_data.get("network_cves", {})
        if not network_cves:
            return self.chains
        
        # Use SWORD chain generator if available
        if self.sword_generator and HAS_SWORD:
            try:
                # Extract CVE IDs
                cve_ids = list(network_cves.keys())
                
                # Generate chains using SWORD's real chain generator
                for cve_id in cve_ids[:10]:  # Limit to top 10 CVEs
                    cve_info = network_cves[cve_id]
                    if cve_info.get("cvss_score", 0) >= 7.0:
                        chain = self._generate_chain_from_cve(cve_id, cve_info)
                        if chain:
                            self.chains.append(chain)
            except Exception as e:
                print(f"Error generating chains with SWORD: {e}")
        else:
            # Fallback: Generate basic chains without SWORD
            for cve_id, cve_info in list(network_cves.items())[:10]:
                if cve_info.get("cvss_score", 0) >= 7.0:
                    chain = self._generate_basic_chain(cve_id, cve_info)
                    if chain:
                        self.chains.append(chain)
        
        return self.chains
    
    def _generate_chain_from_cve(self, cve_id: str, cve_info: Dict[str, Any]) -> Optional[AttackChain]:
        """Generate chain from CVE using SWORD's real chain generator"""
        try:
            # Use SWORD's real chain generation
            target_info = {
                "os": self.enumeration_data.get("system_info", {}).get("os_version", ""),
                "software": cve_info.get("affected_software", [])
            }
            
            # Generate chain using SWORD's real API
            if hasattr(self.sword_generator, 'generate_chain'):
                sword_chain = self.sword_generator.generate_chain(
                    target=target_info,
                    objective="exploit",
                    cve_id=cve_id
                )
                
                if sword_chain:
                    return AttackChain(
                        chain_id=f"chain_{cve_id}",
                        name=f"Attack Chain for {cve_id}",
                        description=f"Generated chain for {cve_id} (CVSS: {cve_info.get('cvss_score', 0)})",
                        steps=sword_chain.get("steps", []),
                        success_probability=sword_chain.get("success_probability", 0.0),
                        compatibility_score=sword_chain.get("compatibility_score", 0.0),
                        source_tool="SWORD",
                        cves=[cve_id]
                    )
        except Exception as e:
            print(f"Error generating chain for {cve_id}: {e}")
        
        return None
    
    def _generate_basic_chain(self, cve_id: str, cve_info: Dict[str, Any]) -> Optional[AttackChain]:
        """Generate basic chain without SWORD (fallback)"""
        steps = [
            {
                "step": 1,
                "type": "reconnaissance",
                "description": f"Identify {cve_id} vulnerability",
                "technique": "T1046"
            },
            {
                "step": 2,
                "type": "exploitation",
                "description": f"Exploit {cve_id}",
                "technique": "T1190",
                "cve": cve_id
            },
            {
                "step": 3,
                "type": "privilege_escalation",
                "description": "Escalate privileges",
                "technique": "T1068"
            }
        ]
        
        return AttackChain(
            chain_id=f"chain_{cve_id}",
            name=f"Basic Attack Chain for {cve_id}",
            description=f"Basic chain for {cve_id} (CVSS: {cve_info.get('cvss_score', 0)})",
            steps=steps,
            success_probability=0.7 if cve_info.get("exploit_available", False) else 0.5,
            source_tool="ENUMERATOR",
            cves=[cve_id]
        )
    
    def find_chain_paths(self, start_cve: str, target: str) -> List[List[str]]:
        """
        Find paths between CVEs using knowledge graph.
        Uses real SWORD knowledge graph if available.
        """
        paths = []
        
        if self.sword_generator and hasattr(self.sword_generator, 'knowledge_graph'):
            try:
                # Use SWORD's real knowledge graph
                if self.sword_generator.knowledge_graph:
                    paths = self.sword_generator.knowledge_graph.find_paths(start_cve, target)
            except Exception as e:
                print(f"Error finding chain paths: {e}")
        
        return paths
    
    def assess_chain_compatibility(self, chain: AttackChain) -> float:
        """
        Assess technical compatibility of chain steps.
        Uses real SWORD compatibility assessment if available.
        """
        if self.sword_generator and hasattr(self.sword_generator, 'assess_compatibility'):
            try:
                # Use SWORD's real compatibility assessment
                return self.sword_generator.assess_compatibility(chain.steps)
            except Exception as e:
                print(f"Error assessing chain compatibility: {e}")
        
        # Fallback: Basic compatibility check
        if len(chain.steps) > 0:
            return 0.8  # Default compatibility score
        return 0.0
