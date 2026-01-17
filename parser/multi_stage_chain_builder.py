#!/usr/bin/env python3
"""
Multi-Stage Chain Builder
Builds sophisticated multi-stage attack chains with conditional paths, fallbacks, and alternatives.
Uses real chain building logic - no fake implementations.
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum

class StageType(Enum):
    """Attack chain stage types"""
    RECONNAISSANCE = "reconnaissance"
    INITIAL_ACCESS = "initial_access"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    PERSISTENCE = "persistence"
    EXFILTRATION = "exfiltration"

@dataclass
class ChainStep:
    """Individual step in an attack chain"""
    step_id: str
    stage: StageType
    technique: str
    description: str
    prerequisites: List[str] = field(default_factory=list)
    success_probability: float = 0.0
    fallback_steps: List[str] = field(default_factory=list)

@dataclass
class ConditionalPath:
    """Conditional execution path"""
    condition: str
    path: List[ChainStep]
    description: str

@dataclass
class AttackChain:
    """Complete attack chain with stages and alternatives"""
    chain_id: str
    name: str
    description: str
    stages: Dict[StageType, List[ChainStep]] = field(default_factory=dict)
    conditional_paths: List[ConditionalPath] = field(default_factory=list)
    alternatives: List['AttackChain'] = field(default_factory=list)
    overall_success_probability: float = 0.0

class MultiStageChainBuilder:
    """
    Builds multi-stage attack chains with real logic.
    No fake implementations - all chain building is functional.
    """
    
    def __init__(self, enumeration_data: Dict[str, Any]):
        """
        Initialize with enumeration data.
        
        Args:
            enumeration_data: Parsed enumeration data
        """
        self.enumeration_data = enumeration_data
        self.chains: List[AttackChain] = []
    
    def build_chains(self) -> List[AttackChain]:
        """Build complete attack chains from enumeration data"""
        self.chains = []
        
        # Extract key information
        system_info = self.enumeration_data.get("system_info", {})
        network_cves = self.enumeration_data.get("network_cves", {})
        techniques = self.enumeration_data.get("techniques", [])
        
        # Build chains based on discovered vulnerabilities and techniques
        if network_cves:
            for cve_id, cve_info in list(network_cves.items())[:5]:  # Top 5 CVEs
                if cve_info.get("cvss_score", 0) >= 7.0:
                    chain = self.build_chain(
                        target=system_info.get("computer_name", "target"),
                        objective=f"Exploit {cve_id}"
                    )
                    if chain:
                        self.chains.append(chain)
        
        # Build chains from discovered techniques
        if techniques:
            technique_chain = self._build_chain_from_techniques(techniques)
            if technique_chain:
                self.chains.append(technique_chain)
        
        return self.chains
    
    def build_chain(self, target: str, objective: str) -> Optional[AttackChain]:
        """
        Build complete attack chain.
        Real chain building with actual logic.
        """
        chain = AttackChain(
            chain_id=f"chain_{len(self.chains) + 1}",
            name=f"Attack Chain: {objective}",
            description=f"Multi-stage attack chain targeting {target} with objective: {objective}"
        )
        
        # Stage 1: Reconnaissance
        recon_steps = self._build_reconnaissance_stage()
        if recon_steps:
            chain.stages[StageType.RECONNAISSANCE] = recon_steps
        
        # Stage 2: Initial Access
        initial_access_steps = self._build_initial_access_stage()
        if initial_access_steps:
            chain.stages[StageType.INITIAL_ACCESS] = initial_access_steps
        
        # Stage 3: Privilege Escalation
        priv_esc_steps = self._build_privilege_escalation_stage()
        if priv_esc_steps:
            chain.stages[StageType.PRIVILEGE_ESCALATION] = priv_esc_steps
        
        # Stage 4: Lateral Movement
        lateral_steps = self._build_lateral_movement_stage()
        if lateral_steps:
            chain.stages[StageType.LATERAL_MOVEMENT] = lateral_steps
        
        # Stage 5: Persistence
        persistence_steps = self._build_persistence_stage()
        if persistence_steps:
            chain.stages[StageType.PERSISTENCE] = persistence_steps
        
        # Stage 6: Exfiltration
        exfil_steps = self._build_exfiltration_stage()
        if exfil_steps:
            chain.stages[StageType.EXFILTRATION] = exfil_steps
        
        # Calculate overall success probability
        chain.overall_success_probability = self._calculate_chain_probability(chain)
        
        return chain
    
    def _build_reconnaissance_stage(self) -> List[ChainStep]:
        """Build reconnaissance stage steps"""
        steps = []
        
        # Network scanning
        network_cves = self.enumeration_data.get("network_cves", {})
        if network_cves:
            steps.append(ChainStep(
                step_id="recon_1",
                stage=StageType.RECONNAISSANCE,
                technique="Network Service Scanning",
                description="Scan network for vulnerable services",
                success_probability=0.9
            ))
        
        # System information gathering
        system_info = self.enumeration_data.get("system_info", {})
        if system_info:
            steps.append(ChainStep(
                step_id="recon_2",
                stage=StageType.RECONNAISSANCE,
                technique="System Information Discovery",
                description="Gather system information and configuration",
                success_probability=0.95
            ))
        
        return steps
    
    def _build_initial_access_stage(self) -> List[ChainStep]:
        """Build initial access stage steps"""
        steps = []
        
        # CVE-based initial access
        network_cves = self.enumeration_data.get("network_cves", {})
        for cve_id, cve_info in list(network_cves.items())[:3]:
            if cve_info.get("cvss_score", 0) >= 7.0:
                steps.append(ChainStep(
                    step_id=f"initial_{cve_id}",
                    stage=StageType.INITIAL_ACCESS,
                    technique=f"Exploit {cve_id}",
                    description=f"Exploit {cve_id} for initial access (CVSS: {cve_info.get('cvss_score', 0)})",
                    success_probability=0.8 if cve_info.get("exploit_available", False) else 0.6
                ))
        
        return steps
    
    def _build_privilege_escalation_stage(self) -> List[ChainStep]:
        """Build privilege escalation stage steps"""
        steps = []
        
        # Check for token manipulation opportunities
        raw_data = self.enumeration_data.get("raw_data", "").lower()
        if "token" in raw_data or "system" in raw_data:
            steps.append(ChainStep(
                step_id="priv_esc_1",
                stage=StageType.PRIVILEGE_ESCALATION,
                technique="Token Manipulation",
                description="Manipulate access tokens for privilege escalation",
                success_probability=0.7
            ))
        
        # Check for kernel exploits
        if "kernel" in raw_data or "driver" in raw_data:
            steps.append(ChainStep(
                step_id="priv_esc_2",
                stage=StageType.PRIVILEGE_ESCALATION,
                technique="Kernel Exploit",
                description="Exploit kernel vulnerability for SYSTEM privileges",
                success_probability=0.6
            ))
        
        return steps
    
    def _build_lateral_movement_stage(self) -> List[ChainStep]:
        """Build lateral movement stage steps"""
        steps = []
        
        # SMB lateral movement
        raw_data = self.enumeration_data.get("raw_data", "").lower()
        if "smb" in raw_data or "share" in raw_data:
            steps.append(ChainStep(
                step_id="lateral_1",
                stage=StageType.LATERAL_MOVEMENT,
                technique="SMB Lateral Movement",
                description="Move laterally via SMB shares",
                success_probability=0.7
            ))
        
        # WMI lateral movement
        if "wmi" in raw_data:
            steps.append(ChainStep(
                step_id="lateral_2",
                stage=StageType.LATERAL_MOVEMENT,
                technique="WMI Lateral Movement",
                description="Move laterally via WMI",
                success_probability=0.6
            ))
        
        return steps
    
    def _build_persistence_stage(self) -> List[ChainStep]:
        """Build persistence stage steps"""
        steps = []
        
        # WMI persistence
        raw_data = self.enumeration_data.get("raw_data", "").lower()
        if "wmi" in raw_data and "event" in raw_data:
            steps.append(ChainStep(
                step_id="persist_1",
                stage=StageType.PERSISTENCE,
                technique="WMI Event Subscription",
                description="Establish persistence via WMI event subscriptions",
                success_probability=0.8
            ))
        
        # Service persistence
        services = self.enumeration_data.get("services", [])
        if services:
            steps.append(ChainStep(
                step_id="persist_2",
                stage=StageType.PERSISTENCE,
                technique="Service Installation",
                description="Install malicious service for persistence",
                success_probability=0.75
            ))
        
        return steps
    
    def _build_exfiltration_stage(self) -> List[ChainStep]:
        """Build exfiltration stage steps"""
        steps = []
        
        # DNS tunneling
        raw_data = self.enumeration_data.get("raw_data", "").lower()
        if "dns" in raw_data:
            steps.append(ChainStep(
                step_id="exfil_1",
                stage=StageType.EXFILTRATION,
                technique="DNS Tunneling",
                description="Exfiltrate data via DNS tunneling",
                success_probability=0.7
            ))
        
        # Steganography
        if "steganography" in raw_data or "entropy" in raw_data:
            steps.append(ChainStep(
                step_id="exfil_2",
                stage=StageType.EXFILTRATION,
                technique="Steganographic Exfiltration",
                description="Exfiltrate data via steganography",
                success_probability=0.65
            ))
        
        return steps
    
    def _build_chain_from_techniques(self, techniques: List[Any]) -> Optional[AttackChain]:
        """Build chain from discovered techniques"""
        if not techniques:
            return None
        
        chain = AttackChain(
            chain_id="technique_chain",
            name="Technique-Based Attack Chain",
            description="Attack chain built from discovered techniques"
        )
        
        # Map techniques to stages
        for tech in techniques[:10]:  # Limit to top 10
            tech_name = tech.name if hasattr(tech, 'name') else str(tech)
            tech_tool = tech.tool_source if hasattr(tech, 'tool_source') else "UNKNOWN"
            
            # Determine stage based on technique
            stage = self._determine_stage_from_technique(tech_name, tech_tool)
            if stage:
                step = ChainStep(
                    step_id=f"tech_{len(chain.stages.get(stage, []))}",
                    stage=stage,
                    technique=tech_name,
                    description=f"{tech_tool} technique: {tech_name}",
                    success_probability=0.7
                )
                if stage not in chain.stages:
                    chain.stages[stage] = []
                chain.stages[stage].append(step)
        
        chain.overall_success_probability = self._calculate_chain_probability(chain)
        return chain
    
    def _determine_stage_from_technique(self, technique_name: str, tool_source: str) -> Optional[StageType]:
        """Determine attack stage from technique name"""
        name_lower = technique_name.lower()
        
        if "recon" in name_lower or "scan" in name_lower or "discovery" in name_lower:
            return StageType.RECONNAISSANCE
        elif "initial" in name_lower or "access" in name_lower or "exploit" in name_lower:
            return StageType.INITIAL_ACCESS
        elif "privilege" in name_lower or "escalation" in name_lower or "token" in name_lower:
            return StageType.PRIVILEGE_ESCALATION
        elif "lateral" in name_lower or "movement" in name_lower or "smb" in name_lower or "wmi" in name_lower:
            return StageType.LATERAL_MOVEMENT
        elif "persistence" in name_lower or "persist" in name_lower or "rootkit" in name_lower:
            return StageType.PERSISTENCE
        elif "exfiltrat" in name_lower or "steganography" in name_lower or "dns" in name_lower:
            return StageType.EXFILTRATION
        
        return None
    
    def _calculate_chain_probability(self, chain: AttackChain) -> float:
        """Calculate overall chain success probability"""
        if not chain.stages:
            return 0.0
        
        total_prob = 1.0
        stage_count = 0
        
        for stage, steps in chain.stages.items():
            if steps:
                stage_prob = max(step.success_probability for step in steps)
                total_prob *= stage_prob
                stage_count += 1
        
        if stage_count > 0:
            return total_prob ** (1.0 / stage_count)
        
        return 0.0
    
    def add_stage(self, chain: AttackChain, stage_type: StageType, techniques: List[ChainStep]):
        """Add stage to attack chain"""
        chain.stages[stage_type] = techniques
        chain.overall_success_probability = self._calculate_chain_probability(chain)
    
    def add_conditional_path(self, chain: AttackChain, condition: str, path: List[ChainStep]):
        """Add conditional execution path"""
        conditional = ConditionalPath(
            condition=condition,
            path=path,
            description=f"Conditional path: {condition}"
        )
        chain.conditional_paths.append(conditional)
    
    def add_fallback(self, chain: AttackChain, technique: ChainStep, fallback: ChainStep):
        """Add fallback technique"""
        technique.fallback_steps.append(fallback.step_id)
    
    def generate_alternatives(self, chain: AttackChain) -> List[AttackChain]:
        """Generate alternative attack paths"""
        alternatives = []
        
        # Generate alternative for each stage
        for stage_type, steps in chain.stages.items():
            if len(steps) > 1:
                # Create alternative chain with different step
                alt_chain = AttackChain(
                    chain_id=f"{chain.chain_id}_alt_{stage_type.value}",
                    name=f"Alternative: {chain.name}",
                    description=f"Alternative path for {chain.name}",
                    stages=chain.stages.copy()
                )
                # Use different step for this stage
                alt_chain.stages[stage_type] = [steps[1]] if len(steps) > 1 else [steps[0]]
                alt_chain.overall_success_probability = self._calculate_chain_probability(alt_chain)
                alternatives.append(alt_chain)
        
        return alternatives
