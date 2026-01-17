#!/usr/bin/env python3
"""
Attack Chain Compiler for Debian Linux
Takes enumeration data from Windows enumerator and constructs sophisticated attack chains
ONLY RUNS ON DEBIAN - Checks OS compatibility before execution
"""

import sys
import json
import argparse
import platform
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field, asdict
import networkx as nx
from datetime import datetime

# Check if running on Debian
def check_debian():
    """Verify we're running on Debian"""
    try:
        # Check /etc/os-release for Debian
        if Path("/etc/os-release").exists():
            with open("/etc/os-release", 'r') as f:
                os_release = f.read()
                if "Debian" in os_release or "debian" in os_release.lower():
                    return True
        
        # Fallback: check platform
        if platform.system() == "Linux":
            result = subprocess.run(["lsb_release", "-is"], capture_output=True, text=True)
            if result.returncode == 0 and "Debian" in result.stdout:
                return True
        
        return False
    except Exception:
        return False

# Verify Debian before proceeding
if not check_debian():
    print("ERROR: This tool only runs on Debian Linux")
    print(f"Detected OS: {platform.system()} {platform.release()}")
    print("Please run this tool on a Debian system")
    sys.exit(1)

# Add parser directory to path (relative to ENUMERATOR root)
parser_path = Path(__file__).parent.parent / "parser"
if parser_path.exists():
    sys.path.insert(0, str(parser_path))
else:
    print("Warning: Parser directory not found at ../parser/. Some features may be limited.")
    print(f"  Expected path: {parser_path}")

# Import attack chain modules
try:
    from cve_chain_generator import CVEChainGenerator, AttackChain as CVEAttackChain
    from technique_pattern_matcher import TechniquePatternMatcher
    from multi_stage_chain_builder import MultiStageChainBuilder, AttackChain as MultiStageAttackChain
    from ml_chain_suggester import MLChainSuggester
    from mitre_mapper import MITREMapper
    from network_cve_correlator import NetworkCVECorrelator
    HAS_PARSER_MODULES = True
except ImportError as e:
    print(f"Warning: Some parser modules not available: {e}")
    HAS_PARSER_MODULES = False

@dataclass
class CompiledChain:
    """Compiled attack chain with all metadata"""
    chain_id: str
    name: str
    description: str
    source: str  # "cve", "technique", "multi_stage", "ml"
    steps: List[Dict[str, Any]]
    prerequisites: List[str] = field(default_factory=list)
    success_probability: float = 0.0
    confidence: float = 0.0
    mitre_techniques: List[str] = field(default_factory=list)
    cves: List[str] = field(default_factory=list)
    affected_hosts: List[str] = field(default_factory=list)
    execution_order: List[str] = field(default_factory=list)
    fallbacks: List[Dict[str, Any]] = field(default_factory=list)
    alternatives: List[str] = field(default_factory=list)
    estimated_time: str = ""
    risk_level: str = "medium"  # low, medium, high, critical

class AttackChainCompiler:
    """
    Compiles enumeration data into executable attack chains.
    Runs on Debian Linux to process Windows enumeration data.
    """
    
    def __init__(self, enumeration_data: Dict[str, Any]):
        """
        Initialize compiler with enumeration data.
        
        Args:
            enumeration_data: Parsed enumeration data from Windows enumerator
        """
        self.enumeration_data = enumeration_data
        self.compiled_chains: List[CompiledChain] = []
        self.chain_graph = nx.DiGraph()
        
    def compile(self) -> List[CompiledChain]:
        """
        Compile all attack chains from enumeration data.
        Returns optimized, executable attack chains.
        """
        print("[*] Compiling attack chains from enumeration data...")
        
        if not HAS_PARSER_MODULES:
            print("[-] Parser modules not available. Using basic compilation.")
            return self._compile_basic_chains()
        
        # Step 1: Generate CVE-based chains
        print("[*] Generating CVE-based attack chains...")
        cve_chains = self._compile_cve_chains()
        
        # Step 2: Match technique patterns
        print("[*] Matching attack technique patterns...")
        technique_chains = self._compile_technique_chains()
        
        # Step 3: Build multi-stage chains
        print("[*] Building multi-stage attack chains...")
        multi_stage_chains = self._compile_multi_stage_chains()
        
        # Step 4: Get ML suggestions
        print("[*] Generating ML-guided suggestions...")
        ml_chains = self._compile_ml_chains()
        
        # Step 5: Optimize and merge chains
        print("[*] Optimizing and merging chains...")
        self._optimize_chains(cve_chains + technique_chains + multi_stage_chains + ml_chains)
        
        # Step 6: Build execution graph
        print("[*] Building execution graph...")
        self._build_execution_graph()
        
        return self.compiled_chains
    
    def _compile_cve_chains(self) -> List[CompiledChain]:
        """Compile CVE-based attack chains"""
        chains = []
        
        try:
            cve_gen = CVEChainGenerator(self.enumeration_data)
            cve_attack_chains = cve_gen.generate_chains()
            
            for chain in cve_attack_chains:
                compiled = CompiledChain(
                    chain_id=f"cve_{chain.chain_id}",
                    name=chain.name,
                    description=chain.description,
                    source="cve",
                    steps=chain.steps,
                    success_probability=chain.success_probability,
                    confidence=chain.compatibility_score,
                    cves=chain.cves if hasattr(chain, 'cves') else [],
                    mitre_techniques=chain.mitre_techniques if hasattr(chain, 'mitre_techniques') else []
                )
                chains.append(compiled)
        except Exception as e:
            print(f"[-] Error compiling CVE chains: {e}")
        
        return chains
    
    def _compile_technique_chains(self) -> List[CompiledChain]:
        """Compile technique-based attack chains"""
        chains = []
        
        try:
            pattern_matcher = TechniquePatternMatcher()
            techniques = pattern_matcher.match_all_patterns(self.enumeration_data)
            
            # Group techniques by tool source
            techniques_by_tool = {}
            for tech in techniques:
                tool = tech.tool_source
                if tool not in techniques_by_tool:
                    techniques_by_tool[tool] = []
                techniques_by_tool[tool].append(tech)
            
            # Create chains from technique groups
            for tool, techs in techniques_by_tool.items():
                if len(techs) >= 2:  # Need at least 2 techniques for a chain
                    compiled = CompiledChain(
                        chain_id=f"tech_{tool.lower()}_{len(chains)}",
                        name=f"{tool} Attack Chain",
                        description=f"Attack chain using {tool} techniques",
                        source="technique",
                        steps=[{
                            "step_id": f"step_{i}",
                            "technique": tech.technique_id,
                            "name": tech.name,
                            "description": tech.description,
                            "mitre_id": tech.mitre_id,
                            "confidence": tech.confidence
                        } for i, tech in enumerate(techs)],
                        success_probability=sum(t.confidence for t in techs) / len(techs),
                        confidence=sum(t.confidence for t in techs) / len(techs),
                        mitre_techniques=[t.mitre_id for t in techs if t.mitre_id]
                    )
                    chains.append(compiled)
        except Exception as e:
            print(f"[-] Error compiling technique chains: {e}")
        
        return chains
    
    def _compile_multi_stage_chains(self) -> List[CompiledChain]:
        """Compile multi-stage attack chains"""
        chains = []
        
        try:
            builder = MultiStageChainBuilder(self.enumeration_data)
            multi_stage_chains = builder.build_chains()
            
            for chain in multi_stage_chains:
                # Convert stages to steps
                steps = []
                for stage_type, stage_steps in chain.stages.items():
                    for step in stage_steps:
                        steps.append({
                            "step_id": step.step_id,
                            "stage": stage_type.value,
                            "technique": step.technique,
                            "description": step.description,
                            "success_probability": step.success_probability,
                            "prerequisites": step.prerequisites
                        })
                
                compiled = CompiledChain(
                    chain_id=f"multi_{chain.chain_id}",
                    name=chain.name,
                    description=chain.description,
                    source="multi_stage",
                    steps=steps,
                    success_probability=chain.overall_success_probability,
                    confidence=chain.overall_success_probability
                )
                chains.append(compiled)
        except Exception as e:
            print(f"[-] Error compiling multi-stage chains: {e}")
        
        return chains
    
    def _compile_ml_chains(self) -> List[CompiledChain]:
        """Compile ML-guided attack chains"""
        chains = []
        
        try:
            ml_suggester = MLChainSuggester()
            if ml_suggester.is_available():
                context = {
                    "objective": "full_compromise",
                    "target": self.enumeration_data.get("system_info", {}).get("computer_name", "target")
                }
                ml_chains = ml_suggester.suggest_chains(self.enumeration_data, context)
                
                for chain in ml_chains:
                    compiled = CompiledChain(
                        chain_id=f"ml_{chain.chain_id}",
                        name=chain.name,
                        description=chain.description,
                        source="ml",
                        steps=chain.steps,
                        success_probability=chain.success_probability,
                        confidence=chain.confidence
                    )
                    chains.append(compiled)
        except Exception as e:
            print(f"[-] Error compiling ML chains: {e}")
        
        return chains
    
    def _optimize_chains(self, chains: List[CompiledChain]):
        """Optimize and merge chains"""
        # Sort by success probability
        chains.sort(key=lambda x: x.success_probability, reverse=True)
        
        # Calculate risk levels
        for chain in chains:
            if chain.success_probability >= 0.9:
                chain.risk_level = "critical"
            elif chain.success_probability >= 0.7:
                chain.risk_level = "high"
            elif chain.success_probability >= 0.5:
                chain.risk_level = "medium"
            else:
                chain.risk_level = "low"
        
        # Extract execution order
        for chain in chains:
            execution_order = []
            for step in chain.steps:
                if "step_id" in step:
                    execution_order.append(step["step_id"])
                elif "technique" in step:
                    execution_order.append(step["technique"])
            chain.execution_order = execution_order
        
        # Extract prerequisites
        for chain in chains:
            prerequisites = set()
            for step in chain.steps:
                if "prerequisites" in step:
                    prerequisites.update(step["prerequisites"])
            chain.prerequisites = list(prerequisites)
        
        self.compiled_chains = chains
    
    def _build_execution_graph(self):
        """Build graph representation of attack chains"""
        for chain in self.compiled_chains:
            self.chain_graph.add_node(chain.chain_id, data=chain)
            
            # Add step nodes and edges
            for i, step in enumerate(chain.steps):
                step_id = step.get("step_id", f"{chain.chain_id}_step_{i}")
                self.chain_graph.add_node(step_id, data=step)
                self.chain_graph.add_edge(chain.chain_id, step_id)
                
                # Add prerequisite edges
                if "prerequisites" in step:
                    for prereq in step["prerequisites"]:
                        self.chain_graph.add_edge(prereq, step_id)
    
    def _compile_basic_chains(self) -> List[CompiledChain]:
        """Basic chain compilation without parser modules"""
        chains = []
        
        # Extract CVEs from enumeration data
        network_cves = self.enumeration_data.get("network_cves", {})
        for cve_id, cve_info in list(network_cves.items())[:10]:
            if cve_info.get("cvss_score", 0) >= 7.0:
                chain = CompiledChain(
                    chain_id=f"basic_{cve_id}",
                    name=f"Attack Chain for {cve_id}",
                    description=f"Basic attack chain for {cve_id}",
                    source="cve",
                    steps=[
                        {
                            "step": 1,
                            "type": "reconnaissance",
                            "description": f"Identify {cve_id} vulnerability"
                        },
                        {
                            "step": 2,
                            "type": "exploitation",
                            "description": f"Exploit {cve_id}",
                            "cve": cve_id
                        }
                    ],
                    success_probability=0.7 if cve_info.get("exploit_available", False) else 0.5,
                    cves=[cve_id]
                )
                chains.append(chain)
        
        return chains
    
    def export(self, output_format: str = "json", output_file: Optional[str] = None) -> str:
        """
        Export compiled chains to file.
        
        Args:
            output_format: Export format ("json", "yaml", "markdown")
            output_file: Output file path (optional)
        
        Returns:
            Path to exported file
        """
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"compiled_chains_{timestamp}.{output_format}"
        
        output_path = Path(output_file)
        
        if output_format == "json":
            data = {
                "compiled_at": datetime.now().isoformat(),
                "source_data": {
                    "timestamp": self.enumeration_data.get("timestamp", ""),
                    "computer_name": self.enumeration_data.get("system_info", {}).get("computer_name", "")
                },
                "chains": [asdict(chain) for chain in self.compiled_chains],
                "statistics": {
                    "total_chains": len(self.compiled_chains),
                    "by_source": {
                        source: len([c for c in self.compiled_chains if c.source == source])
                        for source in ["cve", "technique", "multi_stage", "ml"]
                    },
                    "by_risk": {
                        risk: len([c for c in self.compiled_chains if c.risk_level == risk])
                        for risk in ["low", "medium", "high", "critical"]
                    }
                }
            }
            
            with open(output_path, 'w') as f:
                json.dump(data, f, indent=2)
        
        elif output_format == "markdown":
            with open(output_path, 'w') as f:
                f.write("# Compiled Attack Chains\n\n")
                f.write(f"Compiled at: {datetime.now().isoformat()}\n\n")
                f.write(f"Total chains: {len(self.compiled_chains)}\n\n")
                
                for chain in self.compiled_chains:
                    f.write(f"## {chain.name}\n\n")
                    f.write(f"**Chain ID:** {chain.chain_id}\n\n")
                    f.write(f"**Source:** {chain.source}\n\n")
                    f.write(f"**Description:** {chain.description}\n\n")
                    f.write(f"**Success Probability:** {chain.success_probability * 100:.1f}%\n\n")
                    f.write(f"**Risk Level:** {chain.risk_level}\n\n")
                    
                    if chain.cves:
                        f.write(f"**CVEs:** {', '.join(chain.cves)}\n\n")
                    
                    if chain.mitre_techniques:
                        f.write(f"**MITRE Techniques:** {', '.join(chain.mitre_techniques)}\n\n")
                    
                    f.write("### Steps\n\n")
                    for i, step in enumerate(chain.steps, 1):
                        f.write(f"{i}. {step.get('description', step.get('technique', 'Unknown step'))}\n")
                    
                    f.write("\n---\n\n")
        
        print(f"[+] Compiled chains exported to: {output_path}")
        return str(output_path)
    
    def generate_execution_plan(self, chain_id: str) -> Dict[str, Any]:
        """
        Generate detailed execution plan for a specific chain.
        
        Args:
            chain_id: ID of chain to generate plan for
        
        Returns:
            Execution plan dictionary
        """
        chain = next((c for c in self.compiled_chains if c.chain_id == chain_id), None)
        if not chain:
            return {"error": "Chain not found"}
        
        plan = {
            "chain_id": chain.chain_id,
            "name": chain.name,
            "estimated_time": self._estimate_execution_time(chain),
            "steps": [],
            "prerequisites": chain.prerequisites,
            "fallbacks": chain.fallbacks,
            "alternatives": chain.alternatives
        }
        
        for step in chain.steps:
            step_plan = {
                "step_id": step.get("step_id", ""),
                "description": step.get("description", ""),
                "technique": step.get("technique", ""),
                "commands": self._generate_step_commands(step),
                "expected_output": step.get("expected_output", ""),
                "success_criteria": step.get("success_criteria", "")
            }
            plan["steps"].append(step_plan)
        
        return plan
    
    def _estimate_execution_time(self, chain: CompiledChain) -> str:
        """Estimate execution time for chain"""
        step_count = len(chain.steps)
        estimated_minutes = step_count * 5  # 5 minutes per step average
        return f"{estimated_minutes} minutes"
    
    def _generate_step_commands(self, step: Dict[str, Any]) -> List[str]:
        """Generate commands for a step"""
        commands = []
        step_type = step.get("type", step.get("stage", ""))
        
        if step_type == "reconnaissance":
            commands.append("# Reconnaissance commands")
            commands.append("nmap -sV -sC <target>")
        elif step_type == "exploitation":
            if "cve" in step:
                commands.append(f"# Exploit {step['cve']}")
                commands.append(f"searchsploit {step['cve']}")
        elif step_type == "privilege_escalation":
            commands.append("# Privilege escalation commands")
            commands.append("whoami /priv")
        
        return commands

def main():
    parser = argparse.ArgumentParser(description="Attack Chain Compiler for Debian Linux")
    parser.add_argument("input_file", help="Path to enumeration data JSON file")
    parser.add_argument("-o", "--output", help="Output file path", default=None)
    parser.add_argument("-f", "--format", choices=["json", "markdown"], default="json", help="Output format")
    parser.add_argument("--chain-id", help="Generate execution plan for specific chain")
    
    args = parser.parse_args()
    
    # Load enumeration data
    print(f"[*] Loading enumeration data from: {args.input_file}")
    with open(args.input_file, 'r') as f:
        enumeration_data = json.load(f)
    
    # Compile chains
    compiler = AttackChainCompiler(enumeration_data)
    compiled_chains = compiler.compile()
    
    print(f"[+] Compiled {len(compiled_chains)} attack chains")
    
    # Generate execution plan if chain ID specified
    if args.chain_id:
        plan = compiler.generate_execution_plan(args.chain_id)
        print(json.dumps(plan, indent=2))
    else:
        # Export compiled chains
        output_file = compiler.export(args.format, args.output)
        print(f"[+] Chains exported to: {output_file}")

if __name__ == "__main__":
    main()
