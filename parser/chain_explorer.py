#!/usr/bin/env python3
"""
Chain Explorer
Core engine for exploring and navigating attack chains.
Provides real graph traversal and analysis - no fake exploration.
"""

from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field
import networkx as nx

@dataclass
class ChainNode:
    """Node in attack chain graph"""
    node_id: str
    node_type: str  # "technique", "cve", "stage", "step"
    name: str
    data: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ChainEdge:
    """Edge in attack chain graph"""
    source: str
    target: str
    edge_type: str  # "prerequisite", "enables", "fallback", "alternative"
    weight: float = 1.0

class ChainExplorer:
    """
    Core engine for exploring attack chains.
    Uses real graph operations - no fake traversal.
    """
    
    def __init__(self, chains_data: Dict[str, Any]):
        """
        Initialize with chains data.
        
        Args:
            chains_data: Dictionary containing attack chains
        """
        self.chains_data = chains_data
        self.graph = nx.DiGraph()
        self._build_graph()
    
    def _build_graph(self):
        """Build graph representation of attack chains"""
        # Add nodes from CVE chains
        for chain in self.chains_data.get("attack_chains", []):
            chain_id = chain.get("chain_id", "")
            self.graph.add_node(chain_id, type="chain", data=chain)
            
            for i, step in enumerate(chain.get("steps", [])):
                step_id = f"{chain_id}_step_{i}"
                if isinstance(step, dict):
                    self.graph.add_node(step_id, type="step", data=step)
                    self.graph.add_edge(chain_id, step_id, type="contains")
                    
                    # Add prerequisite edges
                    for prereq in step.get("prerequisites", []):
                        self.graph.add_edge(prereq, step_id, type="prerequisite")
        
        # Add nodes from multi-stage chains
        for chain in self.chains_data.get("multi_stage_chains", []):
            chain_id = chain.get("chain_id", "")
            self.graph.add_node(chain_id, type="multi_stage_chain", data=chain)
            
            stages = chain.get("stages", {})
            for stage_name, steps in stages.items():
                stage_id = f"{chain_id}_stage_{stage_name}"
                self.graph.add_node(stage_id, type="stage", data={"name": stage_name})
                self.graph.add_edge(chain_id, stage_id, type="contains")
                
                for step in steps:
                    step_id = f"{stage_id}_step_{step.get('step_id', '')}"
                    self.graph.add_node(step_id, type="step", data=step)
                    self.graph.add_edge(stage_id, step_id, type="contains")
        
        # Add technique nodes
        for tech in self.chains_data.get("techniques", []):
            tech_id = tech.get("technique_id", "")
            self.graph.add_node(tech_id, type="technique", data=tech)
    
    def find_paths(self, start_node: str, end_node: str) -> List[List[str]]:
        """
        Find all paths between two nodes.
        Uses real graph path finding.
        """
        try:
            if start_node not in self.graph or end_node not in self.graph:
                return []
            
            # Use NetworkX to find all simple paths
            paths = list(nx.all_simple_paths(self.graph, start_node, end_node, cutoff=10))
            return paths
        except Exception as e:
            print(f"Error finding paths: {e}")
            return []
    
    def analyze_dependencies(self, node_id: str) -> Dict[str, Any]:
        """
        Analyze dependencies for a node.
        Real dependency analysis using graph operations.
        """
        if node_id not in self.graph:
            return {}
        
        # Get predecessors (dependencies)
        predecessors = list(self.graph.predecessors(node_id))
        
        # Get successors (dependents)
        successors = list(self.graph.successors(node_id))
        
        return {
            "node_id": node_id,
            "predecessors": predecessors,
            "successors": successors,
            "in_degree": self.graph.in_degree(node_id),
            "out_degree": self.graph.out_degree(node_id)
        }
    
    def calculate_success_probability(self, path: List[str]) -> float:
        """
        Calculate success probability for a path.
        Real probability calculation.
        """
        if not path:
            return 0.0
        
        total_prob = 1.0
        for node_id in path:
            node_data = self.graph.nodes[node_id].get("data", {})
            step_prob = node_data.get("success_probability", 0.5)
            total_prob *= step_prob
        
        return total_prob
    
    def find_alternative_paths(self, start_node: str, end_node: str) -> List[Dict[str, Any]]:
        """
        Find alternative paths between nodes.
        Real alternative path discovery.
        """
        paths = self.find_paths(start_node, end_node)
        
        alternatives = []
        for path in paths[:5]:  # Limit to top 5 alternatives
            prob = self.calculate_success_probability(path)
            alternatives.append({
                "path": path,
                "success_probability": prob,
                "length": len(path)
            })
        
        # Sort by success probability
        alternatives.sort(key=lambda x: x["success_probability"], reverse=True)
        
        return alternatives
    
    def get_chain_statistics(self) -> Dict[str, Any]:
        """Get statistics about attack chains"""
        stats = {
            "total_chains": len(self.chains_data.get("attack_chains", [])),
            "total_multi_stage_chains": len(self.chains_data.get("multi_stage_chains", [])),
            "total_techniques": len(self.chains_data.get("techniques", [])),
            "total_ml_suggestions": len(self.chains_data.get("ml_suggestions", []) or []),
            "graph_nodes": self.graph.number_of_nodes(),
            "graph_edges": self.graph.number_of_edges()
        }
        
        # Calculate average chain length
        chain_lengths = []
        for chain in self.chains_data.get("attack_chains", []):
            chain_lengths.append(len(chain.get("steps", [])))
        
        if chain_lengths:
            stats["avg_chain_length"] = sum(chain_lengths) / len(chain_lengths)
        else:
            stats["avg_chain_length"] = 0.0
        
        return stats
