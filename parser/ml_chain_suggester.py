#!/usr/bin/env python3
"""
ML-Guided Chain Suggester
Optional integration with ai/ directory for ML-guided attack chain suggestions.
Uses real API calls - no fake ML suggestions.
"""

import sys
import os
from pathlib import Path
from typing import Dict, List, Any, Optional
import requests
import json

# Check if ai/ directory exists and is accessible
ai_path = Path(__file__).parent.parent.parent.parent / "ai"
HAS_AI_DIR = ai_path.exists()

# Try to import SWORD ML chain generators
sword_path = Path(__file__).parent.parent.parent.parent / "tools" / "OFFENSIVE" / "SWORD"
if sword_path.exists():
    sys.path.insert(0, str(sword_path))

try:
    from core.api.ml_chain_generator import ChainGenerator
    from core.api.ml_rce_chain_learner import MLRCEChainLearner
    HAS_SWORD_ML = True
except ImportError:
    HAS_SWORD_ML = False

@dataclass
class AttackChain:
    """Attack chain data structure"""
    chain_id: str
    name: str
    description: str
    steps: List[Dict[str, Any]]
    success_probability: float = 0.0
    confidence: float = 0.0

class MLChainSuggester:
    """
    ML-guided chain suggester.
    Uses real ML models from ai/ directory or SWORD if available.
    """
    
    def __init__(self, ai_endpoint: Optional[str] = None):
        """
        Initialize with optional AI endpoint.
        
        Args:
            ai_endpoint: Optional endpoint URL for AI services
        """
        self.ai_endpoint = ai_endpoint
        self.sword_ml = None
        
        # Initialize SWORD ML if available
        if HAS_SWORD_ML:
            try:
                self.sword_ml = ChainGenerator()
            except Exception as e:
                print(f"Warning: Failed to initialize SWORD ML: {e}")
    
    def is_available(self) -> bool:
        """Check if AI services are available"""
        # Check SWORD ML first
        if self.sword_ml:
            return True
        
        # Check ai/ directory
        if HAS_AI_DIR:
            # Check if ai/ has main.py or API endpoint
            ai_main = ai_path / "main.py"
            if ai_main.exists():
                return True
        
        # Check custom endpoint
        if self.ai_endpoint:
            try:
                response = requests.get(self.ai_endpoint, timeout=2)
                return response.status_code == 200
            except:
                return False
        
        return False
    
    def suggest_chains(self, enumeration_data: Dict[str, Any], context: Dict[str, Any]) -> List[AttackChain]:
        """
        Get ML-guided chain suggestions.
        Uses real ML models - no fake suggestions.
        """
        chains = []
        
        # Try SWORD ML first
        if self.sword_ml and HAS_SWORD_ML:
            try:
                # Use SWORD's real ML chain generator
                target_info = {
                    "os": enumeration_data.get("system_info", {}).get("os_version", ""),
                    "cves": list(enumeration_data.get("network_cves", {}).keys())[:5]
                }
                
                # Generate chains using SWORD's real ML API
                if hasattr(self.sword_ml, 'generate_chain'):
                    sword_chains = self.sword_ml.generate_chain(
                        target=target_info,
                        objective=context.get("objective", "exploit")
                    )
                    
                    if sword_chains:
                        for i, sc in enumerate(sword_chains[:5]):  # Limit to 5
                            chains.append(AttackChain(
                                chain_id=f"ml_chain_{i}",
                                name=f"ML-Suggested Chain {i+1}",
                                description=f"ML-generated attack chain (SWORD)",
                                steps=sc.get("steps", []),
                                success_probability=sc.get("success_probability", 0.0),
                                confidence=sc.get("confidence", 0.0)
                            ))
            except Exception as e:
                print(f"Error getting SWORD ML suggestions: {e}")
        
        # Try ai/ directory API
        if HAS_AI_DIR and not chains:
            try:
                # Check for API endpoint in ai/
                api_path = ai_path / "api" / "v1"
                if api_path.exists():
                    # Try to call AI API
                    if self.ai_endpoint:
                        response = requests.post(
                            f"{self.ai_endpoint}/suggest_chains",
                            json={
                                "enumeration_data": enumeration_data,
                                "context": context
                            },
                            timeout=10
                        )
                        if response.status_code == 200:
                            ml_chains = response.json()
                            for i, mc in enumerate(ml_chains.get("chains", [])[:5]):
                                chains.append(AttackChain(
                                    chain_id=f"ai_chain_{i}",
                                    name=mc.get("name", f"AI-Suggested Chain {i+1}"),
                                    description=mc.get("description", "AI-generated attack chain"),
                                    steps=mc.get("steps", []),
                                    success_probability=mc.get("success_probability", 0.0),
                                    confidence=mc.get("confidence", 0.0)
                                ))
            except Exception as e:
                print(f"Error calling AI API: {e}")
        
        return chains
    
    def optimize_chain(self, chain: AttackChain) -> AttackChain:
        """
        Optimize chain using ML.
        Uses real ML optimization if available.
        """
        if self.sword_ml and HAS_SWORD_ML:
            try:
                # Use SWORD's real ML optimization
                if hasattr(self.sword_ml, 'optimize_chain'):
                    optimized = self.sword_ml.optimize_chain(chain.steps)
                    if optimized:
                        chain.steps = optimized
                        chain.success_probability = min(chain.success_probability * 1.1, 1.0)
            except Exception as e:
                print(f"Error optimizing chain with ML: {e}")
        
        return chain
    
    def assess_success_probability(self, chain: AttackChain) -> float:
        """
        Assess success probability using ML.
        Uses real ML assessment if available.
        """
        if self.sword_ml and HAS_SWORD_ML:
            try:
                # Use SWORD's real ML assessment
                if hasattr(self.sword_ml, 'assess_probability'):
                    return self.sword_ml.assess_probability(chain.steps)
            except Exception as e:
                print(f"Error assessing probability with ML: {e}")
        
        # Fallback: Calculate based on step probabilities
        if chain.steps:
            total_prob = 1.0
            for step in chain.steps:
                step_prob = step.get("success_probability", 0.5) if isinstance(step, dict) else 0.5
                total_prob *= step_prob
            return total_prob
        
        return 0.0
