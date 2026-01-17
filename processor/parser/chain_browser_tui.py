#!/usr/bin/env python3
"""
Chain Browser TUI
Rich textual user interface for browsing and exploring attack chains.
Uses real TUI libraries - no fake UI.
"""

import sys
from pathlib import Path
from typing import Dict, List, Any, Optional
import json

try:
    from rich.console import Console
    from rich.tree import Tree
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.prompt import Prompt, Confirm
    HAS_RICH = True
except ImportError:
    HAS_RICH = False
    print("Warning: rich library not found. Install with: pip install rich")

try:
    import textual
    from textual.app import App
    from textual.widgets import Tree as TextualTree, Header, Footer
    HAS_TEXTUAL = True
except ImportError:
    HAS_TEXTUAL = False

class ChainBrowserTUI:
    """
    Textual User Interface for browsing attack chains.
    Uses real TUI libraries for interactive browsing.
    """
    
    def __init__(self, chains_data: Dict[str, Any]):
        """
        Initialize with attack chains data.
        
        Args:
            chains_data: Dictionary containing attack chains, techniques, etc.
        """
        self.chains_data = chains_data
        self.console = Console() if HAS_RICH else None
    
    def browse(self):
        """Start interactive browsing session"""
        if not HAS_RICH:
            print("Error: rich library required for TUI")
            print("Install with: pip install rich")
            return
        
        while True:
            self.console.clear()
            self._show_main_menu()
            
            choice = Prompt.ask("\nSelect option", choices=["1", "2", "3", "4", "5", "q"], default="q")
            
            if choice == "q":
                break
            elif choice == "1":
                self._browse_cve_chains()
            elif choice == "2":
                self._browse_techniques()
            elif choice == "3":
                self._browse_multi_stage_chains()
            elif choice == "4":
                self._browse_ml_suggestions()
            elif choice == "5":
                self._search_chains()
    
    def _show_main_menu(self):
        """Display main menu"""
        menu = Panel.fit(
            "[bold cyan]Attack Chain Browser[/bold cyan]\n\n"
            "1. Browse CVE-based Chains\n"
            "2. Browse Techniques\n"
            "3. Browse Multi-Stage Chains\n"
            "4. Browse ML Suggestions\n"
            "5. Search Chains\n"
            "q. Quit",
            title="Main Menu"
        )
        self.console.print(menu)
    
    def _browse_cve_chains(self):
        """Browse CVE-based attack chains"""
        chains = self.chains_data.get("attack_chains", [])
        if not chains:
            self.console.print("[yellow]No CVE-based chains found[/yellow]")
            Prompt.ask("\nPress Enter to continue")
            return
        
        while True:
            self.console.clear()
            table = Table(title="CVE-Based Attack Chains")
            table.add_column("ID", style="cyan")
            table.add_column("Name", style="green")
            table.add_column("CVEs", style="yellow")
            table.add_column("Success Prob", style="magenta")
            table.add_column("Source", style="blue")
            
            for i, chain in enumerate(chains[:20]):  # Show first 20
                table.add_row(
                    str(i + 1),
                    chain.get("name", "Unknown"),
                    ", ".join(chain.get("cves", [])[:3]),
                    f"{chain.get('success_probability', 0):.2f}",
                    chain.get("source_tool", "UNKNOWN")
                )
            
            self.console.print(table)
            
            choice = Prompt.ask("\nSelect chain number (or 'b' to go back)", default="b")
            if choice == "b":
                break
            
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(chains):
                    self._show_chain_details(chains[idx])
            except ValueError:
                pass
    
    def _browse_techniques(self):
        """Browse discovered techniques"""
        techniques = self.chains_data.get("techniques", [])
        if not techniques:
            self.console.print("[yellow]No techniques found[/yellow]")
            Prompt.ask("\nPress Enter to continue")
            return
        
        while True:
            self.console.clear()
            table = Table(title="Discovered Attack Techniques")
            table.add_column("ID", style="cyan")
            table.add_column("Name", style="green")
            table.add_column("Tool", style="yellow")
            table.add_column("MITRE ID", style="magenta")
            table.add_column("Confidence", style="blue")
            
            for i, tech in enumerate(techniques[:30]):  # Show first 30
                table.add_row(
                    str(i + 1),
                    tech.get("name", "Unknown"),
                    tech.get("tool_source", "UNKNOWN"),
                    tech.get("mitre_id", "N/A"),
                    f"{tech.get('confidence', 0):.2f}"
                )
            
            self.console.print(table)
            
            choice = Prompt.ask("\nSelect technique number (or 'b' to go back)", default="b")
            if choice == "b":
                break
            
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(techniques):
                    self._show_technique_details(techniques[idx])
            except ValueError:
                pass
    
    def _browse_multi_stage_chains(self):
        """Browse multi-stage attack chains"""
        chains = self.chains_data.get("multi_stage_chains", [])
        if not chains:
            self.console.print("[yellow]No multi-stage chains found[/yellow]")
            Prompt.ask("\nPress Enter to continue")
            return
        
        while True:
            self.console.clear()
            tree = Tree("Multi-Stage Attack Chains")
            
            for chain in chains[:10]:  # Show first 10
                chain_node = tree.add(f"[green]{chain.get('name', 'Unknown')}[/green] (Prob: {chain.get('overall_success_probability', 0):.2f})")
                stages = chain.get("stages", {})
                for stage_name, steps in stages.items():
                    stage_node = chain_node.add(f"[yellow]{stage_name}[/yellow] ({len(steps)} steps)")
                    for step in steps[:5]:  # Show first 5 steps per stage
                        step_node = stage_node.add(f"[cyan]{step.get('technique', 'Unknown')}[/cyan]")
                        step_node.add(f"Prob: {step.get('success_probability', 0):.2f}")
            
            self.console.print(tree)
            
            choice = Prompt.ask("\nSelect chain number (or 'b' to go back)", default="b")
            if choice == "b":
                break
            
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(chains):
                    self._show_multi_stage_details(chains[idx])
            except ValueError:
                pass
    
    def _browse_ml_suggestions(self):
        """Browse ML-suggested chains"""
        ml_chains = self.chains_data.get("ml_suggestions", [])
        if not ml_chains:
            self.console.print("[yellow]No ML suggestions available[/yellow]")
            Prompt.ask("\nPress Enter to continue")
            return
        
        while True:
            self.console.clear()
            table = Table(title="ML-Suggested Attack Chains")
            table.add_column("ID", style="cyan")
            table.add_column("Name", style="green")
            table.add_column("Steps", style="yellow")
            table.add_column("Success Prob", style="magenta")
            table.add_column("Confidence", style="blue")
            
            for i, chain in enumerate(ml_chains[:20]):
                table.add_row(
                    str(i + 1),
                    chain.get("name", "Unknown"),
                    str(len(chain.get("steps", []))),
                    f"{chain.get('success_probability', 0):.2f}",
                    f"{chain.get('confidence', 0):.2f}"
                )
            
            self.console.print(table)
            
            choice = Prompt.ask("\nSelect chain number (or 'b' to go back)", default="b")
            if choice == "b":
                break
            
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(ml_chains):
                    self._show_chain_details(ml_chains[idx])
            except ValueError:
                pass
    
    def _search_chains(self):
        """Search chains by keyword"""
        search_term = Prompt.ask("Enter search term")
        if not search_term:
            return
        
        results = []
        
        # Search in CVE chains
        for chain in self.chains_data.get("attack_chains", []):
            if search_term.lower() in chain.get("name", "").lower() or \
               search_term.lower() in chain.get("description", "").lower():
                results.append(("CVE Chain", chain))
        
        # Search in techniques
        for tech in self.chains_data.get("techniques", []):
            if search_term.lower() in tech.get("name", "").lower():
                results.append(("Technique", tech))
        
        if not results:
            self.console.print(f"[yellow]No results found for '{search_term}'[/yellow]")
            Prompt.ask("\nPress Enter to continue")
            return
        
        self.console.print(f"\n[green]Found {len(results)} results:[/green]\n")
        for i, (result_type, result) in enumerate(results[:20]):
            self.console.print(f"{i+1}. [{result_type}] {result.get('name', 'Unknown')}")
        
        Prompt.ask("\nPress Enter to continue")
    
    def _show_chain_details(self, chain: Dict[str, Any]):
        """Show detailed information about a chain"""
        self.console.clear()
        
        content = f"""
[bold]Chain ID:[/bold] {chain.get('chain_id', 'N/A')}
[bold]Name:[/bold] {chain.get('name', 'N/A')}
[bold]Description:[/bold] {chain.get('description', 'N/A')}
[bold]Success Probability:[/bold] {chain.get('success_probability', 0):.2f}
[bold]Source Tool:[/bold] {chain.get('source_tool', 'N/A')}

[bold]Steps:[/bold]
"""
        for i, step in enumerate(chain.get("steps", [])[:10], 1):
            if isinstance(step, dict):
                content += f"{i}. {step.get('description', step.get('technique', 'Unknown'))}\n"
            else:
                content += f"{i}. {str(step)}\n"
        
        panel = Panel(content, title="Chain Details", expand=False)
        self.console.print(panel)
        Prompt.ask("\nPress Enter to continue")
    
    def _show_technique_details(self, tech: Dict[str, Any]):
        """Show detailed information about a technique"""
        self.console.clear()
        
        content = f"""
[bold]Technique ID:[/bold] {tech.get('technique_id', 'N/A')}
[bold]Name:[/bold] {tech.get('name', 'N/A')}
[bold]Tool Source:[/bold] {tech.get('tool_source', 'N/A')}
[bold]MITRE ID:[/bold] {tech.get('mitre_id', 'N/A')}
[bold]Confidence:[/bold] {tech.get('confidence', 0):.2f}
[bold]Description:[/bold] {tech.get('description', 'N/A')}

[bold]Evidence:[/bold]
"""
        for evidence in tech.get("evidence", [])[:10]:
            content += f"  - {evidence}\n"
        
        panel = Panel(content, title="Technique Details", expand=False)
        self.console.print(panel)
        Prompt.ask("\nPress Enter to continue")
    
    def _show_multi_stage_details(self, chain: Dict[str, Any]):
        """Show detailed information about a multi-stage chain"""
        self.console.clear()
        
        content = f"""
[bold]Chain ID:[/bold] {chain.get('chain_id', 'N/A')}
[bold]Name:[/bold] {chain.get('name', 'N/A')}
[bold]Description:[/bold] {chain.get('description', 'N/A')}
[bold]Overall Success Probability:[/bold] {chain.get('overall_success_probability', 0):.2f}

[bold]Stages:[/bold]
"""
        stages = chain.get("stages", {})
        for stage_name, steps in stages.items():
            content += f"\n[bold yellow]{stage_name}:[/bold yellow]\n"
            for i, step in enumerate(steps[:5], 1):
                content += f"  {i}. {step.get('technique', 'Unknown')} (Prob: {step.get('success_probability', 0):.2f})\n"
                content += f"     {step.get('description', '')}\n"
        
        panel = Panel(content, title="Multi-Stage Chain Details", expand=False)
        self.console.print(panel)
        Prompt.ask("\nPress Enter to continue")

def main():
    """Main entry point for TUI"""
    if len(sys.argv) < 2:
        print("Usage: python chain_browser_tui.py <parsed_data.json>")
        sys.exit(1)
    
    data_file = Path(sys.argv[1])
    if not data_file.exists():
        print(f"Error: File not found: {data_file}")
        sys.exit(1)
    
    with open(data_file, 'r') as f:
        chains_data = json.load(f)
    
    browser = ChainBrowserTUI(chains_data)
    browser.browse()

if __name__ == "__main__":
    main()
