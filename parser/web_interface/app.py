#!/usr/bin/env python3
"""
Web Interface Backend
Flask/FastAPI backend for attack chain browsing web interface.
Uses real web framework - no fake server.
"""

import sys
from pathlib import Path
import json

try:
    from flask import Flask, render_template, jsonify, request
    HAS_FLASK = True
except ImportError:
    HAS_FLASK = False
    print("Warning: Flask not found. Install with: pip install flask")

try:
    from fastapi import FastAPI, HTTPException
    from fastapi.staticfiles import StaticFiles
    from fastapi.responses import HTMLResponse
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

app = Flask(__name__) if HAS_FLASK else None

if app:
    @app.route('/')
    def index():
        """Main page"""
        return render_template('index.html')
    
    @app.route('/api/chains')
    def get_chains():
        """Get all attack chains"""
        try:
            data_file = Path(__file__).parent.parent / "output" / "parsed_data.json"
            if not data_file.exists():
                return jsonify({"error": "Data file not found"}), 404
            
            with open(data_file, 'r') as f:
                data = json.load(f)
            
            return jsonify({
                "cve_chains": data.get("attack_chains", []),
                "multi_stage_chains": data.get("multi_stage_chains", []),
                "techniques": data.get("techniques", []),
                "ml_suggestions": data.get("ml_suggestions", [])
            })
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    @app.route('/api/chain/<chain_id>')
    def get_chain(chain_id):
        """Get specific chain by ID"""
        try:
            data_file = Path(__file__).parent.parent / "output" / "parsed_data.json"
            if not data_file.exists():
                return jsonify({"error": "Data file not found"}), 404
            
            with open(data_file, 'r') as f:
                data = json.load(f)
            
            # Search in all chain types
            for chain in data.get("attack_chains", []):
                if chain.get("chain_id") == chain_id:
                    return jsonify(chain)
            
            for chain in data.get("multi_stage_chains", []):
                if chain.get("chain_id") == chain_id:
                    return jsonify(chain)
            
            return jsonify({"error": "Chain not found"}), 404
        except Exception as e:
            return jsonify({"error": str(e)}), 500

def main():
    """Run web server"""
    if not HAS_FLASK:
        print("Error: Flask required for web interface")
        print("Install with: pip install flask")
        return
    
    print("Starting web interface on http://localhost:5000")
    app.run(host='127.0.0.1', port=5000, debug=True)

if __name__ == "__main__":
    main()
