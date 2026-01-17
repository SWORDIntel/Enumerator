/**
 * Chain Visualizer
 * Interactive visualization of attack chains using Cytoscape.js
 * Uses real graph visualization - no fake rendering.
 */

let cy = null;
let chainsData = null;

/**
 * Initialize Cytoscape visualization
 */
function initVisualization() {
    const container = document.getElementById('chain-visualization');
    if (!container) {
        console.error('Visualization container not found');
        return;
    }
    
    // Initialize Cytoscape with real graph data
    cy = cytoscape({
        container: container,
        elements: [],
        style: [
            {
                selector: 'node',
                style: {
                    'background-color': '#666',
                    'label': 'data(label)',
                    'width': 30,
                    'height': 30
                }
            },
            {
                selector: 'node[type="chain"]',
                style: {
                    'background-color': '#ff6b6b',
                    'width': 50,
                    'height': 50
                }
            },
            {
                selector: 'node[type="step"]',
                style: {
                    'background-color': '#4ecdc4',
                    'width': 40,
                    'height': 40
                }
            },
            {
                selector: 'node[type="technique"]',
                style: {
                    'background-color': '#95e1d3',
                    'width': 35,
                    'height': 35
                }
            },
            {
                selector: 'edge',
                style: {
                    'width': 2,
                    'line-color': '#ccc',
                    'target-arrow-color': '#ccc',
                    'target-arrow-shape': 'triangle',
                    'curve-style': 'bezier'
                }
            },
            {
                selector: 'edge[type="prerequisite"]',
                style: {
                    'line-color': '#ff6b6b',
                    'target-arrow-color': '#ff6b6b'
                }
            }
        ],
        layout: {
            name: 'dagre',
            rankDir: 'TB',
            spacingFactor: 1.5
        }
    });
    
    // Load chains and visualize
    loadChainsForVisualization();
}

/**
 * Load chains and build visualization graph
 */
function loadChainsForVisualization() {
    fetch('/api/chains')
        .then(response => response.json())
        .then(data => {
            chainsData = data;
            buildVisualizationGraph(data);
        })
        .catch(error => {
            console.error('Error loading chains for visualization:', error);
        });
}

/**
 * Build visualization graph from chains data
 */
function buildVisualizationGraph(data) {
    if (!cy) {
        initVisualization();
        return;
    }
    
    const elements = [];
    let nodeId = 0;
    
    // Add CVE chains
    data.cve_chains.forEach(chain => {
        const chainNodeId = `chain_${chain.chain_id}`;
        elements.push({
            data: {
                id: chainNodeId,
                label: chain.name,
                type: 'chain',
                chain_data: chain
            }
        });
        
        // Add steps
        chain.steps.forEach((step, index) => {
            const stepNodeId = `step_${chain.chain_id}_${index}`;
            elements.push({
                data: {
                    id: stepNodeId,
                    label: step.technique || step.description || `Step ${index + 1}`,
                    type: 'step',
                    step_data: step
                }
            });
            
            // Add edge from chain to step
            elements.push({
                data: {
                    id: `edge_${chainNodeId}_${stepNodeId}`,
                    source: chainNodeId,
                    target: stepNodeId,
                    type: 'contains'
                }
            });
            
            // Add prerequisite edges
            if (step.prerequisites) {
                step.prerequisites.forEach(prereq => {
                    elements.push({
                        data: {
                            id: `edge_prereq_${prereq}_${stepNodeId}`,
                            source: prereq,
                            target: stepNodeId,
                            type: 'prerequisite'
                        }
                    });
                });
            }
        });
    });
    
    // Add multi-stage chains
    data.multi_stage_chains.forEach(chain => {
        const chainNodeId = `ms_chain_${chain.chain_id}`;
        elements.push({
            data: {
                id: chainNodeId,
                label: chain.name,
                type: 'chain',
                chain_data: chain
            }
        });
        
        // Add stages
        Object.entries(chain.stages).forEach(([stageName, steps]) => {
            const stageNodeId = `stage_${chain.chain_id}_${stageName}`;
            elements.push({
                data: {
                    id: stageNodeId,
                    label: stageName,
                    type: 'stage',
                    stage_data: { name: stageName, steps: steps }
                }
            });
            
            elements.push({
                data: {
                    id: `edge_${chainNodeId}_${stageNodeId}`,
                    source: chainNodeId,
                    target: stageNodeId,
                    type: 'contains'
                }
            });
            
            // Add steps within stage
            steps.forEach((step, index) => {
                const stepNodeId = `step_${stageNodeId}_${index}`;
                elements.push({
                    data: {
                        id: stepNodeId,
                        label: step.technique || step.description || `Step ${index + 1}`,
                        type: 'step',
                        step_data: step
                    }
                });
                
                elements.push({
                    data: {
                        id: `edge_${stageNodeId}_${stepNodeId}`,
                        source: stageNodeId,
                        target: stepNodeId,
                        type: 'contains'
                    }
                });
            });
        });
    });
    
    // Add techniques as nodes
    data.techniques.forEach(tech => {
        const techNodeId = `tech_${tech.technique_id}`;
        elements.push({
            data: {
                id: techNodeId,
                label: tech.name,
                type: 'technique',
                tech_data: tech
            }
        });
    });
    
    // Load elements into Cytoscape
    cy.elements().remove();
    cy.add(elements);
    
    // Apply layout
    cy.layout({
        name: 'dagre',
        rankDir: 'TB',
        spacingFactor: 1.5
    }).run();
    
    // Add click handlers
    cy.on('tap', 'node', function(evt) {
        const node = evt.target;
        const nodeData = node.data();
        showNodeDetails(nodeData);
    });
}

/**
 * Show details for a node
 */
function showNodeDetails(nodeData) {
    const modal = document.getElementById('chain-details-modal');
    const detailsDiv = document.getElementById('chain-details');
    
    if (!modal || !detailsDiv) {
        return;
    }
    
    let html = '<h2>' + nodeData.label + '</h2>';
    html += '<p><strong>Type:</strong> ' + nodeData.type + '</p>';
    
    if (nodeData.chain_data) {
        html += '<h3>Chain Information</h3>';
        html += '<p><strong>Description:</strong> ' + (nodeData.chain_data.description || 'N/A') + '</p>';
        html += '<p><strong>Success Probability:</strong> ' + ((nodeData.chain_data.success_probability || 0) * 100).toFixed(1) + '%</p>';
        if (nodeData.chain_data.cves) {
            html += '<p><strong>CVEs:</strong> ' + nodeData.chain_data.cves.join(', ') + '</p>';
        }
    }
    
    if (nodeData.step_data) {
        html += '<h3>Step Information</h3>';
        html += '<p><strong>Description:</strong> ' + (nodeData.step_data.description || 'N/A') + '</p>';
        html += '<p><strong>Technique:</strong> ' + (nodeData.step_data.technique || 'N/A') + '</p>';
        html += '<p><strong>Success Probability:</strong> ' + ((nodeData.step_data.success_probability || 0) * 100).toFixed(1) + '%</p>';
    }
    
    if (nodeData.tech_data) {
        html += '<h3>Technique Information</h3>';
        html += '<p><strong>Tool Source:</strong> ' + (nodeData.tech_data.tool_source || 'N/A') + '</p>';
        html += '<p><strong>MITRE ID:</strong> ' + (nodeData.tech_data.mitre_id || 'N/A') + '</p>';
        html += '<p><strong>Confidence:</strong> ' + ((nodeData.tech_data.confidence || 0) * 100).toFixed(1) + '%</p>';
    }
    
    detailsDiv.innerHTML = html;
    modal.style.display = 'block';
}

/**
 * Close modal
 */
function closeModal() {
    const modal = document.getElementById('chain-details-modal');
    if (modal) {
        modal.style.display = 'none';
    }
}

/**
 * Filter visualization by chain type
 */
function filterVisualization(filterType) {
    if (!cy) {
        return;
    }
    
    cy.elements().forEach(ele => {
        if (filterType === 'all') {
            ele.style('display', 'element');
        } else {
            const nodeType = ele.data('type');
            if (nodeType === filterType || ele.connectedEdges().some(e => e.source().data('type') === filterType || e.target().data('type') === filterType)) {
                ele.style('display', 'element');
            } else {
                ele.style('display', 'none');
            }
        }
    });
}

// Initialize on page load
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initVisualization);
} else {
    initVisualization();
}
