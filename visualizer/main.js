// Register fcose physics layout extension for nested graphs
cytoscape.use(cytoscapeFcose);

let cy;
let hiddenTypes = new Set(); // For legend toggles

document.addEventListener('DOMContentLoaded', () => {
    initCy();

    const searchInput = document.getElementById('search-input');
    searchInput.addEventListener('input', handleSearch);

    // Setup interactive legend
    document.querySelectorAll('.legend-item').forEach(item => {
        item.addEventListener('click', (e) => {
            const target = e.currentTarget;
            const typeAttr = target.getAttribute('data-type');
            const types = typeAttr ? typeAttr.split(',') : [];

            target.classList.toggle('disabled');
            if (target.classList.contains('disabled')) {
                types.forEach(type => hiddenTypes.add(type));
            } else {
                types.forEach(type => hiddenTypes.delete(type));
            }
            applyFilters();
        });
    });

    // Bypass DLP: Load static payload exported by test_codemaps.ts
    if (window.CODEMAP_DATA) {
        document.getElementById('welcome-text').style.display = 'none';
        loadGraphData(window.CODEMAP_DATA);
        document.getElementById('file-status').textContent = `Loaded ${window.CODEMAP_DATA.nodes.length} nodes, ${window.CODEMAP_DATA.edges.length} edges`;
    } else {
        document.getElementById('file-status').textContent = 'Error: data.js payload not found. Run test_codemaps.ts first.';
    }
});

function initCy() {
    cy = cytoscape({
        container: document.getElementById('cy'),
        elements: [],
        style: [
            {
                selector: 'node',
                style: {
                    'label': 'data(label)',
                    'color': '#f8fafc',
                    'text-valign': 'bottom',
                    'text-halign': 'center',
                    'text-margin-y': 6,
                    'text-background-color': 'rgba(15, 23, 42, 0.7)',
                    'text-background-opacity': 1,
                    'text-background-padding': '4px',
                    'text-background-shape': 'round-rectangle',
                    'font-family': 'Inter, sans-serif',
                    'font-size': '10px',
                    'font-weight': '500',
                    'background-color': '#64748b',
                    'width': 24,
                    'height': 24,
                    'border-width': 1,
                    'border-color': 'rgba(255,255,255,0.2)',
                    'transition-property': 'background-color, border-color, width, height, shadow-opacity',
                    'transition-duration': '0.3s'
                }
            },
            {
                selector: 'node[type="class"], node[type="interface"]',
                style: { 'background-color': '#f59e0b', 'shape': 'hexagon', 'width': 24, 'height': 24 }
            },
            {
                selector: 'node.compound-file',
                style: {
                    'background-color': '#334155', // Lighter visible color
                    'background-opacity': 0.6,
                    'border-width': 2,
                    'border-color': '#94a3b8', // Softer border
                    'border-style': 'solid',
                    'shape': 'round-rectangle',
                    'text-valign': 'top',
                    'text-halign': 'center',
                    'padding': 20,
                    'font-size': '16px',
                    'font-weight': '700',
                    'color': '#f8fafc',
                    'text-margin-y': -8
                }
            },
            {
                selector: 'node.cy-expand-collapse-collapsed-node',
                style: {
                    'background-color': '#475569', // Distinct slate for collapsed files
                    'background-opacity': 1,
                    'border-width': 2,
                    'border-color': '#38bdf8',
                    'shape': 'round-rectangle',
                    'text-valign': 'bottom',
                    'padding': 10
                }
            },
            {
                selector: 'node[type="function"], node[type="method"]',
                style: { 'background-color': '#10b981', 'shape': 'ellipse' }
            },
            {
                selector: 'node[type="function"]:parent, node[type="method"]:parent',
                style: {
                    'background-color': 'rgba(16, 185, 129, 0.15)', // Tinted green background
                    'border-color': '#10b981',
                    'border-width': 2,
                    'border-style': 'dashed',
                    'shape': 'round-rectangle',
                    'text-valign': 'top',
                    'text-halign': 'center',
                    'padding': 15,
                    'text-margin-y': -8,
                    'text-background-opacity': 0 // remove text bg for compound titles
                }
            },
            {
                selector: 'node[type="class"]:parent, node[type="interface"]:parent',
                style: {
                    'background-color': 'rgba(245, 158, 11, 0.15)', // Tinted orange background
                    'border-color': '#f59e0b',
                    'border-width': 2,
                    'border-style': 'dashed',
                    'shape': 'round-rectangle',
                    'text-valign': 'top',
                    'text-halign': 'center',
                    'padding': 15,
                    'text-margin-y': -8,
                    'text-background-opacity': 0 // remove text bg for compound titles
                }
            },
            {
                selector: 'node[type="variable"]',
                style: { 'background-color': '#8b5cf6', 'shape': 'round-rectangle', 'width': 20, 'height': 20, 'padding': 10 }
            },
            {
                selector: 'node[type="module"]',
                style: { 'background-color': '#ec4899', 'shape': 'diamond', 'width': 26, 'height': 26 }
            },
            {
                // VP Feature: Faint "on-demand" edges by default
                selector: 'edge',
                style: {
                    'width': 1.5,
                    'curve-style': 'bezier',
                    'target-arrow-shape': 'triangle',
                    'line-color': '#475569',
                    'target-arrow-color': '#475569',
                    'opacity': 0.05, // VERY DIM
                    'arrow-scale': 0.8,
                    'transition-property': 'opacity, width, line-color, target-arrow-color',
                    'transition-duration': '0.3s'
                }
            },
            {
                // VP Feature: Edge bundling via expand/collapse Meta-edges
                selector: 'edge.meta',
                style: {
                    'width': 3,
                    'line-color': '#94a3b8',
                    'target-arrow-color': '#94a3b8',
                    'opacity': 0.8,
                    'line-style': 'solid'
                }
            },
            {
                // GLOWING EFFECTS High-contrast aesthetic
                selector: 'node.highlighted',
                style: {
                    'border-width': 3,
                    'border-color': '#fff',
                    'shadow-blur': 20,
                    'shadow-color': '#38bdf8',
                    'shadow-opacity': 1,
                    'color': '#fff',
                    'font-weight': '700',
                    'font-size': '14px',
                    'width': 32,
                    'height': 32
                }
            },
            {
                selector: 'node.compound-file.highlighted',
                style: {
                    'border-color': '#38bdf8',
                    'background-color': 'rgba(56, 189, 248, 0.1)',
                }
            },
            {
                selector: 'edge.highlighted',
                style: {
                    'opacity': 1,
                    'width': 3,
                    'z-index': 999
                }
            },
            {
                selector: 'edge.highlighted[origType="calls"]',
                style: { 'line-color': '#38bdf8', 'target-arrow-color': '#38bdf8', 'line-style': 'dashed' }
            },
            {
                selector: 'edge.highlighted[origType="imports"]',
                style: { 'line-color': '#a78bfa', 'target-arrow-color': '#a78bfa', 'line-style': 'dotted' }
            },
            {
                selector: 'node.dimmed', style: { 'opacity': 0.1 }
            },
            {
                selector: 'edge.dimmed', style: { 'opacity': 0 }
            },
            {
                selector: '.hidden-node', style: { 'opacity': 0, 'events': 'no' }
            }
        ],
        layout: { name: 'preset' }
    });

    const api = cy.expandCollapse({
        layoutBy: {
            name: 'fcose',
            randomize: false,
            fit: true,
            animate: true,
            animationDuration: 1000
        },
        fisheye: true,
        animate: true,
        undoable: false,
        expandCollapseCuePosition: 'top-left',
        expandCollapseCueSize: 16,
        expandCollapseCueLineSize: 8,
        // Meta edges bundle automatically when children collapse
        createMissedEdges: true,
    });
    window.cyExpandCollapseApi = api;

    cy.on('tap', 'node', (evt) => {
        const node = evt.target;
        if (node.hasClass('cy-expand-collapse-collapsed-node')) return;

        showDetails(node.data());

        // Reset all
        cy.elements().removeClass('highlighted dimmed');
        cy.elements().addClass('dimmed');

        // Highlight node, its distinct edges, and immediate neighborhood
        node.removeClass('dimmed').addClass('highlighted');

        // If it's a compound node, make sure its children stay fully visible
        if (node.isParent()) {
            node.descendants().removeClass('dimmed').addClass('highlighted');
        }

        // If it's a child node, make sure ALL its parent containers stay visible
        if (node.isChild()) {
            node.ancestors().removeClass('dimmed').addClass('highlighted');
        }

        const connectedEdges = node.connectedEdges();
        connectedEdges.removeClass('dimmed').addClass('highlighted');
        const connectedNodes = connectedEdges.connectedNodes();
        connectedNodes.removeClass('dimmed').addClass('highlighted');
        connectedNodes.descendants().removeClass('dimmed').addClass('highlighted');
        connectedNodes.ancestors().removeClass('dimmed').addClass('highlighted');

        applyFilters();
    });

    cy.on('tap', (evt) => {
        if (evt.target === cy) {
            hideDetails();
            cy.elements().removeClass('highlighted dimmed');
            applyFilters();
        }
    });
}

function loadGraphData(data) {
    const elements = [];

    // First pass: Find all unique file paths to act as parent container nodes
    const filePaths = new Set();
    data.nodes.forEach(n => {
        if (n.type === 'file') {
            filePaths.add(n.id);
            // Smart Label Truncation: Force split the ID string regardless of n.name
            const sourceStr = n.name || n.id;
            const parts = sourceStr.split(/[\/\\]/);
            const cleanLabel = parts[parts.length - 1];

            elements.push({
                data: {
                    id: n.id,
                    label: cleanLabel,
                    name: cleanLabel,
                    type: n.type,
                    origType: n.type,
                    filePath: n.id,
                },
                classes: 'compound-file'
            });
        }
    });

    // Create a parent-child mapping using the structural 'contains' edges from the AST
    const parentMap = new Map();
    data.edges.forEach(e => {
        if (e.type === 'contains') {
            // target is the child, source is the parent scope
            parentMap.set(e.target, e.source);
        }
    });

    // Create a mapping to resolve relative internal module imports (e.g. './security') 
    // to their actual file equivalents (e.g. '.../security.ts')
    const internalModuleMap = new Map();
    data.nodes.forEach(n => {
        if (n.type === 'module') {
            const moduleName = n.name;
            // Internal modules typically use relative paths
            if (moduleName.startsWith('.') || moduleName.startsWith('/')) {
                const baseName = moduleName.split(/[\/\\]/).pop(); // e.g., 'security'
                console.log(`[DEBUG MAP] Inspecting module: ${moduleName}, baseName: ${baseName}`);

                // Greedy match to find a corresponding file path
                for (const filePath of filePaths) {
                    // Prevent matches against test files unless the import explicitly asks for it
                    if (filePath.endsWith('.test.ts') || filePath.endsWith('.test.js')) {
                        if (!baseName.includes('.test')) continue;
                    }

                    const parts = filePath.split(/[\/\\]/);
                    const fileName = parts[parts.length - 1]; // 'security.ts'

                    // Priority 1: Exact filename match (e.g. import './security.js' -> 'security.js')
                    if (fileName === baseName) {
                        internalModuleMap.set(n.id, filePath);
                        break;
                    }

                    // Priority 2: Base name match excluding extension (e.g. import './security' -> 'security.ts')
                    const fileBaseName = fileName.replace(/\.[^/.]+$/, ""); // Strip exact extension
                    if (fileBaseName === baseName) {
                        internalModuleMap.set(n.id, filePath);
                        break;
                    }
                }
            }
        }
    });

    // Second pass: Add actual nodes and assign them to their file parent
    data.nodes.forEach(n => {
        if (n.type === 'file') return; // Handled above

        // Skip adding the module node if it was successfully resolved to an actual file
        if (n.type === 'module' && internalModuleMap.has(n.id)) {
            return;
        }

        const filePathStr = n.id.split(':')[0];
        // Multi-level hierarchy: First try to use the direct structural parent from AST
        let parentId = parentMap.get(n.id);
        // Fallback to the file container if no structural parent exists
        if (!parentId) {
            parentId = filePaths.has(filePathStr) ? filePathStr : null;
        }

        // Truncate inner labels as well
        const nodeParts = n.id.split(/[:\/\\]/);
        const cleanLabel = nodeParts[nodeParts.length - 1];

        elements.push({
            data: {
                id: n.id,
                parent: parentId,
                label: cleanLabel,
                name: cleanLabel,
                type: n.type,
                origType: n.type,
                startLine: n.startLine,
                endLine: n.endLine,
                codeSnippet: n.codeSnippet,
                filePath: filePathStr
            }
        });
    });

    data.edges.forEach((e, i) => {
        // Reroute edges pointing to internal modules directly to the matched file nodes
        let targetId = e.target;
        if (internalModuleMap.has(targetId)) {
            targetId = internalModuleMap.get(targetId);
        }

        let sourceId = e.source;
        if (internalModuleMap.has(sourceId)) {
            sourceId = internalModuleMap.get(sourceId);
        }

        // Filter out redundant intra-file relationships
        // If a class 'contains' a method, and they are both in the same file,
        // the compound node nesting visually implies this connection. Drawing lines is redundant clutter.
        if (e.type === 'contains' || e.type === 'inherits') {
            const sourceFile = sourceId.split(':')[0];
            const targetFile = targetId.split(':')[0];
            if (sourceFile === targetFile) {
                return; // Skip adding this edge
            }
        }

        // Prevent self-loops from rerouting
        if (sourceId === targetId) {
            return;
        }

        elements.push({
            data: {
                id: `e${i}`,
                source: sourceId,
                target: targetId,
                type: e.type,
                origType: e.type
            }
        });
    });

    cy.elements().remove();
    cy.add(elements);

    const layout = cy.layout({
        name: 'fcose',
        randomize: true,
        animate: true,
        animationDuration: 1000,
        fit: true,
        padding: 50,
        nodeDimensionsIncludeLabels: true,
        uniformNodeDimensions: false,
        packComponents: true,
        nodeRepulsion: node => 4500, // Reverts to stronger repulsion for label clearance
        idealEdgeLength: edge => 200, // Longer edges
        edgeElasticity: edge => 0.45,
        nestingFactor: 1.2, // Pushes nodes much harder away from the borders of their containers
        gravity: 0.25,
        numIter: 2500,
        tile: true,
        tilingPaddingVertical: 60, // Much more space when tiling disconnected variables
        tilingPaddingHorizontal: 60
    });

    layout.promiseOn('layoutstop').then(() => {
        if (window.cyExpandCollapseApi) {
            window.cyExpandCollapseApi.collapseAll();
            cy.layout({
                name: 'fcose',
                randomize: false,
                animate: true,
                animationDuration: 1000,
                fit: true,
                padding: 50
            }).run();
        }
    });

    layout.run();
}

function applyFilters() {
    cy.elements().removeClass('filtered-out');

    // Instead of completely display:none (which breaks compound nodes and expand/collapse physics),
    // we use a hidden class that sets opacity to 0 and removes interactivity

    cy.elements().removeClass('hidden-node');

    if (hiddenTypes.size === 0) return;

    cy.elements().forEach(ele => {
        const type = ele.data('origType');
        if (hiddenTypes.has(type)) {
            ele.addClass('hidden-node');
        }
    });
}

function handleSearch(e) {
    const query = e.target.value.toLowerCase();

    cy.elements().removeClass('highlighted dimmed');

    if (query.trim() === '') {
        applyFilters();
        return;
    }

    cy.elements().addClass('dimmed');

    const matched = cy.nodes().filter(n => {
        return n.data('name') && n.data('name').toLowerCase().includes(query);
    });

    matched.removeClass('dimmed').addClass('highlighted');
}

function showDetails(data) {
    document.getElementById('details-title').textContent = data.label || data.name;
    document.getElementById('details-type').textContent = data.type || 'unknown';
    document.getElementById('details-file').textContent = data.filePath || 'globals';

    if (data.startLine && data.endLine) {
        document.getElementById('details-lines').textContent = `${data.startLine} - ${data.endLine}`;
    } else {
        document.getElementById('details-lines').textContent = `N/A`;
    }

    const snippetEl = document.getElementById('details-snippet');
    if (data.codeSnippet) {
        snippetEl.textContent = data.codeSnippet;
        snippetEl.style.display = 'block';
    } else {
        snippetEl.style.display = 'none';
    }

    document.getElementById('details-panel').classList.remove('hidden');
}

function hideDetails() {
    document.getElementById('details-panel').classList.add('hidden');
}
