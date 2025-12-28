// Cloud Policy Graph Visualization
// Neo4j + D3.js visualization

let driver = null;
let session = null;

// Predefined queries
const QUERIES = {
    'all-policies': `
        MATCH (n)
        RETURN n
        LIMIT 100
    `,
    'vulnerable': `
        MATCH (pol:Policy {vulnerable: true})
        OPTIONAL MATCH (p:Principal)-[:HAS_POLICY]->(pol)
        OPTIONAL MATCH (pol)-[:GRANTS]->(a:Action)
        OPTIONAL MATCH (a)-[:ON_RESOURCE]->(r:Resource)
        RETURN pol, p, a, r
        LIMIT 50
    `,
    'admin-access': `
        MATCH (p:Principal)-[:HAS_POLICY]->(pol:Policy)-[:GRANTS]->(a:Action)
        WHERE a.category = 'admin' OR a.name CONTAINS '*'
        RETURN p, pol, a
        LIMIT 50
    `,
    'public-access': `
        MATCH (p:Principal {type: 'public'})-[:HAS_POLICY]->(pol)-[:GRANTS]->(a)-[:ON_RESOURCE]->(r)
        RETURN p, pol, a, r
        LIMIT 50
    `,
    'wildcard': `
        MATCH (pol:Policy)-[:GRANTS]->(a:Action)-[:ON_RESOURCE]->(r:Resource)
        WHERE a.name CONTAINS '*' OR r.arn = '*'
        RETURN pol, a, r
        LIMIT 50
    `,
    'attack-paths': `
        MATCH path = (p:Principal)-[*1..3]->(r:Resource)
        RETURN path
        LIMIT 25
    `
};

// Connect to Neo4j
async function connectToNeo4j() {
    const uri = document.getElementById('neo4j-uri').value;
    const user = document.getElementById('neo4j-user').value;
    const password = document.getElementById('neo4j-password').value;

    try {
        if (driver) {
            await driver.close();
        }

        driver = neo4j.driver(uri, neo4j.auth.basic(user, password));
        session = driver.session();

        // Test connection
        await session.run('RETURN 1');

        updateConnectionStatus(true);
        await loadStatistics();
        showMessage('Connected to Neo4j successfully!', 'success');
    } catch (error) {
        updateConnectionStatus(false);
        showMessage(`Connection failed: ${error.message}`, 'error');
    }
}

function updateConnectionStatus(connected) {
    const status = document.getElementById('connection-status');
    status.textContent = connected ? '● Connected' : '● Disconnected';
    status.className = connected ? 'connected' : 'disconnected';
}

async function loadStatistics() {
    if (!session) return;

    try {
        // Get node counts
        const nodeStats = await session.run(`
            MATCH (n)
            RETURN
                count(n) as total_nodes,
                count(CASE WHEN n:Principal THEN 1 END) as principals,
                count(CASE WHEN n:Resource THEN 1 END) as resources,
                count(CASE WHEN n:Action THEN 1 END) as actions,
                count(CASE WHEN n:Policy THEN 1 END) as policies,
                count(CASE WHEN n:Policy AND n.vulnerable = true THEN 1 END) as vulnerable
        `);

        const stats = nodeStats.records[0].toObject();

        document.getElementById('stat-nodes').textContent = stats.total_nodes || 0;
        document.getElementById('stat-principals').textContent = stats.principals || 0;
        document.getElementById('stat-resources').textContent = stats.resources || 0;
        document.getElementById('stat-policies').textContent = stats.policies || 0;
        document.getElementById('stat-actions').textContent = stats.actions || 0;
        document.getElementById('stat-vulnerable').textContent = stats.vulnerable || 0;
    } catch (error) {
        console.error('Error loading statistics:', error);
    }
}

async function runQuery(query) {
    if (!session) {
        showMessage('Please connect to Neo4j first', 'error');
        return;
    }

    const resultsDiv = document.getElementById('results');
    resultsDiv.innerHTML = '<div class="loading">Running query...</div>';

    try {
        const result = await session.run(query);

        if (result.records.length === 0) {
            resultsDiv.innerHTML = '<div class="result-item">No results found</div>';
            clearGraph();
            return;
        }

        displayResults(result.records);
        visualizeGraph(result.records);

    } catch (error) {
        resultsDiv.innerHTML = `<div class="error">Query error: ${error.message}</div>`;
        console.error('Query error:', error);
    }
}

function displayResults(records) {
    const resultsDiv = document.getElementById('results');
    resultsDiv.innerHTML = '';

    records.forEach((record, index) => {
        const div = document.createElement('div');
        div.className = 'result-item';

        // Check if this is a policy and if it's vulnerable
        const values = record.toObject();
        const hasVulnerablePolicy = Object.values(values).some(v =>
            v && v.labels && v.labels.includes('Policy') && v.properties.vulnerable
        );

        if (hasVulnerablePolicy) {
            div.classList.add('vulnerable');
        }

        div.innerHTML = `
            <h3>Result ${index + 1}</h3>
            <pre>${JSON.stringify(record.toObject(), null, 2)}</pre>
        `;

        resultsDiv.appendChild(div);
    });
}

function visualizeGraph(records) {
    const graphContainer = document.getElementById('graph-container');
    graphContainer.innerHTML = '';

    const width = graphContainer.offsetWidth;
    const height = graphContainer.offsetHeight;

    // Extract nodes and links from records
    const nodesMap = new Map();
    const links = [];

    records.forEach(record => {
        record.forEach(value => {
            if (value && value.identity) {
                // It's a node
                const nodeId = value.identity.toString();
                if (!nodesMap.has(nodeId)) {
                    nodesMap.set(nodeId, {
                        id: nodeId,
                        labels: value.labels || [],
                        properties: value.properties || {},
                        ...value.properties
                    });
                }
            } else if (value && value.segments) {
                // It's a path
                value.segments.forEach(segment => {
                    const startId = segment.start.identity.toString();
                    const endId = segment.end.identity.toString();

                    if (!nodesMap.has(startId)) {
                        nodesMap.set(startId, {
                            id: startId,
                            labels: segment.start.labels || [],
                            properties: segment.start.properties || {},
                            ...segment.start.properties
                        });
                    }

                    if (!nodesMap.has(endId)) {
                        nodesMap.set(endId, {
                            id: endId,
                            labels: segment.end.labels || [],
                            properties: segment.end.properties || {},
                            ...segment.end.properties
                        });
                    }

                    links.push({
                        source: startId,
                        target: endId,
                        type: segment.relationship.type
                    });
                });
            }
        });
    });

    const nodes = Array.from(nodesMap.values());

    if (nodes.length === 0) {
        graphContainer.innerHTML = '<div class="loading">No graph data to visualize</div>';
        return;
    }

    // Create D3 force simulation
    const svg = d3.select(graphContainer)
        .append('svg')
        .attr('width', width)
        .attr('height', height);

    const simulation = d3.forceSimulation(nodes)
        .force('link', d3.forceLink(links).id(d => d.id).distance(100))
        .force('charge', d3.forceManyBody().strength(-300))
        .force('center', d3.forceCenter(width / 2, height / 2))
        .force('collision', d3.forceCollide().radius(30));

    // Draw links
    const link = svg.append('g')
        .selectAll('line')
        .data(links)
        .enter().append('line')
        .attr('class', 'link');

    // Draw nodes
    const node = svg.append('g')
        .selectAll('circle')
        .data(nodes)
        .enter().append('circle')
        .attr('class', d => {
            let classes = 'node ' + (d.labels[0] || 'Unknown');
            if (d.labels.includes('Policy') && d.vulnerable) {
                classes += ' vulnerable';
            }
            return classes;
        })
        .attr('r', 10)
        .call(d3.drag()
            .on('start', dragStarted)
            .on('drag', dragged)
            .on('end', dragEnded));

    // Add labels
    const label = svg.append('g')
        .selectAll('text')
        .data(nodes)
        .enter().append('text')
        .attr('class', 'node-label')
        .attr('dy', 20)
        .text(d => d.name || d.id || d.labels[0]);

    // Tooltip
    node.append('title')
        .text(d => `${d.labels[0]}: ${d.name || d.id}\n${JSON.stringify(d.properties, null, 2)}`);

    // Update positions
    simulation.on('tick', () => {
        link
            .attr('x1', d => d.source.x)
            .attr('y1', d => d.source.y)
            .attr('x2', d => d.target.x)
            .attr('y2', d => d.target.y);

        node
            .attr('cx', d => d.x)
            .attr('cy', d => d.y);

        label
            .attr('x', d => d.x)
            .attr('y', d => d.y);
    });

    function dragStarted(event, d) {
        if (!event.active) simulation.alphaTarget(0.3).restart();
        d.fx = d.x;
        d.fy = d.y;
    }

    function dragged(event, d) {
        d.fx = event.x;
        d.fy = event.y;
    }

    function dragEnded(event, d) {
        if (!event.active) simulation.alphaTarget(0);
        d.fx = null;
        d.fy = null;
    }
}

function clearGraph() {
    document.getElementById('graph-container').innerHTML = '<div class="loading">Run a query to visualize</div>';
}

function showMessage(message, type) {
    console.log(`[${type}] ${message}`);
    // You could add a toast notification here
}

// Event Listeners
document.getElementById('connect-btn').addEventListener('click', connectToNeo4j);

document.querySelectorAll('.query-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        const queryName = btn.getAttribute('data-query');
        const query = QUERIES[queryName];
        if (query) {
            document.getElementById('custom-cypher').value = query.trim();
            runQuery(query);
        }
    });
});

document.getElementById('run-query-btn').addEventListener('click', () => {
    const query = document.getElementById('custom-cypher').value;
    if (query) {
        runQuery(query);
    }
});

// Initialize
updateConnectionStatus(false);
clearGraph();
