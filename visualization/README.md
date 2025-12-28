# Cloud Policy Graph Visualization

Interactive web-based visualization for exploring cloud policy graphs stored in Neo4j.

## Features

- **Real-time Connection**: Connect to your Neo4j database directly from the browser
- **Pre-built Queries**: One-click access to common security analysis queries
- **Custom Queries**: Run any Cypher query you want
- **Interactive Graph**: D3.js force-directed graph visualization with drag-and-drop nodes
- **Statistics Dashboard**: See database statistics at a glance
- **Vulnerability Highlighting**: Vulnerable policies shown in red

## Setup

### 1. Start Neo4j

Make sure Neo4j is running via Docker Compose:

```bash
docker-compose up -d
```

The Neo4j Browser will be available at http://localhost:7474

### 2. Run a Scan

Run any of the cloud scanners to populate the graph database:

```bash
# AWS
python aws-scan.py --profile your-profile

# Azure
python azure-scan.py --subscription-id your-subscription-id

# GCP
python gcp-scan.py --project-id your-project-id
```

### 3. Open the Visualization

Simply open `index.html` in your web browser:

```bash
# macOS
open visualization/index.html

# Linux
xdg-open visualization/index.html

# Windows
start visualization/index.html
```

Or use a local web server (recommended):

```bash
# Python 3
cd visualization
python -m http.server 8000

# Then open http://localhost:8000 in your browser
```

## Usage

### Connecting

1. Enter your Neo4j connection details:
   - **URI**: `bolt://localhost:7687` (default)
   - **Username**: `neo4j` (default)
   - **Password**: `cloudpolicy123` (from docker-compose.yml)

2. Click **Connect**

3. Once connected, statistics will load automatically

### Running Queries

#### Pre-built Queries

Click any of the query buttons:

- **All Policies**: Show all policies in the database
- **Vulnerable Policies**: Show only policies marked as vulnerable
- **Admin Access**: Show principals with admin-level permissions
- **Public Access**: Show publicly accessible resources
- **Wildcard Permissions**: Show policies with wildcard (*) permissions
- **Attack Paths**: Show potential attack paths from principals to resources

#### Custom Queries

1. Enter a Cypher query in the text area
2. Click **Run Custom Query**
3. Results will appear below and visualize in the graph

Example queries:

```cypher
// Find all AWS policies
MATCH (pol:Policy {provider: 'AWS'})
RETURN pol

// Find principals with most policies
MATCH (p:Principal)-[:HAS_POLICY]->(pol:Policy)
RETURN p.name, count(pol) as policy_count
ORDER BY policy_count DESC
LIMIT 10

// Find privilege escalation paths
MATCH path = (p:Principal)-[:HAS_POLICY*1..3]->(pol:Policy)
WHERE pol.vulnerable = true
RETURN path
```

### Graph Visualization

- **Nodes**: Colored by type
  - 🔵 Principal (blue)
  - 🟢 Resource (green)
  - 🟡 Action (yellow)
  - 🟣 Policy (purple)
  - 🔴 Vulnerable Policy (red)

- **Interactions**:
  - **Drag nodes**: Click and drag to reposition
  - **Hover**: See node details
  - **Force simulation**: Nodes repel each other and links pull them together

### Results Panel

- Shows raw query results as JSON
- Vulnerable policies highlighted with red border
- Scroll through all results

## Troubleshooting

### Connection Failed

1. Verify Neo4j is running: `docker ps | grep neo4j`
2. Check Neo4j logs: `docker logs cloudpolicy-neo4j`
3. Verify connection details match docker-compose.yml
4. Try connecting via Neo4j Browser first: http://localhost:7474

### No Data

1. Run a scanner to populate the database
2. Check if Neo4j is enabled in `config.yaml`:
   ```yaml
   neo4j:
     enabled: true
   ```
3. Verify `NEO4J_PASSWORD` is set in `.env` file

### CORS Issues

If you see CORS errors:

1. Use a local web server instead of opening the HTML file directly:
   ```bash
   cd visualization
   python -m http.server 8000
   ```

2. Open http://localhost:8000 in your browser

### Graph Not Rendering

1. Check browser console for JavaScript errors
2. Ensure you have a stable internet connection (D3.js and Neo4j driver load from CDN)
3. Try refreshing the page
4. Try a different browser (Chrome/Firefox recommended)

## Advanced Usage

### Query Templates

See the `../queries/` directory for more advanced Cypher query templates:

- `attack_paths.cypher`: Attack path analysis
- `privilege_escalation.cypher`: Privilege escalation detection
- `overly_permissive.cypher`: Overly permissive policy analysis

Copy queries from these files into the custom query box.

### Exporting Graphs

To export graph visualizations:

1. Run your query to render the graph
2. Right-click on the graph visualization
3. "Save image as..." or use browser screenshot tools
4. For programmatic export, use Neo4j's APOC library

### Neo4j Browser

For more advanced graph analysis, use Neo4j Browser at http://localhost:7474:

- Full Cypher query support
- Better graph rendering for large datasets
- Query profiling and performance analysis
- Data import/export capabilities

## Architecture

### Frontend Stack

- **HTML/CSS/JS**: Pure vanilla JavaScript (no build step required)
- **D3.js v7**: Force-directed graph visualization
- **Neo4j JavaScript Driver**: Direct browser-to-Neo4j connection

### Data Flow

```
Scanner (Python)
  ↓
  exports to
  ↓
Neo4j Database
  ↓
  queries via
  ↓
Web UI (JavaScript)
  ↓
  renders with
  ↓
D3.js Visualization
```

## Security Notes

- The web UI connects directly to Neo4j from the browser
- Credentials are sent over the connection (use HTTPS in production)
- For production use:
  - Use authentication
  - Enable SSL/TLS
  - Run behind a reverse proxy
  - Don't expose Neo4j directly to the internet

## License

Part of the llm-cloudpolicy-scanner project.
