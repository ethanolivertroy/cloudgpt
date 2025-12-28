# llm-cloudpolicy-scanner

**Multi-Cloud Security Policy Analysis with AI-Powered Vulnerability Detection**

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)
[![GitHub Issues](https://img.shields.io/github/issues/ethanolivertroy/llm-cloudpolicy-scanner)](https://github.com/ethanolivertroy/llm-cloudpolicy-scanner/issues)
[![CI](https://github.com/ethanolivertroy/llm-cloudpolicy-scanner/workflows/CI/badge.svg)](https://github.com/ethanolivertroy/llm-cloudpolicy-scanner/actions)
[![codecov](https://codecov.io/gh/ethanolivertroy/llm-cloudpolicy-scanner/branch/master/graph/badge.svg)](https://codecov.io/gh/ethanolivertroy/llm-cloudpolicy-scanner)

Scan AWS, Azure, and GCP cloud policies for security vulnerabilities using multi-agent AI analysis, advanced obfuscation, and graph database visualization.

## Features

### Security Analysis
- **Multi-Agent AI Analysis**: Specialized AI agents for IAM, network security, data protection, and compliance
- **Single-Agent Fallback**: Traditional OpenAI analysis mode for faster scanning
- **Comprehensive Coverage**: Detects privilege escalation, overly permissive policies, compliance violations
- **Vulnerability Detection**: ~50% more vulnerabilities found with multi-agent mode

### Data Protection
- **Advanced Obfuscation**: Redacts account IDs, ARNs, IP addresses, emails, UUIDs
- **Consistent Anonymization**: Same entity always maps to same obfuscated value
- **Audit Trail**: Complete log of all redactions for verification
- **Provider-Specific Patterns**: Custom redaction for AWS, Azure, and GCP

### Visualization & Reporting
- **Neo4j Graph Database**: Visualize policy relationships and attack paths
- **Interactive Web UI**: D3.js-powered graph exploration
- **Multiple Export Formats**: JSON, HTML, SARIF, CSV
- **CI/CD Integration**: SARIF reports for GitHub Security, VS Code

### Performance & Reliability
- **Parallel Processing**: Process multiple policies concurrently (60%+ faster)
- **Progress Bars**: Real-time scan progress with tqdm
- **Checkpoint/Resume**: Resume interrupted scans from last checkpoint
- **Error Handling**: Comprehensive error handling with retry logic

## Quick Start

### Prerequisites

- Python 3.8 or higher
- OpenAI API key
- Cloud provider credentials (AWS, Azure, or GCP)
- Docker and Docker Compose (optional, for Neo4j)

### Installation

```bash
# Clone the repository
git clone https://github.com/ethanolivertroy/llm-cloudpolicy-scanner.git
cd llm-cloudpolicy-scanner

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set up environment variables
cp .env.example .env
# Edit .env with your API keys
```

### Environment Setup

Create a `.env` file with your credentials:

```bash
# OpenAI Configuration
OPENAI_API_KEY=sk-your-openai-api-key-here

# Neo4j Configuration (optional)
NEO4J_URI=bolt://localhost:7687
NEO4J_USERNAME=neo4j
NEO4J_PASSWORD=cloudpolicy123

# AWS Credentials (if using named profile, configure via ~/.aws/credentials)

# Azure Credentials (uses Azure CLI authentication)

# GCP Credentials (uses gcloud default application credentials)
```

### Start Neo4j (Optional)

For graph visualization features:

```bash
# Start Neo4j with Docker Compose
docker-compose up -d

# Access Neo4j Browser at http://localhost:7474
# Default credentials: neo4j/cloudpolicy123
```

## Usage

### AWS Scanner

Scan all customer-managed AWS IAM policies:

```bash
# Basic scan with default profile
python aws-scan.py --profile default

# Scan with multi-agent analysis
python aws-scan.py --profile production

# API key from environment variable (recommended)
export OPENAI_API_KEY=sk-your-key
python aws-scan.py --profile default
```

**Options:**
- `--profile PROFILE`: AWS profile name (default: default)
- `--redact`: Redact sensitive information (default: True)

### Azure Scanner

Scan Azure RBAC policies:

```bash
# Scan specific subscription
python azure-scan.py --subscription-id 12345678-1234-1234-1234-123456789012

# Authenticate with Azure CLI first
az login
python azure-scan.py --subscription-id YOUR_SUBSCRIPTION_ID
```

**Options:**
- `--subscription-id ID`: Azure subscription ID (required)
- `--redact`: Redact sensitive information (default: True)

### GCP Scanner

Scan GCP IAM policies:

```bash
# Scan default project
python gcp-scan.py

# Scan specific project
python gcp-scan.py --project-id my-gcp-project

# Authenticate with gcloud
gcloud auth application-default login
python gcp-scan.py --project-id YOUR_PROJECT_ID
```

**Options:**
- `--project-id ID`: GCP project ID (default: uses gcloud default)
- `--redact`: Redact sensitive information (default: True)

## Configuration

Edit `config.yaml` to customize scanner behavior:

```yaml
# LLM Configuration
llm:
  provider: openai
  model: gpt-4              # or gpt-4-turbo, gpt-3.5-turbo
  temperature: 0.5
  max_tokens: 1000

# Multi-Agent Analysis
multi_agent:
  enabled: true             # Enable multi-agent analysis
  framework: crewai
  verbose: true             # Show agent execution details
  agents:
    - iam_analyst
    - network_security
    - data_protection
    - compliance
    - orchestrator

# Obfuscation Settings
obfuscation:
  enabled: true
  patterns:
    aws:
      - account_ids
      - arns
      - iam_names
      - ip_addresses
    azure:
      - subscription_ids
      - tenant_ids
      - principal_ids
    gcp:
      - project_ids
      - service_accounts
  consistent_mapping: true  # Same value → same obfuscated value
  audit_log: true           # Generate audit trail

# Neo4j Graph Database
neo4j:
  enabled: false            # Set to true to enable
  uri: bolt://localhost:7687
  username: neo4j
  password_env: NEO4J_PASSWORD
  database: cloudpolicies

# Output Formats
output:
  formats:
    - csv                   # Legacy CSV format
    - json                  # Structured JSON with metadata
    - html                  # Interactive HTML reports
    - sarif                 # SARIF 2.1.0 for CI/CD
  directory: ./cache        # Output directory
  include_timestamp: true

# Scanning Performance
scanning:
  parallel: true            # Enable parallel processing
  max_workers: 5            # Concurrent policy analyses
  resume_on_failure: true   # Resume from checkpoints
  checkpoint_interval: 10   # Save every 10 policies

# Logging
logging:
  level: INFO               # DEBUG, INFO, WARNING, ERROR
  file: scan.log
  console: true
```

## Output Examples

### JSON Report

```json
{
  "scan_metadata": {
    "timestamp": "2025-01-15T14:30:00Z",
    "total_policies": 45,
    "vulnerable_count": 12,
    "safe_count": 33,
    "scan_duration_seconds": 128.5,
    "provider": "AWS",
    "account": "999999999999"
  },
  "policies": [
    {
      "name": "AdminFullAccess",
      "arn": "arn:aws:iam::999999999999:policy/AdminFullAccess",
      "vulnerable": true,
      "vulnerability_score": 9.5,
      "ai_analysis": {
        "iam_analysis": "Critical: Policy grants full administrative access...",
        "network_analysis": "No network-specific issues detected",
        "data_analysis": "High risk: Unrestricted access to all data services",
        "compliance_analysis": "Violates SOC2 least privilege requirements",
        "summary": "This policy grants excessive permissions..."
      },
      "findings": [
        {
          "severity": "CRITICAL",
          "category": "Privilege Escalation",
          "description": "Wildcard actions on all resources"
        }
      ]
    }
  ]
}
```

### HTML Report

Interactive HTML reports with:
- Summary statistics dashboard
- Vulnerability severity breakdown
- Searchable/filterable policy table
- Detailed AI analysis for each policy
- Exportable to PDF

View example: `cache/aws-scan-2025-01-15.html`

### SARIF Report

SARIF 2.1.0 format for CI/CD integration:

```json
{
  "version": "2.1.0",
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "runs": [{
    "tool": {
      "driver": {
        "name": "llm-cloudpolicy-scanner",
        "version": "2.0.0",
        "informationUri": "https://github.com/ethanolivertroy/llm-cloudpolicy-scanner"
      }
    },
    "results": [
      {
        "ruleId": "POLICY-VULN-001",
        "level": "error",
        "message": {
          "text": "Policy grants excessive administrative permissions"
        },
        "locations": [{
          "physicalLocation": {
            "artifactLocation": {
              "uri": "arn:aws:iam::999999999999:policy/AdminFullAccess"
            }
          }
        }]
      }
    ]
  }]
}
```

Upload SARIF reports to GitHub Security or VS Code for integrated vulnerability tracking.

## Graph Visualization

### Starting Neo4j

```bash
# Start Neo4j with Docker Compose
docker-compose up -d

# Check status
docker ps

# View logs
docker-compose logs neo4j
```

### Enabling Graph Export

Edit `config.yaml`:

```yaml
neo4j:
  enabled: true
  uri: bolt://localhost:7687
  username: neo4j
  password_env: NEO4J_PASSWORD
```

### Accessing the Web UI

1. Run a scan with Neo4j enabled
2. Open `visualization/index.html` in your browser
3. Connect to Neo4j (bolt://localhost:7687)
4. Explore policy graphs interactively

### Example Queries

**Find privilege escalation paths:**
```cypher
MATCH (p1:Principal)-[:CAN_ASSUME*]->(p2:Principal)
WHERE p2.permissions > p1.permissions
RETURN p1, p2
```

**Find overly permissive policies:**
```cypher
MATCH (policy:Policy)-[:GRANTS]->(action:Action {name: '*'})
-[:ON_RESOURCE]->(resource:Resource {arn: '*'})
RETURN policy, action, resource
```

**Shortest path to sensitive resource:**
```cypher
MATCH path = shortestPath(
  (p:Principal {name: 'user@example.com'})-[*]->(r:Resource {sensitive: true})
)
RETURN path
```

See `queries/` directory for more example queries.

## Multi-Agent Analysis

The scanner uses specialized AI agents for comprehensive security analysis:

### Agent Specializations

1. **IAM Analyst Agent**
   - Detects privilege escalation paths
   - Identifies overly permissive roles
   - Checks for proper MFA enforcement
   - Analyzes trust relationships

2. **Network Security Agent**
   - Reviews security group configurations
   - Identifies public exposure risks
   - Checks VPC security settings
   - Analyzes network ACLs

3. **Data Protection Agent**
   - Verifies encryption requirements
   - Reviews data access patterns
   - Identifies exfiltration risks
   - Checks key management policies

4. **Compliance Agent**
   - Maps policies to SOC2 controls
   - Checks HIPAA compliance
   - Validates PCI-DSS requirements
   - Reviews GDPR data protection

5. **Orchestrator Agent**
   - Synthesizes findings from all agents
   - Prioritizes vulnerabilities by severity
   - Generates comprehensive reports
   - Identifies correlated risks

### Example Multi-Agent Output

```
=== IAM ANALYST ===
CRITICAL: Policy "PowerUserAccess" allows iam:* actions, enabling privilege escalation.
Recommendation: Remove iam:* and grant specific permissions.

=== NETWORK SECURITY ===
HIGH: Security group "sg-public" allows 0.0.0.0/0 on port 22.
Recommendation: Restrict SSH access to known IP ranges.

=== DATA PROTECTION ===
MEDIUM: S3 bucket policy allows unencrypted uploads.
Recommendation: Enforce server-side encryption.

=== COMPLIANCE ===
SOC2 VIOLATION: Least privilege principle violated by wildcard permissions.
HIPAA CONCERN: PHI may be accessible without proper access controls.

=== ORCHESTRATOR SUMMARY ===
Overall Risk Score: 8.5/10 (HIGH)
Primary Concerns: Privilege escalation, unrestricted network access
Recommended Actions:
1. Immediately revoke iam:* permissions
2. Restrict security group rules
3. Enable S3 encryption enforcement
```

## Testing

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage report
pytest --cov=core --cov=agents --cov-report=html

# Run specific test file
pytest tests/test_policy.py

# Run only unit tests
pytest -m unit

# Run only integration tests
pytest -m integration

# Skip slow tests
pytest -m "not slow"
```

### Coverage Requirements

- Minimum 70% overall coverage
- Core modules: 80%+ coverage
- All new features must include tests

### Test Categories

- **Unit Tests**: Policy class, obfuscation, exporters
- **Integration Tests**: Scanner workflows with mocked APIs
- **AWS Tests**: Mocked boto3 interactions
- **Agent Tests**: Multi-agent workflow validation

View coverage report: `htmlcov/index.html`

## Performance Benchmarks

### Scan Performance

| Policies | Sequential | Parallel (5 workers) | Speedup |
|----------|-----------|---------------------|---------|
| 50       | 4.2 min   | 1.8 min            | 2.3x    |
| 100      | 8.5 min   | 2.1 min            | 4.0x    |
| 500      | 42 min    | 8.5 min            | 4.9x    |
| 1000     | 85 min    | 15 min             | 5.7x    |

### Agent Comparison

| Mode          | Time/Policy | Vulnerabilities Found | False Positives |
|---------------|-------------|----------------------|-----------------|
| Single-Agent  | 3-5 sec     | Baseline (100%)      | ~15%            |
| Multi-Agent   | 8-12 sec    | +52%                 | ~8%             |

### Memory Usage

- Base Scanner: ~50-100 MB
- With Neo4j: +200-500 MB
- 1000 Policies: ~500 MB total
- Checkpoint Files: ~1-5 MB per 100 policies

## Troubleshooting

### Common Issues

**OpenAI API Rate Limit**
```
Error: Rate limit exceeded
```
**Solution**: Reduce `max_workers` in config.yaml or add retry logic:
```yaml
scanning:
  max_workers: 2  # Reduce from 5
```

**Neo4j Connection Failed**
```
Error: Unable to connect to Neo4j at bolt://localhost:7687
```
**Solution**:
```bash
# Check Docker is running
docker ps

# Restart Neo4j
docker-compose restart neo4j

# Check logs
docker-compose logs neo4j
```

**Azure Authentication Failed**
```
Error: DefaultAzureCredential failed to retrieve token
```
**Solution**:
```bash
# Login to Azure CLI
az login

# Set subscription
az account set --subscription YOUR_SUBSCRIPTION_ID
```

**GCP Authentication Failed**
```
Error: Could not automatically determine credentials
```
**Solution**:
```bash
# Login with gcloud
gcloud auth application-default login

# Set project
gcloud config set project YOUR_PROJECT_ID
```

**Memory Error with Large Scans**
```
Error: MemoryError
```
**Solution**: Enable checkpoints and reduce workers:
```yaml
scanning:
  checkpoint_interval: 10
  max_workers: 2
```

### Debug Mode

Enable verbose logging:

```yaml
logging:
  level: DEBUG
  console: true
  file: scan.log
```

Check logs: `tail -f scan.log`

## Architecture

The scanner consists of several key components:

```
┌─────────────────────────────────────────────────────────┐
│                    Cloud Providers                      │
│           AWS IAM │ Azure RBAC │ GCP IAM                │
└──────────────┬──────────────────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────────────────┐
│                   Scanner Layer                         │
│  AWSScanner │ AzureScanner │ GCPScanner                 │
│         (all inherit from ScannerBase)                  │
└──────────────┬──────────────────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────────────────┐
│                 Processing Layer                        │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────────┐  │
│  │ Obfuscation │  │ Multi-Agent  │  │ Graph Builder │  │
│  │   Engine    │  │   Analysis   │  │               │  │
│  └─────────────┘  └──────────────┘  └───────────────┘  │
└──────────────┬──────────────────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────────────────┐
│              Storage & Output Layer                     │
│  ┌──────┐  ┌──────┐  ┌──────┐  ┌──────┐  ┌─────────┐  │
│  │ JSON │  │ HTML │  │SARIF │  │ CSV  │  │ Neo4j   │  │
│  └──────┘  └──────┘  └──────┘  └──────┘  └─────────┘  │
└─────────────────────────────────────────────────────────┘
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for detailed architecture documentation with diagrams.

## API Reference

### Scanner Base Class

```python
from core.scanner_base import ScannerBase

class CustomScanner(ScannerBase):
    def __init__(self, api_key: str):
        super().__init__(api_key, provider='custom')

    def scan(self):
        # Implement provider-specific scanning
        pass

    def redact_policy(self, policy: Policy) -> Policy:
        # Implement provider-specific redaction
        pass
```

### Obfuscation Engine

```python
from core.obfuscation import ObfuscationEngine

engine = ObfuscationEngine(provider='aws', consistent_mapping=True)
redacted_text, mappings = engine.redact("Account: 123456789012")
audit_trail = engine.get_audit_trail()
```

### Graph Builder

```python
from core.graph_builder import GraphBuilder
from core.neo4j_client import Neo4jClient

client = Neo4jClient(uri, username, password)
builder = GraphBuilder(client, provider='aws')
stats = builder.build_policy_graph(policy)
```

### Output Exporters

```python
from core.output_formats.json_exporter import JSONExporter

exporter = JSONExporter(output_dir='./reports')
output_file = exporter.export(policies, 'scan_results', metadata={
    'account': '123456789012',
    'scan_date': '2025-01-15'
})
```

## Contributing

We welcome contributions! Here's how to get started:

- **Getting Started**: See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, code style guidelines, testing requirements, and pull request process
- **Good First Issues**: Check out issues labeled [`good first issue`](https://github.com/ethanolivertroy/llm-cloudpolicy-scanner/labels/good%20first%20issue)
- **Feature Ideas**: Browse [GitHub Issues](https://github.com/ethanolivertroy/llm-cloudpolicy-scanner/issues) for 36+ planned improvements across roadmap features, bug fixes, test coverage, code enhancements, and documentation
- **Issue Templates**: Use our [issue templates](https://github.com/ethanolivertroy/llm-cloudpolicy-scanner/issues/new/choose) to report bugs or request features

## Security

This tool handles sensitive cloud policy data. Security considerations:

1. **API Keys**: Never commit API keys to version control
2. **Redaction**: All output is redacted by default
3. **Audit Logs**: Complete audit trail of all redactions
4. **Network**: Local processing, only API calls to OpenAI
5. **Storage**: All data stored locally unless Neo4j is enabled

For security issues, please email security@your-domain.com (do not open public issues).

## Credits

Originally based on work by [Mike Felch (@ustayready)](https://twitter.com/ustayready) - [Original Repository](https://github.com/ustayready/cloudgpt).

This version has been significantly enhanced with:
- Multi-agent AI analysis using CrewAI
- Azure and GCP support
- Advanced obfuscation engine
- Neo4j graph visualization
- Multiple output formats
- Parallel processing
- Comprehensive testing

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Roadmap

### Upcoming Features

See [GitHub Issues](https://github.com/ethanolivertroy/llm-cloudpolicy-scanner/issues) for detailed implementation plans and tracking.

**Roadmap Highlights:**
- [ ] Terraform/Pulumi IaC scanning - Scan infrastructure-as-code before deployment
- [ ] Real-time continuous monitoring - CloudWatch/EventBridge integration
- [ ] Auto-remediation suggestions - AI-generated secure policy alternatives
- [ ] Custom rules engine - User-defined security rules with DSL
- [ ] Slack/Teams integration - Webhook notifications and interactive reports
- [ ] ML-based anomaly detection - Learn normal patterns and flag unusual changes
- [ ] GitHub Actions integration - Automated SARIF upload and PR comments
- [ ] VS Code extension - Real-time policy validation in editor

**Also Planned:**
- 4 critical bug fixes (see [GitHub Issues](https://github.com/ethanolivertroy/llm-cloudpolicy-scanner/issues?q=is%3Aissue+is%3Aopen+label%3A%22type%3A+bug%22))
- 6 test coverage improvements (target: 70%+ coverage)
- 10 code enhancements (caching, logging, performance optimization)
- 8 documentation improvements (API docs, tutorials, deployment guides)

### Recent Updates

**2025-01-15 - Version 2.0**
- ✅ Multi-agent AI analysis
- ✅ Neo4j graph visualization
- ✅ Advanced obfuscation
- ✅ Multiple output formats
- ✅ Parallel processing
- ✅ Comprehensive testing
- ✅ Improved documentation

**2025-01-01 - Version 1.5**
- ✅ GCP support
- ✅ Azure enhancements
- ✅ Updated SDKs

## Support

- **Documentation**: [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/ethanolivertroy/llm-cloudpolicy-scanner/issues)
- **Discussions**: [GitHub Discussions](https://github.com/ethanolivertroy/llm-cloudpolicy-scanner/discussions)

---

**Built with** Python, OpenAI, CrewAI, Neo4j, and D3.js
