# Cypher Query Templates

This directory contains pre-built Cypher queries for analyzing cloud policy graphs in Neo4j.

## Query Files

### attack_paths.cypher
Find potential attack paths from principals to resources:
- Paths from specific principals to resources
- Paths to sensitive/vulnerable resources
- Shortest paths from public access
- Principals with admin-level access
- Resources accessible by multiple high-privilege paths
- Wildcard resource permissions
- Paths through vulnerable policies

### privilege_escalation.cypher
Identify privilege escalation opportunities:
- Role assumption chains
- IAM policy modification permissions
- Lambda/function + IAM combinations
- EC2 + PassRole combinations
- Permission boundary bypasses
- Service accounts with excessive permissions
- Cross-account escalation risks

### overly_permissive.cypher
Find overly permissive policies:
- Vulnerable policies
- Wildcard actions on wildcard resources
- Full administrative access
- Public-accessible resources
- Policies without conditions
- Cross-account access
- Write/delete without MFA
- Storage access patterns

## Usage

### Via Neo4j Browser
1. Open Neo4j Browser at http://localhost:7474
2. Copy and paste queries from these files
3. Replace parameter placeholders (e.g., `$principal_id`) with actual values
4. Run the query

### Via Python Code
```python
from core.neo4j_client import Neo4jClient

client = Neo4jClient(
    uri='bolt://localhost:7687',
    username='neo4j',
    password='your-password'
)

# Read query from file
with open('queries/attack_paths.cypher', 'r') as f:
    query = f.read().split(';')[0]  # Get first query

# Execute
results = client.execute_query(query, {'principal_id': 'some-principal-id'})
```

### Common Parameters

- `$principal_id` - Principal identifier (e.g., user ARN, service account email)
- `$resource_arn` - Resource ARN or identifier
- `$policy_id` - Policy identifier

## Query Patterns

### Find Relationships
```cypher
MATCH (p:Principal)-[r:HAS_POLICY]->(pol:Policy)
RETURN p, r, pol
```

### Find Paths
```cypher
MATCH path = (start)-[*1..5]->(end)
RETURN path
```

### Aggregation
```cypher
MATCH (p:Principal)-[:HAS_POLICY]->(pol:Policy)
RETURN p.name, count(pol) as policy_count
ORDER BY policy_count DESC
```

### Filtering
```cypher
MATCH (pol:Policy)
WHERE pol.vulnerable = true
RETURN pol
```

## Tips

1. **Limit Results**: Always use `LIMIT` for exploratory queries to avoid overwhelming results
2. **Index Performance**: Queries run faster on indexed properties (id, name, type, etc.)
3. **Path Depth**: Limit path searches with `*1..5` to avoid expensive queries
4. **Use EXPLAIN**: Prefix queries with `EXPLAIN` to see the query plan
5. **Use PROFILE**: Prefix with `PROFILE` to see actual execution stats

## Example Workflow

1. **Start Broad**: Run overly permissive queries to identify problem areas
2. **Drill Down**: Use attack path queries to understand specific vulnerabilities
3. **Escalation Analysis**: Check for privilege escalation opportunities
4. **Prioritize**: Focus on vulnerable policies and public access first
5. **Remediate**: Use findings to update policies and reduce attack surface
