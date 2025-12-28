// Attack Path Analysis Queries
// Find potential attack paths from principals to sensitive resources

// 1. Find all paths from a specific principal to any resource
// Usage: Replace $principal_id with actual principal ID
MATCH path = (p:Principal {id: $principal_id})-[*]->(r:Resource)
RETURN path
LIMIT 100;

// 2. Find paths to sensitive/vulnerable resources
MATCH path = (p:Principal)-[*]->(r:Resource)
WHERE r.type IN ['s3:bucket', 'database', 'secret']
RETURN path
LIMIT 100;

// 3. Find shortest path from public access to resources
MATCH path = shortestPath(
  (p:Principal {type: 'public'})-[*]->(r:Resource)
)
RETURN path
LIMIT 50;

// 4. Find all principals with admin-level access
MATCH (p:Principal)-[:HAS_POLICY]->(pol:Policy)-[:GRANTS]->(a:Action)
WHERE a.category = 'admin' OR a.name CONTAINS '*'
RETURN DISTINCT p.name, p.type, collect(DISTINCT a.name) as admin_actions
ORDER BY size(admin_actions) DESC;

// 5. Find resources accessible by multiple high-privilege paths
MATCH (p:Principal)-[:HAS_POLICY]->(pol:Policy)-[:GRANTS]->(a:Action)-[:ON_RESOURCE]->(r:Resource)
WHERE a.category IN ['admin', 'delete', 'write']
WITH r, count(DISTINCT p) as principal_count, collect(DISTINCT p.name) as principals
WHERE principal_count > 3
RETURN r.name, r.type, principal_count, principals
ORDER BY principal_count DESC;

// 6. Find wildcard resource permissions
MATCH (pol:Policy)-[:GRANTS]->(a:Action)-[:ON_RESOURCE]->(r:Resource {arn: '*'})
RETURN pol.name, a.name, r
LIMIT 100;

// 7. Find principals with both read and write access to same resource
MATCH (p:Principal)-[:HAS_POLICY]->(pol:Policy)-[:GRANTS]->(a_read:Action {category: 'read'})-[:ON_RESOURCE]->(r:Resource)
MATCH (p)-[:HAS_POLICY]->(pol2:Policy)-[:GRANTS]->(a_write:Action {category: 'write'})-[:ON_RESOURCE]->(r)
RETURN DISTINCT p.name, r.name, r.type
LIMIT 50;

// 8. Find all paths through vulnerable policies
MATCH path = (p:Principal)-[:HAS_POLICY]->(pol:Policy {vulnerable: true})-[:GRANTS]->(a:Action)-[:ON_RESOURCE]->(r:Resource)
RETURN path
LIMIT 100;
