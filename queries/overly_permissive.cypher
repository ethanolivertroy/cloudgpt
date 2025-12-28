// Overly Permissive Policy Analysis
// Find policies that grant excessive permissions

// 1. Find all policies marked as vulnerable
MATCH (pol:Policy {vulnerable: true})
RETURN pol.name, pol.provider, pol.ai_response
ORDER BY pol.name;

// 2. Find policies with wildcard actions on wildcard resources
MATCH (pol:Policy)-[:GRANTS]->(a:Action)-[:ON_RESOURCE]->(r:Resource)
WHERE (a.name CONTAINS '*' OR a.category = 'admin')
  AND (r.arn = '*' OR r.type = 'wildcard')
RETURN pol.name, pol.provider, a.name, r.arn
ORDER BY pol.provider, pol.name;

// 3. Find principals with full administrative access
MATCH (p:Principal)-[:HAS_POLICY]->(pol:Policy)-[:GRANTS]->(a:Action {name: '*:*'})
RETURN DISTINCT p.name, p.type, pol.name
ORDER BY p.type, p.name;

// 4. Find public-accessible resources
MATCH (p:Principal {type: 'public'})-[:HAS_POLICY]->(pol:Policy)-[:GRANTS]->(a:Action)-[:ON_RESOURCE]->(r:Resource)
RETURN r.name, r.type, r.arn, collect(DISTINCT a.name) as public_actions
ORDER BY r.type;

// 5. Find policies granting delete permissions on all resources
MATCH (pol:Policy)-[:GRANTS]->(a:Action)-[:ON_RESOURCE]->(r:Resource {arn: '*'})
WHERE a.category = 'delete'
RETURN pol.name, pol.provider, a.name
ORDER BY pol.name;

// 6. Find service accounts with more than 10 different permissions
MATCH (p:Principal)-[:HAS_POLICY]->(pol:Policy)-[:GRANTS]->(a:Action)
WHERE p.type IN ['service_account', 'serviceAccount', 'role']
WITH p, count(DISTINCT a) as action_count, collect(DISTINCT a.name)[..20] as actions
WHERE action_count > 10
RETURN p.name, p.type, action_count, actions
ORDER BY action_count DESC;

// 7. Find policies without any conditions or restrictions
// Note: This is simplified - real implementation would check for Condition blocks
MATCH (pol:Policy)
WHERE NOT (pol)-[:REQUIRES]->(:Condition)
RETURN pol.name, pol.provider
ORDER BY pol.provider, pol.name
LIMIT 100;

// 8. Find cross-account access without restrictions
MATCH (p:Principal)-[:HAS_POLICY]->(pol:Policy)-[:GRANTS]->(a:Action)-[:ON_RESOURCE]->(r:Resource)
WHERE r.arn CONTAINS 'arn:aws'
  AND NOT r.arn CONTAINS pol.account
RETURN p.name, pol.name, a.name, r.arn as external_resource
LIMIT 100;

// 9. Find resources accessible by more than 5 different principals
MATCH (p:Principal)-[:HAS_POLICY]->(pol:Policy)-[:GRANTS]->(a:Action)-[:ON_RESOURCE]->(r:Resource)
WITH r, count(DISTINCT p) as principal_count, collect(DISTINCT p.name) as principals
WHERE principal_count > 5
RETURN r.name, r.type, principal_count, principals
ORDER BY principal_count DESC
LIMIT 50;

// 10. Find write/delete access without MFA requirement
// Note: Simplified - real implementation would check Condition blocks for MFA
MATCH (pol:Policy)-[:GRANTS]->(a:Action)
WHERE a.category IN ['write', 'delete', 'admin']
  AND NOT EXISTS((pol)-[:REQUIRES]->(:Condition))
RETURN pol.name, pol.provider, count(DISTINCT a) as risky_actions
ORDER BY risky_actions DESC
LIMIT 50;

// 11. Find policies granting full S3/storage access
MATCH (pol:Policy)-[:GRANTS]->(a:Action)-[:ON_RESOURCE]->(r:Resource)
WHERE (a.name IN ['s3:*', 's3:GetObject', 's3:PutObject', 's3:DeleteObject']
       OR a.name CONTAINS 'storage')
  AND (r.arn = '*' OR r.type CONTAINS 'bucket' OR r.type CONTAINS 'storage')
RETURN pol.name, pol.provider, collect(DISTINCT a.name) as storage_permissions
ORDER BY pol.name;

// 12. Find all admin-category actions across the environment
MATCH (pol:Policy)-[:GRANTS]->(a:Action {category: 'admin'})
RETURN pol.provider, pol.name, collect(DISTINCT a.name) as admin_actions
ORDER BY pol.provider, size(admin_actions) DESC;

// 13. Find principals with both data access and key management permissions
// Dangerous combination: can access data and manage encryption keys
MATCH (p:Principal)-[:HAS_POLICY]->(pol1:Policy)-[:GRANTS]->(a1:Action)
WHERE a1.name CONTAINS 'kms:' OR a1.name CONTAINS 'key'
MATCH (p)-[:HAS_POLICY]->(pol2:Policy)-[:GRANTS]->(a2:Action)-[:ON_RESOURCE]->(r:Resource)
WHERE r.type IN ['s3:bucket', 'database', 'storage']
RETURN DISTINCT p.name,
  collect(DISTINCT a1.name)[..5] as key_permissions,
  collect(DISTINCT a2.name)[..5] as data_permissions
LIMIT 50;
