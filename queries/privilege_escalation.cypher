// Privilege Escalation Analysis Queries
// Identify potential privilege escalation paths and permission chains

// 1. Find principals who can assume other principals (role assumption chains)
// This finds transitive privilege escalation opportunities
MATCH path = (p1:Principal)-[:CAN_ASSUME*1..5]->(p2:Principal)
WHERE p1 <> p2
RETURN path
LIMIT 100;

// 2. Find principals who can modify IAM policies
MATCH (p:Principal)-[:HAS_POLICY]->(pol:Policy)-[:GRANTS]->(a:Action)-[:ON_RESOURCE]->(r:Resource)
WHERE a.name IN [
  'iam:CreatePolicy',
  'iam:PutUserPolicy',
  'iam:PutRolePolicy',
  'iam:PutGroupPolicy',
  'iam:AttachUserPolicy',
  'iam:AttachRolePolicy',
  'iam:AttachGroupPolicy',
  'iam:UpdateAssumeRolePolicy'
]
RETURN DISTINCT p.name, p.type, collect(DISTINCT a.name) as dangerous_permissions
ORDER BY size(dangerous_permissions) DESC;

// 3. Find principals with permission to create or modify roles
MATCH (p:Principal)-[:HAS_POLICY]->(pol:Policy)-[:GRANTS]->(a:Action)
WHERE a.name IN [
  'iam:CreateRole',
  'iam:UpdateRole',
  'iam:PassRole',
  'sts:AssumeRole'
]
RETURN DISTINCT p.name, collect(DISTINCT a.name) as escalation_actions
ORDER BY size(escalation_actions) DESC;

// 4. Find principals with lambda/function execution + IAM modification
// Classic privilege escalation: create function with high-privilege role, execute it
MATCH (p:Principal)-[:HAS_POLICY]->(pol1:Policy)-[:GRANTS]->(a1:Action)
WHERE a1.name IN ['lambda:CreateFunction', 'lambda:UpdateFunctionCode']
MATCH (p)-[:HAS_POLICY]->(pol2:Policy)-[:GRANTS]->(a2:Action)
WHERE a2.name IN ['iam:PassRole', 'iam:CreateRole']
RETURN DISTINCT p.name,
  collect(DISTINCT a1.name) as lambda_permissions,
  collect(DISTINCT a2.name) as iam_permissions;

// 5. Find EC2 instances or compute resources with iam:PassRole
// Can launch instances with privileged roles
MATCH (p:Principal)-[:HAS_POLICY]->(pol:Policy)-[:GRANTS]->(a1:Action)
WHERE a1.name IN ['ec2:RunInstances', 'ec2:StartInstances']
MATCH (p)-[:HAS_POLICY]->(pol2:Policy)-[:GRANTS]->(a2:Action {name: 'iam:PassRole'})
RETURN DISTINCT p.name as potential_escalation_principal;

// 6. Find principals with SetDefaultPolicyVersion permission
// Can activate old policy versions with higher privileges
MATCH (p:Principal)-[:HAS_POLICY]->(pol:Policy)-[:GRANTS]->(a:Action {name: 'iam:SetDefaultPolicyVersion'})
RETURN p.name, p.type, pol.name;

// 7. Find permission boundaries that could be bypassed
MATCH (p:Principal)-[:HAS_POLICY]->(pol:Policy)-[:GRANTS]->(a:Action)
WHERE a.name IN [
  'iam:DeleteUserPermissionsBoundary',
  'iam:DeleteRolePermissionsBoundary',
  'iam:PutUserPermissionsBoundary',
  'iam:PutRolePermissionsBoundary'
]
RETURN p.name, collect(DISTINCT a.name) as boundary_manipulation;

// 8. Find principals with UpdateAssumeRolePolicy + PassRole
// Can modify who can assume roles and assign themselves
MATCH (p:Principal)-[:HAS_POLICY]->(pol1:Policy)-[:GRANTS]->(a1:Action {name: 'iam:UpdateAssumeRolePolicy'})
MATCH (p)-[:HAS_POLICY]->(pol2:Policy)-[:GRANTS]->(a2:Action {name: 'iam:PassRole'})
RETURN DISTINCT p.name as high_risk_principal;

// 9. Find service principals with excessive permissions
// Service accounts should have minimal permissions
MATCH (p:Principal)-[:HAS_POLICY]->(pol:Policy)-[:GRANTS]->(a:Action)
WHERE p.type IN ['service_account', 'serviceAccount']
  AND a.category IN ['admin', 'delete']
RETURN p.name, count(DISTINCT a) as excessive_permissions, collect(DISTINCT a.name)[..10] as sample_actions
ORDER BY excessive_permissions DESC
LIMIT 50;

// 10. Find cross-account privilege escalation risks
MATCH (p:Principal)-[:HAS_POLICY]->(pol:Policy)-[:GRANTS]->(a:Action)-[:ON_RESOURCE]->(r:Resource)
WHERE r.arn CONTAINS 'arn:aws:iam::'
  AND NOT r.arn CONTAINS pol.account
  AND a.name CONTAINS 'iam:'
RETURN p.name, pol.name, a.name, r.arn as cross_account_resource
LIMIT 50;
