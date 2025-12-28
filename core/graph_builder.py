"""
Graph Builder for Cloud Policies
Parses cloud policies and constructs graph representations for Neo4j.
"""

import json
import logging
import re
from typing import Dict, List, Any, Optional, Tuple
from core.neo4j_client import Neo4jClient
from core.policy import Policy


class GraphBuilder:
    """
    Builds graph representations of cloud policies for Neo4j.

    Creates nodes and relationships representing:
    - Principals (users, roles, service accounts)
    - Resources (S3 buckets, VMs, databases, etc.)
    - Actions (permissions/operations)
    - Policies (the policy documents themselves)
    - Relationships (who can do what to which resources)
    """

    def __init__(self, neo4j_client: Neo4jClient, provider: str):
        """
        Initialize graph builder.

        Args:
            neo4j_client: Neo4j client instance
            provider: Cloud provider (aws, azure, gcp)
        """
        self.client = neo4j_client
        self.provider = provider.lower()
        self.logger = logging.getLogger(self.__class__.__name__)

    def build_policy_graph(self, policy: Policy) -> Dict[str, int]:
        """
        Build graph representation of a policy.

        Args:
            policy: Policy object to convert to graph

        Returns:
            Statistics about nodes and relationships created
        """
        stats = {
            'principals': 0,
            'resources': 0,
            'actions': 0,
            'policies': 0,
            'relationships': 0
        }

        try:
            # Parse policy document
            policy_doc = self._parse_policy_document(policy)

            if self.provider == 'aws':
                stats = self._build_aws_graph(policy, policy_doc)
            elif self.provider == 'azure':
                stats = self._build_azure_graph(policy, policy_doc)
            elif self.provider == 'gcp':
                stats = self._build_gcp_graph(policy, policy_doc)
            else:
                self.logger.warning(f"Unknown provider: {self.provider}")

        except Exception as e:
            self.logger.error(f"Error building graph for policy {policy.name}: {str(e)}")

        return stats

    def _parse_policy_document(self, policy: Policy) -> Dict[str, Any]:
        """
        Parse policy document into dictionary.

        Args:
            policy: Policy object

        Returns:
            Parsed policy document
        """
        try:
            # Try to parse as JSON if it's a string
            if isinstance(policy.policy, str):
                return json.loads(policy.policy)
            elif isinstance(policy.policy, dict):
                return policy.policy
            else:
                # Convert to string and parse
                policy_str = str(policy.policy)
                return json.loads(policy_str)
        except json.JSONDecodeError:
            self.logger.warning(f"Failed to parse policy document for {policy.name}")
            return {}

    def _build_aws_graph(self, policy: Policy, policy_doc: Dict[str, Any]) -> Dict[str, int]:
        """
        Build graph for AWS IAM policy.

        Args:
            policy: Policy object
            policy_doc: Parsed policy document

        Returns:
            Statistics about created nodes/relationships
        """
        stats = {'principals': 0, 'resources': 0, 'actions': 0, 'policies': 1, 'relationships': 0}

        # Create policy node
        policy_id = policy.arn if hasattr(policy, 'arn') else f"aws-policy-{policy.name}"
        self.client.create_policy(
            policy_id=policy_id,
            policy_name=policy.name,
            cloud_provider='AWS',
            vulnerable=policy.is_vulnerable(),
            properties={
                'account': getattr(policy, 'account', 'unknown'),
                'arn': getattr(policy, 'arn', ''),
                'version': getattr(policy, 'version', ''),
                'ai_response': policy.ai_response or '',
                'redacted_document': policy.redacted_document or ''
            }
        )

        # Parse statements
        statements = policy_doc.get('Statement', [])
        if not isinstance(statements, list):
            statements = [statements]

        for stmt in statements:
            effect = stmt.get('Effect', 'Allow')

            # Extract principals
            principals = self._extract_aws_principals(stmt)
            for principal in principals:
                self.client.create_principal(
                    principal_id=principal['id'],
                    principal_type=principal['type'],
                    name=principal['name'],
                    properties={'provider': 'AWS'}
                )
                stats['principals'] += 1

                # Link principal to policy
                self.client.create_relationship(
                    from_id=principal['id'],
                    from_label='Principal',
                    to_id=policy_id,
                    to_label='Policy',
                    relationship_type='HAS_POLICY',
                    properties={'effect': effect}
                )
                stats['relationships'] += 1

            # Extract actions
            actions = self._extract_aws_actions(stmt)
            for action in actions:
                category = self._categorize_action(action)
                self.client.create_action(
                    action_name=action,
                    category=category,
                    properties={'provider': 'AWS'}
                )
                stats['actions'] += 1

                # Link policy to action
                self.client.create_relationship(
                    from_id=policy_id,
                    from_label='Policy',
                    to_id=action,
                    to_label='Action',
                    relationship_type='GRANTS',
                    properties={'effect': effect}
                )
                stats['relationships'] += 1

            # Extract resources
            resources = self._extract_aws_resources(stmt)
            for resource in resources:
                resource_type = self._extract_resource_type_from_arn(resource)
                resource_name = self._extract_resource_name_from_arn(resource)

                self.client.create_resource(
                    arn=resource,
                    resource_type=resource_type,
                    name=resource_name,
                    properties={'provider': 'AWS'}
                )
                stats['resources'] += 1

                # Link action to resource
                for action in actions:
                    self.client.create_relationship(
                        from_id=action,
                        from_label='Action',
                        to_id=resource,
                        to_label='Resource',
                        relationship_type='ON_RESOURCE',
                        properties={'effect': effect}
                    )
                    stats['relationships'] += 1

        return stats

    def _build_azure_graph(self, policy: Policy, policy_doc: Dict[str, Any]) -> Dict[str, int]:
        """
        Build graph for Azure policy.

        Args:
            policy: Policy object
            policy_doc: Parsed policy document

        Returns:
            Statistics about created nodes/relationships
        """
        stats = {'principals': 0, 'resources': 0, 'actions': 0, 'policies': 1, 'relationships': 0}

        # Create policy node
        policy_id = getattr(policy, 'id', f"azure-policy-{policy.name}")
        self.client.create_policy(
            policy_id=policy_id,
            policy_name=policy.name,
            cloud_provider='Azure',
            vulnerable=policy.is_vulnerable(),
            properties={
                'subscription_id': getattr(policy, 'subscription_id', 'unknown'),
                'resource_group': getattr(policy, 'resource_group', ''),
                'ai_response': policy.ai_response or '',
                'redacted_document': policy.redacted_document or ''
            }
        )

        # Azure policies have different structure - extract what we can
        # This is a simplified extraction; real-world would be more complex
        if 'then' in policy_doc:
            effect = policy_doc['then'].get('effect', 'Allow')

            # Create a generic principal for Azure policies
            principal_id = f"azure-subscription-{getattr(policy, 'subscription_id', 'unknown')}"
            self.client.create_principal(
                principal_id=principal_id,
                principal_type='subscription',
                name=f"Subscription {getattr(policy, 'subscription_id', 'unknown')}",
                properties={'provider': 'Azure'}
            )
            stats['principals'] += 1

            # Link to policy
            self.client.create_relationship(
                from_id=principal_id,
                from_label='Principal',
                to_id=policy_id,
                to_label='Policy',
                relationship_type='HAS_POLICY',
                properties={'effect': effect}
            )
            stats['relationships'] += 1

        return stats

    def _build_gcp_graph(self, policy: Policy, policy_doc: Dict[str, Any]) -> Dict[str, int]:
        """
        Build graph for GCP policy.

        Args:
            policy: Policy object
            policy_doc: Parsed policy document

        Returns:
            Statistics about created nodes/relationships
        """
        stats = {'principals': 0, 'resources': 0, 'actions': 0, 'policies': 1, 'relationships': 0}

        # Create policy node
        policy_id = f"gcp-policy-{getattr(policy, 'project_id', 'unknown')}-{policy.name}"
        self.client.create_policy(
            policy_id=policy_id,
            policy_name=policy.name,
            cloud_provider='GCP',
            vulnerable=policy.is_vulnerable(),
            properties={
                'project_id': getattr(policy, 'project_id', 'unknown'),
                'policy_type': getattr(policy, 'policy_type', ''),
                'ai_response': policy.ai_response or '',
                'redacted_document': policy.redacted_document or ''
            }
        )

        # GCP IAM policies have bindings
        bindings = policy_doc.get('bindings', [])
        for binding in bindings:
            role = binding.get('role', 'unknown')

            # Extract members (principals)
            members = binding.get('members', [])
            for member in members:
                principal_type, principal_name = self._parse_gcp_member(member)
                principal_id = member

                self.client.create_principal(
                    principal_id=principal_id,
                    principal_type=principal_type,
                    name=principal_name,
                    properties={'provider': 'GCP', 'role': role}
                )
                stats['principals'] += 1

                # Link to policy
                self.client.create_relationship(
                    from_id=principal_id,
                    from_label='Principal',
                    to_id=policy_id,
                    to_label='Policy',
                    relationship_type='HAS_POLICY',
                    properties={'role': role}
                )
                stats['relationships'] += 1

                # Create action for the role
                self.client.create_action(
                    action_name=role,
                    category=self._categorize_gcp_role(role),
                    properties={'provider': 'GCP'}
                )
                stats['actions'] += 1

                # Link policy to action
                self.client.create_relationship(
                    from_id=policy_id,
                    from_label='Policy',
                    to_id=role,
                    to_label='Action',
                    relationship_type='GRANTS',
                    properties={}
                )
                stats['relationships'] += 1

        return stats

    def _extract_aws_principals(self, statement: Dict[str, Any]) -> List[Dict[str, str]]:
        """Extract principals from AWS policy statement."""
        principals = []
        principal_data = statement.get('Principal', {})

        if isinstance(principal_data, str):
            if principal_data == '*':
                principals.append({'id': 'aws-principal-*', 'type': 'public', 'name': 'Public Access'})
        elif isinstance(principal_data, dict):
            for prin_type, prin_values in principal_data.items():
                if not isinstance(prin_values, list):
                    prin_values = [prin_values]

                for prin_value in prin_values:
                    if prin_value == '*':
                        principals.append({'id': 'aws-principal-*', 'type': 'public', 'name': 'Public Access'})
                    else:
                        principals.append({
                            'id': prin_value,
                            'type': prin_type.lower(),
                            'name': prin_value.split('/')[-1] if '/' in prin_value else prin_value
                        })

        return principals

    def _extract_aws_actions(self, statement: Dict[str, Any]) -> List[str]:
        """Extract actions from AWS policy statement."""
        actions = statement.get('Action', [])
        if not isinstance(actions, list):
            actions = [actions]
        return actions

    def _extract_aws_resources(self, statement: Dict[str, Any]) -> List[str]:
        """Extract resources from AWS policy statement."""
        resources = statement.get('Resource', [])
        if not isinstance(resources, list):
            resources = [resources]
        return resources

    def _extract_resource_type_from_arn(self, arn: str) -> str:
        """Extract resource type from ARN."""
        if arn == '*':
            return 'wildcard'

        # ARN format: arn:partition:service:region:account-id:resource-type/resource-id
        parts = arn.split(':')
        if len(parts) >= 6:
            service = parts[2]
            resource_part = parts[5]
            if '/' in resource_part:
                resource_type = resource_part.split('/')[0]
            else:
                resource_type = resource_part

            return f"{service}:{resource_type}"

        return 'unknown'

    def _extract_resource_name_from_arn(self, arn: str) -> str:
        """Extract resource name from ARN."""
        if arn == '*':
            return 'All Resources'

        # Try to get the last part of the ARN
        parts = arn.split(':')
        if len(parts) >= 6:
            resource_part = parts[5]
            if '/' in resource_part:
                return resource_part.split('/')[-1]
            return resource_part

        return arn

    def _parse_gcp_member(self, member: str) -> Tuple[str, str]:
        """Parse GCP member string into type and name."""
        if ':' in member:
            member_type, member_id = member.split(':', 1)
            return member_type, member_id
        return 'unknown', member

    def _categorize_action(self, action: str) -> str:
        """Categorize action by type."""
        action_lower = action.lower()

        if '*' in action or 'admin' in action_lower:
            return 'admin'
        elif any(word in action_lower for word in ['delete', 'remove', 'terminate']):
            return 'delete'
        elif any(word in action_lower for word in ['put', 'create', 'write', 'update', 'modify']):
            return 'write'
        elif any(word in action_lower for word in ['get', 'list', 'describe', 'read']):
            return 'read'
        else:
            return 'other'

    def _categorize_gcp_role(self, role: str) -> str:
        """Categorize GCP role by permission level."""
        role_lower = role.lower()

        if 'owner' in role_lower or 'admin' in role_lower:
            return 'admin'
        elif 'editor' in role_lower or 'writer' in role_lower:
            return 'write'
        elif 'viewer' in role_lower or 'reader' in role_lower:
            return 'read'
        else:
            return 'other'
