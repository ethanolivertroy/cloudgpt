"""
JSON Exporter
Exports scan results to JSON format.
"""

import json
from datetime import datetime
from typing import List, Dict, Any
from core.policy import Policy
from core.output_formats.base_exporter import BaseExporter


class JSONExporter(BaseExporter):
    """Export scan results to JSON format."""

    def export(self, policies: List[Policy], filename: str, metadata: Dict[str, Any] = None) -> str:
        """
        Export policies to JSON format.

        Args:
            policies: List of Policy objects to export
            filename: Output filename (without extension)
            metadata: Additional metadata to include

        Returns:
            Full path to exported file
        """
        output_file = self.get_full_path(filename, '.json')

        # Build JSON structure
        data = {
            'scan_metadata': {
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'total_policies': len(policies),
                'vulnerable_count': self.count_vulnerable(policies),
                'by_provider': self.count_by_provider(policies),
                **(metadata or {})
            },
            'policies': []
        }

        # Add each policy
        for policy in policies:
            policy_data = {
                'name': policy.name,
                'vulnerable': policy.is_vulnerable(),
                'ai_response': policy.ai_response or '',
                'redacted_document': policy.redacted_document or '',
                'mappings': policy.retrieve_mappings() if hasattr(policy, 'retrieve_mappings') else {}
            }

            # Add provider-specific fields
            if hasattr(policy, 'arn'):
                policy_data['provider'] = 'AWS'
                policy_data['account'] = getattr(policy, 'account', '')
                policy_data['arn'] = policy.arn
                policy_data['version'] = getattr(policy, 'version', '')
            elif hasattr(policy, 'subscription_id'):
                policy_data['provider'] = 'Azure'
                policy_data['subscription_id'] = policy.subscription_id
                policy_data['resource_group'] = getattr(policy, 'resource_group', '')
                policy_data['id'] = getattr(policy, 'id', '')
            elif hasattr(policy, 'project_id'):
                policy_data['provider'] = 'GCP'
                policy_data['project_id'] = policy.project_id
                policy_data['policy_type'] = getattr(policy, 'policy_type', '')

            data['policies'].append(policy_data)

        # Write JSON file
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        return output_file
