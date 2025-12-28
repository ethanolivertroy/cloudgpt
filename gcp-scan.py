"""
GCP Policy Scanner
Scans GCP IAM and organization policies for security vulnerabilities using AI analysis.
"""

import os
import re
import random
import argparse
from google.cloud import resourcemanager_v3
from google.cloud import iam_v2
from google.cloud.iam_admin_v1 import IAMClient
from core.policy import Policy
from core.scanner_base import ScannerBase
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


class GCPScanner(ScannerBase):
    """Scanner for GCP IAM and organization policies."""

    def __init__(self, api_key: str, project_id: str):
        """
        Initialize GCP scanner.

        Args:
            api_key: OpenAI API key
            project_id: GCP project ID
        """
        super().__init__(api_key, provider='gcp')
        self.project_id = project_id
        self.iam_client = IAMClient()

    def redact_policy(self, policy: Policy) -> Policy:
        """
        Redact GCP sensitive information from policy document using enhanced obfuscation.

        Args:
            policy: Policy object to redact

        Returns:
            Policy object with redacted_document populated
        """
        new_policy = policy
        new_policy.original_document = str(policy.policy)

        # Use obfuscation engine if available
        if self.obfuscation_engine:
            # Get configured patterns for GCP
            obf_config = self.config.get('obfuscation', {})
            enabled_patterns = obf_config.get('gcp_patterns', None)

            # Perform redaction
            redacted_text, mappings = self.obfuscation_engine.redact(
                new_policy.original_document,
                enabled_patterns=enabled_patterns
            )

            new_policy.redacted_document = redacted_text

            # Store mappings in policy object
            for original, replacement in mappings.items():
                new_policy.map_accounts(original, replacement)
        else:
            # Fallback to basic redaction if obfuscation engine not available
            match = re.search(r'projects/([a-z0-9-]+)', new_policy.original_document)
            if match:
                original_project = match.group(1)
                new_project = f'project-{random.randint(10000, 99999)}'
                new_policy.map_accounts(original_project, new_project)
                new_policy.redacted_document = new_policy.original_document.replace(
                    original_project, new_project
                )
            else:
                new_policy.redacted_document = new_policy.original_document

        return new_policy

    def scan(self, redact: bool = True):
        """
        Scan all GCP IAM and organization policies in the project.

        Args:
            redact: Whether to redact sensitive information (default: True)
        """
        self.log(f'Retrieving and redacting policies for GCP project: {self.project_id}')

        # Scan IAM policies
        self._scan_iam_policies(redact)

        # Scan organization policies
        self._scan_org_policies(redact)

    def _scan_iam_policies(self, redact: bool):
        """Scan IAM policies for the project."""
        try:
            request = iam_v2.GetPolicyRequest(
                resource=f'projects/{self.project_id}'
            )
            policy = self.iam_client.get_iam_policy(request=request)

            p = Policy()
            p.project_id = self.project_id
            p.policy_type = "IAM"
            p.name = f"{self.project_id}-iam-policy"
            p.policy = policy

            if redact:
                p = self.redact_policy(p)
                p = self.check_policy(p, 'GCP')

            self.results.append(p)

        except Exception as e:
            self.logger.error(f"Error scanning IAM policies for project {self.project_id}: {str(e)}")

    def _scan_org_policies(self, redact: bool):
        """Scan organization policies for the project."""
        try:
            client = resourcemanager_v3.OrgPolicyClient()
            parent = f"projects/{self.project_id}"

            # List all organization policy constraints
            constraints = client.list_constraints(parent=parent)

            for constraint in constraints:
                try:
                    policy_name = f"{parent}/policies/{constraint.name.split('/')[-1]}"

                    try:
                        policy = client.get_policy(name=policy_name)

                        p = Policy()
                        p.project_id = self.project_id
                        p.policy_type = "Organization"
                        p.name = constraint.name
                        p.policy = policy

                        if redact:
                            p = self.redact_policy(p)
                            p = self.check_policy(p, 'GCP')

                        self.results.append(p)

                    except Exception as e:
                        self.logger.error(f"Error getting policy for constraint {constraint.name}: {str(e)}")

                except Exception as e:
                    self.logger.error(f"Error processing constraint {constraint.name}: {str(e)}")
                    continue

        except Exception as e:
            self.logger.error(f"Error listing constraints for project {self.project_id}: {str(e)}")

    def save_results(self):
        """Save scan results to CSV file."""
        scan_timestamp = self.get_scan_timestamp()
        filename = f'cache/{self.project_id}_{scan_timestamp}.csv'

        header = ['project_id', 'policy_type', 'name', 'vulnerable', 'policy', 'mappings']

        def row_builder(data):
            mappings = '' if len(data.retrieve_mappings()) == 0 else data.retrieve_mappings()
            return {
                'project_id': data.project_id,
                'policy_type': data.policy_type,
                'name': data.name,
                'vulnerable': data.ai_response,
                'policy': data.redacted_document,
                'mappings': mappings
            }

        self.preserve(filename, header, self.results, row_builder)

        # Export obfuscation audit log if enabled
        self.export_obfuscation_audit()

        # Export to Neo4j graph database if enabled
        self.export_to_neo4j()


def main(args):
    """Main entry point for GCP scanner."""
    # Get API key with priority: CLI arg > environment variable
    api_key = args.key or os.getenv('OPENAI_API_KEY')
    if not api_key:
        raise ValueError(
            "OpenAI API key is required. Provide it via --key argument or OPENAI_API_KEY environment variable."
        )

    # Get project ID with priority: CLI arg > environment variable
    project_id = args.project_id or os.getenv('GCP_PROJECT_ID')
    if not project_id:
        raise ValueError(
            "GCP project ID is required. Provide it via --project-id argument or GCP_PROJECT_ID environment variable."
        )

    # Create and run scanner
    scanner = GCPScanner(api_key, project_id)
    scanner.scan(redact=args.redact)
    scanner.save_results()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Retrieve all GCP policies and check for vulnerabilities'
    )
    parser.add_argument(
        '--key',
        type=str,
        required=False,
        help='OpenAI API key (can also use OPENAI_API_KEY environment variable)'
    )
    parser.add_argument(
        '--project-id',
        type=str,
        required=False,
        help='GCP project ID (can also use GCP_PROJECT_ID environment variable)'
    )
    parser.add_argument(
        '--redact',
        action='store_true',
        default=True,
        help='Redact sensitive information in the policy document (default: True)'
    )

    args = parser.parse_args()
    main(args)
