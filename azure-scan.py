"""
Azure Policy Scanner
Scans Azure policy assignments for security vulnerabilities using AI analysis.
"""

import os
import re
import uuid
import argparse
from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.authorization import AuthorizationManagementClient
from core.policy import Policy
from core.scanner_base import ScannerBase
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


class AzureScanner(ScannerBase):
    """Scanner for Azure policies."""

    def __init__(self, api_key: str, subscription_id: str):
        """
        Initialize Azure scanner.

        Args:
            api_key: OpenAI API key
            subscription_id: Azure subscription ID
        """
        super().__init__(api_key, provider='azure')
        self.subscription_id = subscription_id
        self.credential = DefaultAzureCredential()
        self.resource_client = ResourceManagementClient(self.credential, subscription_id)
        self.authorization_client = AuthorizationManagementClient(self.credential, subscription_id)

    def redact_policy(self, policy: Policy) -> Policy:
        """
        Redact Azure sensitive information from policy document using enhanced obfuscation.

        Args:
            policy: Policy object to redact

        Returns:
            Policy object with redacted_document populated
        """
        new_policy = policy
        new_policy.original_document = str(policy.policy)

        # Use obfuscation engine if available
        if self.obfuscation_engine:
            # Get configured patterns for Azure
            obf_config = self.config.get('obfuscation', {})
            enabled_patterns = obf_config.get('azure_patterns', None)

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
            match = re.search(
                r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
                new_policy.original_document,
                re.IGNORECASE
            )
            if match:
                original_subscription = match.group()
                new_subscription = str(uuid.uuid4())
                new_policy.map_accounts(original_subscription, new_subscription)
                new_policy.redacted_document = new_policy.original_document.replace(
                    original_subscription, new_subscription
                )
            else:
                new_policy.redacted_document = new_policy.original_document

        return new_policy

    def scan(self, redact: bool = True):
        """
        Scan all Azure policy assignments in the subscription.

        Args:
            redact: Whether to redact sensitive information (default: True)
        """
        self.log(f'Retrieving and redacting policies for subscription: {self.subscription_id}')

        # Create cache directory if it doesn't exist
        os.makedirs('cache', exist_ok=True)

        # Scan resource group level policies
        try:
            for group in self.resource_client.resource_groups.list():
                resource_group_name = group.name
                self.log(f'Scanning resource group: {resource_group_name}')

                try:
                    policy_assignments = self.authorization_client.policy_assignments.list_for_resource_group(
                        resource_group_name
                    )

                    for assignment in policy_assignments:
                        try:
                            policy_definition = self.authorization_client.policy_definitions.get(
                                assignment.policy_definition_id.split('/')[-1]
                            )

                            p = Policy()
                            p.subscription_id = self.subscription_id
                            p.resource_group = resource_group_name
                            p.name = assignment.name
                            p.id = assignment.id
                            p.policy = policy_definition.policy_rule

                            if redact:
                                p = self.redact_policy(p)
                                p = self.check_policy(p, 'Azure')

                            self.results.append(p)

                        except Exception as e:
                            self.logger.error(f'Error processing policy {assignment.name}: {str(e)}')
                            continue

                except Exception as e:
                    self.logger.error(f'Error scanning resource group {resource_group_name}: {str(e)}')
                    continue

        except Exception as e:
            self.logger.error(f'Error listing resource groups: {str(e)}')
            raise

        # Scan subscription-level policy assignments
        try:
            subscription_policies = self.authorization_client.policy_assignments.list_for_subscription()

            for assignment in subscription_policies:
                try:
                    policy_definition = self.authorization_client.policy_definitions.get(
                        assignment.policy_definition_id.split('/')[-1]
                    )

                    p = Policy()
                    p.subscription_id = self.subscription_id
                    p.resource_group = "subscription-level"
                    p.name = assignment.name
                    p.id = assignment.id
                    p.policy = policy_definition.policy_rule

                    if redact:
                        p = self.redact_policy(p)
                        p = self.check_policy(p, 'Azure')

                    self.results.append(p)

                except Exception as e:
                    self.logger.error(f'Error processing policy {assignment.name}: {str(e)}')
                    continue

        except Exception as e:
            self.logger.error(f'Error scanning subscription-level policies: {str(e)}')

    def save_results(self):
        """Save scan results to CSV file."""
        scan_timestamp = self.get_scan_timestamp()
        filename = f'cache/{self.subscription_id}_{scan_timestamp}.csv'

        header = ['subscription_id', 'resource_group', 'name', 'id', 'vulnerable', 'policy', 'mappings']

        def row_builder(data):
            mappings = '' if len(data.retrieve_mappings()) == 0 else data.retrieve_mappings()
            return {
                'subscription_id': data.subscription_id,
                'resource_group': data.resource_group,
                'name': data.name,
                'id': data.id,
                'vulnerable': data.ai_response,
                'policy': data.redacted_document,
                'mappings': mappings
            }

        self.preserve(filename, header, self.results, row_builder)

        # Export obfuscation audit log if enabled
        self.export_obfuscation_audit()


def main(args):
    """Main entry point for Azure scanner."""
    # Get API key with priority: CLI arg > environment variable
    api_key = args.key or os.getenv('OPENAI_API_KEY')
    if not api_key:
        raise ValueError(
            "OpenAI API key is required. Provide it via --key argument or OPENAI_API_KEY environment variable."
        )

    # Get subscription ID with priority: CLI arg > environment variable
    subscription_id = args.subscription_id or os.getenv('AZURE_SUBSCRIPTION_ID')
    if not subscription_id:
        raise ValueError(
            "Azure subscription ID is required. Provide it via --subscription-id argument or AZURE_SUBSCRIPTION_ID environment variable."
        )

    # Create and run scanner
    scanner = AzureScanner(api_key, subscription_id)
    scanner.scan(redact=args.redact)
    scanner.save_results()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Retrieve all Azure policies and check for vulnerabilities'
    )
    parser.add_argument(
        '--key',
        type=str,
        required=False,
        help='OpenAI API key (can also use OPENAI_API_KEY environment variable)'
    )
    parser.add_argument(
        '--subscription-id',
        type=str,
        required=False,
        help='Azure subscription ID (can also use AZURE_SUBSCRIPTION_ID environment variable)'
    )
    parser.add_argument(
        '--redact',
        action='store_true',
        default=True,
        help='Redact sensitive information in the policy document (default: True)'
    )

    args = parser.parse_args()
    main(args)
