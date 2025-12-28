"""
AWS IAM Policy Scanner
Scans customer-managed IAM policies for security vulnerabilities using AI analysis.
"""

import boto3
import argparse
import re
import os
import random
from core.policy import Policy
from core.scanner_base import ScannerBase
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


class AWSScanner(ScannerBase):
    """Scanner for AWS IAM policies."""

    def __init__(self, api_key: str, profile: str = 'default'):
        """
        Initialize AWS scanner.

        Args:
            api_key: OpenAI API key
            profile: AWS profile name to use
        """
        super().__init__(api_key)
        self.session = boto3.Session(profile_name=profile)
        self.iam_client = self.session.client('iam')
        self.sts_client = self.session.client('sts')
        self.account = self.sts_client.get_caller_identity().get('Account')

    def redact_policy(self, policy: Policy) -> Policy:
        """
        Redact AWS account IDs from policy document.

        Args:
            policy: Policy object to redact

        Returns:
            Policy object with redacted_document populated
        """
        new_policy = policy
        new_policy.original_document = str(policy.policy)

        # Find and replace 12-digit AWS account numbers
        match = re.search(r'\b\d{12}\b', new_policy.original_document)
        if match:
            original_account = match.group()
            new_account = random.randint(100000000000, 999999999999)
            new_policy.map_accounts(original_account, new_account)
            new_policy.redacted_document = new_policy.original_document.replace(
                original_account, str(new_account)
            )
        else:
            new_policy.redacted_document = new_policy.original_document

        return new_policy

    def scan(self, redact: bool = True):
        """
        Scan all customer-managed IAM policies in the AWS account.

        Args:
            redact: Whether to redact sensitive information (default: True)
        """
        self.log(f'Retrieving and redacting policies for account: {self.account}')

        try:
            paginator = self.iam_client.get_paginator('list_policies')
            response_iterator = paginator.paginate(Scope='Local', OnlyAttached=False)

            for response in response_iterator:
                for policy_data in response['Policies']:
                    try:
                        policy_name = policy_data['PolicyName']
                        policy_arn = policy_data['Arn']

                        # Skip AWS-managed policies
                        if policy_arn.startswith("arn:aws:iam::aws"):
                            continue

                        policy_version = self.iam_client.get_policy_version(
                            PolicyArn=policy_data['Arn'],
                            VersionId=policy_data['DefaultVersionId']
                        )
                        default_version = policy_version['PolicyVersion']['VersionId']

                        # Create Policy object
                        p = Policy()
                        p.account = self.account
                        p.arn = policy_arn
                        p.name = policy_name
                        p.policy = policy_version['PolicyVersion']['Document']
                        p.version = default_version

                        if redact:
                            p = self.redact_policy(p)
                            p = self.check_policy(p, 'AWS')

                        self.results.append(p)

                    except Exception as e:
                        self.logger.error(f'Error processing policy {policy_name}: {str(e)}')
                        continue

        except Exception as e:
            self.logger.error(f'Error scanning AWS policies: {str(e)}')
            raise

    def save_results(self):
        """Save scan results to CSV file."""
        scan_timestamp = self.get_scan_timestamp()
        filename = f'cache/{self.account}_{scan_timestamp}.csv'

        header = ['account', 'name', 'arn', 'version', 'vulnerable', 'policy', 'mappings']

        def row_builder(data):
            mappings = '' if len(data.retrieve_mappings()) == 0 else data.retrieve_mappings()
            return {
                'account': data.account,
                'name': data.name,
                'arn': data.arn,
                'version': data.version,
                'vulnerable': data.ai_response,
                'policy': data.redacted_document,
                'mappings': mappings
            }

        self.preserve(filename, header, self.results, row_builder)


def main(args):
    """Main entry point for AWS scanner."""
    # Get API key with priority: CLI arg > environment variable
    api_key = args.key or os.getenv('OPENAI_API_KEY')
    if not api_key:
        raise ValueError(
            "OpenAI API key is required. Provide it via --key argument or OPENAI_API_KEY environment variable."
        )

    # Create and run scanner
    scanner = AWSScanner(api_key, profile=args.profile)
    scanner.scan(redact=args.redact)
    scanner.save_results()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Retrieve all customer managed policies and check the default policy version for vulnerabilities'
    )
    parser.add_argument(
        '--key',
        type=str,
        required=False,
        help='OpenAI API key (can also use OPENAI_API_KEY environment variable)'
    )
    parser.add_argument(
        '--profile',
        type=str,
        default='default',
        help='AWS profile name to use (default: default)'
    )
    parser.add_argument(
        '--redact',
        action='store_true',
        default=True,
        help='Redact sensitive information in the policy document (default: True)'
    )

    args = parser.parse_args()
    main(args)
