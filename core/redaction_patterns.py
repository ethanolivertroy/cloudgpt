"""
Redaction Patterns Library
Defines regex patterns for identifying sensitive information across cloud providers.
"""

import re
from typing import Dict, List, Tuple


class RedactionPatterns:
    """Pattern library for identifying sensitive data in cloud policies."""

    # AWS Patterns
    AWS_ACCOUNT_ID = r'\b\d{12}\b'
    AWS_ARN = r'arn:aws:[a-z0-9\-]+:[a-z0-9\-]*:\d{12}:[a-zA-Z0-9\-\/\._]+'
    AWS_IAM_USER = r'arn:aws:iam::\d{12}:user/[a-zA-Z0-9\-\/\._]+'
    AWS_IAM_ROLE = r'arn:aws:iam::\d{12}:role/[a-zA-Z0-9\-\/\._]+'
    AWS_ACCESS_KEY = r'AKIA[0-9A-Z]{16}'

    # Azure Patterns
    AZURE_SUBSCRIPTION_ID = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
    AZURE_TENANT_ID = r'/tenants/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
    AZURE_RESOURCE_ID = r'/subscriptions/[0-9a-f\-]+/resourceGroups/[a-zA-Z0-9\-\_]+(/providers/[a-zA-Z0-9\.\-\_/]+)?'
    AZURE_PRINCIPAL_ID = r'"principalId":\s*"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"'

    # GCP Patterns
    GCP_PROJECT_ID = r'projects/([a-z0-9\-]+)'
    GCP_PROJECT_NUMBER = r'projects/(\d{12})'
    GCP_SERVICE_ACCOUNT = r'[a-z0-9\-]+@[a-z0-9\-]+\.iam\.gserviceaccount\.com'
    GCP_ORG_ID = r'organizations/\d+'

    # Common Patterns (all cloud providers)
    IPV4_ADDRESS = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    IPV6_ADDRESS = r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
    EMAIL_ADDRESS = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'

    @classmethod
    def get_aws_patterns(cls) -> Dict[str, str]:
        """Get all AWS redaction patterns."""
        return {
            'account_id': cls.AWS_ACCOUNT_ID,
            'arn': cls.AWS_ARN,
            'iam_user': cls.AWS_IAM_USER,
            'iam_role': cls.AWS_IAM_ROLE,
            'access_key': cls.AWS_ACCESS_KEY,
            'ipv4': cls.IPV4_ADDRESS,
            'email': cls.EMAIL_ADDRESS,
        }

    @classmethod
    def get_azure_patterns(cls) -> Dict[str, str]:
        """Get all Azure redaction patterns."""
        return {
            'subscription_id': cls.AZURE_SUBSCRIPTION_ID,
            'tenant_id': cls.AZURE_TENANT_ID,
            'resource_id': cls.AZURE_RESOURCE_ID,
            'principal_id': cls.AZURE_PRINCIPAL_ID,
            'ipv4': cls.IPV4_ADDRESS,
            'email': cls.EMAIL_ADDRESS,
        }

    @classmethod
    def get_gcp_patterns(cls) -> Dict[str, str]:
        """Get all GCP redaction patterns."""
        return {
            'project_id': cls.GCP_PROJECT_ID,
            'project_number': cls.GCP_PROJECT_NUMBER,
            'service_account': cls.GCP_SERVICE_ACCOUNT,
            'org_id': cls.GCP_ORG_ID,
            'ipv4': cls.IPV4_ADDRESS,
            'email': cls.EMAIL_ADDRESS,
        }

    @classmethod
    def get_patterns_for_provider(cls, provider: str) -> Dict[str, str]:
        """
        Get redaction patterns for a specific cloud provider.

        Args:
            provider: Cloud provider name ('aws', 'azure', 'gcp')

        Returns:
            Dictionary mapping pattern names to regex patterns
        """
        provider_lower = provider.lower()
        if provider_lower == 'aws':
            return cls.get_aws_patterns()
        elif provider_lower == 'azure':
            return cls.get_azure_patterns()
        elif provider_lower == 'gcp':
            return cls.get_gcp_patterns()
        else:
            raise ValueError(f"Unknown provider: {provider}")
