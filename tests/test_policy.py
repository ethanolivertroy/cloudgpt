"""
Unit tests for Policy class
"""

import pytest
from core.policy import Policy


class TestPolicy:
    """Test suite for Policy class"""

    def test_policy_initialization(self):
        """Test Policy object initialization"""
        policy = Policy()
        assert policy.name is None
        assert policy.policy is None
        assert policy.original_document is None
        assert policy.redacted_document is None
        assert policy.ai_response is None

    def test_policy_with_attributes(self):
        """Test Policy with set attributes"""
        policy = Policy()
        policy.name = "test-policy"
        policy.account = "123456789012"
        policy.arn = "arn:aws:iam::123456789012:policy/test-policy"

        assert policy.name == "test-policy"
        assert policy.account == "123456789012"
        assert policy.arn == "arn:aws:iam::123456789012:policy/test-policy"

    def test_map_accounts(self):
        """Test account mapping functionality"""
        policy = Policy()
        policy.map_accounts("123456789012", "999999999999")

        mappings = policy.retrieve_mappings()
        assert "123456789012 -> 999999999999" in mappings

    def test_multiple_mappings(self):
        """Test multiple account mappings"""
        policy = Policy()
        policy.map_accounts("111111111111", "999999999999")
        policy.map_accounts("222222222222", "888888888888")

        mappings = policy.retrieve_mappings()
        assert "111111111111 -> 999999999999" in mappings
        assert "222222222222 -> 888888888888" in mappings

    def test_retrieve_mappings_empty(self):
        """Test retrieve mappings when no mappings exist"""
        policy = Policy()
        mappings = policy.retrieve_mappings()
        assert mappings == ''

    def test_is_vulnerable_yes(self):
        """Test vulnerability detection for vulnerable policy"""
        policy = Policy()
        policy.ai_response = "Yes, this policy has security vulnerabilities"
        assert policy.is_vulnerable() is True

    def test_is_vulnerable_no(self):
        """Test vulnerability detection for safe policy"""
        policy = Policy()
        policy.ai_response = "No, this policy appears secure"
        assert policy.is_vulnerable() is False

    def test_is_vulnerable_case_insensitive(self):
        """Test vulnerability detection is case insensitive"""
        policy = Policy()
        policy.ai_response = "YES, there are issues"
        assert policy.is_vulnerable() is True

        policy.ai_response = "NO issues found"
        assert policy.is_vulnerable() is False

    def test_is_vulnerable_no_response(self):
        """Test vulnerability detection with no AI response"""
        policy = Policy()
        assert policy.is_vulnerable() is False

    def test_is_vulnerable_empty_response(self):
        """Test vulnerability detection with empty response"""
        policy = Policy()
        policy.ai_response = ""
        assert policy.is_vulnerable() is False

    def test_aws_policy_attributes(self):
        """Test AWS-specific policy attributes"""
        policy = Policy()
        policy.account = "123456789012"
        policy.arn = "arn:aws:iam::123456789012:policy/AdminPolicy"
        policy.name = "AdminPolicy"
        policy.version = "v1"

        assert hasattr(policy, 'account')
        assert hasattr(policy, 'arn')
        assert hasattr(policy, 'name')
        assert hasattr(policy, 'version')

    def test_azure_policy_attributes(self):
        """Test Azure-specific policy attributes"""
        policy = Policy()
        policy.subscription_id = "12345678-1234-1234-1234-123456789012"
        policy.resource_group = "my-resource-group"
        policy.name = "storage-policy"
        policy.id = "/subscriptions/12345678-1234-1234-1234-123456789012/providers/Microsoft.Authorization/policyAssignments/storage-policy"

        assert hasattr(policy, 'subscription_id')
        assert hasattr(policy, 'resource_group')
        assert hasattr(policy, 'name')
        assert hasattr(policy, 'id')

    def test_gcp_policy_attributes(self):
        """Test GCP-specific policy attributes"""
        policy = Policy()
        policy.project_id = "my-gcp-project"
        policy.policy_type = "IAM"
        policy.name = "project-iam-policy"

        assert hasattr(policy, 'project_id')
        assert hasattr(policy, 'policy_type')
        assert hasattr(policy, 'name')

    def test_policy_redaction(self):
        """Test policy document redaction"""
        policy = Policy()
        policy.original_document = '{"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}'
        policy.redacted_document = '{"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}'

        assert policy.original_document is not None
        assert policy.redacted_document is not None
        assert isinstance(policy.original_document, str)
        assert isinstance(policy.redacted_document, str)

    def test_policy_ai_response(self):
        """Test AI response storage"""
        policy = Policy()
        ai_response = "Yes, this policy grants excessive permissions with wildcard actions and resources."
        policy.ai_response = ai_response

        assert policy.ai_response == ai_response
        assert policy.is_vulnerable() is True
