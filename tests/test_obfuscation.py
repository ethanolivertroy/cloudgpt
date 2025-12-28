"""
Unit tests for Obfuscation Engine
"""

import pytest
import re
from core.obfuscation import ObfuscationEngine
from core.redaction_patterns import RedactionPatterns


class TestRedactionPatterns:
    """Test suite for RedactionPatterns"""

    def test_aws_account_id_pattern(self):
        """Test AWS account ID regex pattern"""
        pattern = RedactionPatterns.AWS_ACCOUNT_ID
        assert re.search(pattern, "123456789012")
        assert re.search(pattern, "Account: 123456789012")
        assert not re.search(pattern, "12345")  # Too short
        assert not re.search(pattern, "1234567890123")  # Too long

    def test_aws_arn_pattern(self):
        """Test AWS ARN regex pattern"""
        pattern = RedactionPatterns.AWS_ARN
        assert re.search(pattern, "arn:aws:iam::123456789012:role/MyRole")
        assert re.search(pattern, "arn:aws:s3:::my-bucket")
        assert re.search(pattern, "arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0")

    def test_azure_subscription_id_pattern(self):
        """Test Azure subscription ID (UUID) pattern"""
        pattern = RedactionPatterns.AZURE_SUBSCRIPTION_ID
        assert re.search(pattern, "12345678-1234-1234-1234-123456789012")
        assert re.search(pattern, "abcd1234-ab12-cd34-ef56-abcdef123456")
        assert not re.search(pattern, "not-a-uuid")

    def test_gcp_project_id_pattern(self):
        """Test GCP project ID pattern"""
        pattern = RedactionPatterns.GCP_PROJECT_ID
        assert re.search(pattern, "projects/my-project-123")
        assert re.search(pattern, "projects/test-project")
        match = re.search(pattern, "projects/my-gcp-project")
        assert match.group(1) == "my-gcp-project"

    def test_ipv4_pattern(self):
        """Test IPv4 address pattern"""
        pattern = RedactionPatterns.IPV4_ADDRESS
        assert re.search(pattern, "192.168.1.1")
        assert re.search(pattern, "10.0.0.1")
        assert re.search(pattern, "255.255.255.255")
        assert not re.search(pattern, "256.1.1.1")  # Invalid
        assert not re.search(pattern, "192.168.1")  # Incomplete

    def test_email_pattern(self):
        """Test email address pattern"""
        pattern = RedactionPatterns.EMAIL_ADDRESS
        assert re.search(pattern, "user@example.com")
        assert re.search(pattern, "test.user+tag@domain.co.uk")
        assert not re.search(pattern, "not-an-email")
        assert not re.search(pattern, "@example.com")


class TestObfuscationEngine:
    """Test suite for ObfuscationEngine"""

    @pytest.fixture
    def aws_engine(self):
        """Create AWS obfuscation engine"""
        return ObfuscationEngine(provider='aws', consistent_mapping=True, audit_log=True)

    @pytest.fixture
    def azure_engine(self):
        """Create Azure obfuscation engine"""
        return ObfuscationEngine(provider='azure', consistent_mapping=True, audit_log=True)

    @pytest.fixture
    def gcp_engine(self):
        """Create GCP obfuscation engine"""
        return ObfuscationEngine(provider='gcp', consistent_mapping=True, audit_log=True)

    def test_engine_initialization(self, aws_engine):
        """Test obfuscation engine initialization"""
        assert aws_engine.provider == 'aws'
        assert aws_engine.consistent_mapping is True
        assert aws_engine.audit_log is True
        assert len(aws_engine.patterns) > 0

    def test_aws_account_id_redaction(self, aws_engine):
        """Test AWS account ID redaction"""
        text = "Account ID: 123456789012"
        redacted, mappings = aws_engine.redact(text)

        assert "123456789012" not in redacted
        assert "123456789012" in mappings
        assert len(mappings["123456789012"]) == 12  # Replacement should be 12 digits

    def test_consistent_mapping(self, aws_engine):
        """Test consistent anonymization"""
        text1 = "Account: 123456789012"
        text2 = "Also account: 123456789012"

        redacted1, mappings1 = aws_engine.redact(text1)
        redacted2, mappings2 = aws_engine.redact(text2)

        # Same account ID should map to same replacement
        assert mappings1["123456789012"] == mappings2["123456789012"]

    def test_multiple_patterns(self, aws_engine):
        """Test multiple pattern redaction"""
        text = "Account 123456789012 with email user@example.com and IP 192.168.1.1"
        redacted, mappings = aws_engine.redact(text)

        assert "123456789012" not in redacted
        assert "user@example.com" not in redacted
        assert "192.168.1.1" not in redacted
        assert len(mappings) >= 3

    def test_audit_trail(self, aws_engine):
        """Test audit trail generation"""
        text = "Account: 123456789012"
        aws_engine.redact(text)

        audit_trail = aws_engine.get_audit_trail()
        assert len(audit_trail) > 0
        assert audit_trail[0]['pattern_type'] == 'account_id'
        assert 'timestamp' in audit_trail[0]

    def test_azure_uuid_redaction(self, azure_engine):
        """Test Azure UUID redaction"""
        text = "Subscription: 12345678-1234-1234-1234-123456789012"
        redacted, mappings = azure_engine.redact(text)

        assert "12345678-1234-1234-1234-123456789012" not in redacted
        assert len(mappings) > 0

    def test_gcp_project_redaction(self, gcp_engine):
        """Test GCP project ID redaction"""
        text = "projects/my-gcp-project-123"
        redacted, mappings = gcp_engine.redact(text)

        assert "my-gcp-project-123" not in redacted
        assert len(mappings) > 0

    def test_enabled_patterns(self, aws_engine):
        """Test selective pattern enabling"""
        text = "Account 123456789012 with email user@example.com"

        # Only redact account IDs
        redacted, mappings = aws_engine.redact(text, enabled_patterns=['account_id'])

        assert "123456789012" not in redacted
        assert "user@example.com" in redacted  # Email should not be redacted
        assert len(mappings) == 1

    def test_empty_text(self, aws_engine):
        """Test redaction of empty text"""
        redacted, mappings = aws_engine.redact("")
        assert redacted == ""
        assert len(mappings) == 0

    def test_no_sensitive_data(self, aws_engine):
        """Test redaction when no sensitive data present"""
        text = "This is just normal text without any sensitive information"
        redacted, mappings = aws_engine.redact(text)

        assert redacted == text
        assert len(mappings) == 0

    def test_clear_cache(self, aws_engine):
        """Test cache clearing"""
        text = "Account: 123456789012"
        aws_engine.redact(text)

        assert len(aws_engine.mapping_cache) > 0
        assert len(aws_engine.audit_trail) > 0

        aws_engine.clear_cache()

        assert len(aws_engine.mapping_cache) == 0
        assert len(aws_engine.audit_trail) == 0

    def test_export_audit_log(self, aws_engine, tmp_path):
        """Test audit log export"""
        text = "Account: 123456789012 with email user@example.com"
        aws_engine.redact(text)

        audit_file = tmp_path / "audit.json"
        aws_engine.export_audit_log(str(audit_file))

        assert audit_file.exists()

        import json
        with open(audit_file, 'r') as f:
            audit_data = json.load(f)

        assert 'provider' in audit_data
        assert 'total_redactions' in audit_data
        assert audit_data['provider'] == 'aws'

    def test_deterministic_replacement(self, aws_engine):
        """Test deterministic replacement generation"""
        account_id = "123456789012"

        # Create two separate engines to test determinism
        engine1 = ObfuscationEngine(provider='aws', consistent_mapping=True)
        engine2 = ObfuscationEngine(provider='aws', consistent_mapping=True)

        redacted1, _ = engine1.redact(f"Account: {account_id}")
        redacted2, _ = engine2.redact(f"Account: {account_id}")

        # Should produce same redacted output
        assert redacted1 == redacted2

    def test_arn_redaction(self, aws_engine):
        """Test AWS ARN redaction"""
        arn = "arn:aws:iam::123456789012:role/MyRole"
        text = f"ARN: {arn}"

        redacted, mappings = aws_engine.redact(text)

        # Account ID within ARN should be redacted
        assert "123456789012" not in redacted
        assert "arn:aws:iam::" in redacted
