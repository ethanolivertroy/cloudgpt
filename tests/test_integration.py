"""
Integration tests with mocked cloud APIs
"""

import pytest
import json
from unittest.mock import Mock, patch, MagicMock
from core.scanner_base import ScannerBase
from core.policy import Policy


@pytest.mark.integration
class TestScannerBaseIntegration:
    """Integration tests for ScannerBase"""

    def test_check_policy_single_agent(self):
        """Test single-agent policy checking"""
        # Create a minimal concrete scanner for testing
        class TestScanner(ScannerBase):
            def __init__(self, api_key):
                super().__init__(api_key, provider='test')

            def scan(self):
                pass

            def redact_policy(self, policy):
                policy.redacted_document = policy.policy
                return policy

        with patch('core.scanner_base.OpenAI') as mock_openai:
            # Mock OpenAI response
            mock_response = Mock()
            mock_response.choices = [Mock()]
            mock_response.choices[0].message.content = "Yes, this policy has vulnerabilities"

            mock_client = Mock()
            mock_client.chat.completions.create.return_value = mock_response
            mock_openai.return_value = mock_client

            scanner = TestScanner('test-api-key')
            policy = Policy()
            policy.name = "test-policy"
            policy.policy = '{"Statement": []}'
            policy.redacted_document = '{"Statement": []}'

            result = scanner.check_policy(policy, 'Test')

            assert result.ai_response == "Yes, this policy has vulnerabilities"
            assert result.is_vulnerable() is True

    def test_parallel_processing(self):
        """Test parallel policy processing"""
        class TestScanner(ScannerBase):
            def __init__(self, api_key):
                super().__init__(api_key, provider='test')
                # Enable parallel processing
                self.config['scanning'] = {'parallel': True, 'max_workers': 2}

            def scan(self):
                pass

            def redact_policy(self, policy):
                policy.redacted_document = policy.policy
                return policy

        with patch('core.scanner_base.OpenAI') as mock_openai:
            mock_response = Mock()
            mock_response.choices = [Mock()]
            mock_response.choices[0].message.content = "No, policy is secure"

            mock_client = Mock()
            mock_client.chat.completions.create.return_value = mock_response
            mock_openai.return_value = mock_client

            scanner = TestScanner('test-api-key')

            # Create test policies
            policies = []
            for i in range(5):
                p = Policy()
                p.name = f"policy-{i}"
                p.policy = '{"Statement": []}'
                p.redacted_document = '{"Statement": []}'
                policies.append(p)

            # Process in parallel
            results = scanner.process_policies_parallel(policies, 'Test')

            assert len(results) == 5
            for result in results:
                assert result.ai_response is not None

    def test_checkpoint_save_load(self, tmp_path):
        """Test checkpoint save and load"""
        class TestScanner(ScannerBase):
            def __init__(self, api_key):
                super().__init__(api_key, provider='test')

            def scan(self):
                pass

            def redact_policy(self, policy):
                return policy

        with patch('core.scanner_base.OpenAI'):
            scanner = TestScanner('test-api-key')

            # Add some results
            for i in range(3):
                p = Policy()
                p.name = f"policy-{i}"
                scanner.results.append(p)

            # Save checkpoint
            checkpoint_file = tmp_path / "checkpoint.pkl"
            scanner.save_checkpoint(str(checkpoint_file))

            assert checkpoint_file.exists()

            # Create new scanner and load checkpoint
            scanner2 = TestScanner('test-api-key')
            loaded = scanner2.load_checkpoint(str(checkpoint_file))

            assert loaded is True
            assert len(scanner2.results) == 3
            assert scanner2.results[0].name == "policy-0"

    def test_export_multiple_formats(self, tmp_path):
        """Test multi-format export"""
        class TestScanner(ScannerBase):
            def __init__(self, api_key):
                super().__init__(api_key, provider='test')
                self.config['output'] = {
                    'formats': ['json', 'html', 'sarif'],
                    'directory': str(tmp_path)
                }

            def scan(self):
                pass

            def redact_policy(self, policy):
                return policy

        with patch('core.scanner_base.OpenAI'):
            scanner = TestScanner('test-api-key')

            # Add test policy
            p = Policy()
            p.name = "test-policy"
            p.ai_response = "Yes, vulnerable"
            scanner.results.append(p)

            # Export
            scanner.export_multiple_formats("test_scan")

            # Check files were created
            assert (tmp_path / "test_scan.json").exists()
            assert (tmp_path / "test_scan.html").exists()
            assert (tmp_path / "test_scan.sarif").exists()


@pytest.mark.integration
@pytest.mark.aws
class TestAWSIntegration:
    """Integration tests for AWS scanner with mocked APIs"""

    @patch('boto3.Session')
    def test_aws_scanner_initialization(self, mock_session):
        """Test AWS scanner initialization with mocked boto3"""
        mock_iam = Mock()
        mock_sts = Mock()
        mock_sts.get_caller_identity.return_value = {'Account': '123456789012'}

        mock_session_instance = Mock()
        mock_session_instance.client.side_effect = lambda service: {
            'iam': mock_iam,
            'sts': mock_sts
        }[service]

        mock_session.return_value = mock_session_instance

        with patch('core.scanner_base.OpenAI'):
            from aws_scan import AWSScanner
            scanner = AWSScanner('test-api-key', profile='default')

            assert scanner.account == '123456789012'

    @patch('boto3.Session')
    def test_aws_policy_scan(self, mock_session):
        """Test AWS policy scanning with mocked IAM API"""
        # Mock IAM responses
        mock_iam = Mock()
        mock_iam.get_paginator.return_value.paginate.return_value = [
            {
                'Policies': [
                    {
                        'PolicyName': 'TestPolicy',
                        'Arn': 'arn:aws:iam::123456789012:policy/TestPolicy',
                        'DefaultVersionId': 'v1'
                    }
                ]
            }
        ]

        mock_iam.get_policy_version.return_value = {
            'PolicyVersion': {
                'VersionId': 'v1',
                'Document': {
                    'Statement': [{
                        'Effect': 'Allow',
                        'Action': 's3:GetObject',
                        'Resource': '*'
                    }]
                }
            }
        }

        mock_sts = Mock()
        mock_sts.get_caller_identity.return_value = {'Account': '123456789012'}

        mock_session_instance = Mock()
        mock_session_instance.client.side_effect = lambda service: {
            'iam': mock_iam,
            'sts': mock_sts
        }[service]

        mock_session.return_value = mock_session_instance

        with patch('core.scanner_base.OpenAI') as mock_openai:
            mock_response = Mock()
            mock_response.choices = [Mock()]
            mock_response.choices[0].message.content = "No, policy is secure"

            mock_client = Mock()
            mock_client.chat.completions.create.return_value = mock_response
            mock_openai.return_value = mock_client

            from aws_scan import AWSScanner
            scanner = AWSScanner('test-api-key', profile='default')
            scanner.scan(redact=True)

            assert len(scanner.results) > 0
            assert scanner.results[0].name == 'TestPolicy'


@pytest.mark.integration
class TestNeo4jIntegration:
    """Integration tests for Neo4j graph builder"""

    def test_graph_builder_initialization(self):
        """Test graph builder initialization"""
        with patch('core.neo4j_client.GraphDatabase'):
            from core.neo4j_client import Neo4jClient
            from core.graph_builder import GraphBuilder

            mock_client = Mock(spec=Neo4jClient)
            builder = GraphBuilder(mock_client, 'aws')

            assert builder.provider == 'aws'
            assert builder.client == mock_client

    def test_policy_graph_building(self):
        """Test building graph from policy"""
        with patch('core.neo4j_client.GraphDatabase'):
            from core.neo4j_client import Neo4jClient
            from core.graph_builder import GraphBuilder

            mock_client = Mock(spec=Neo4jClient)
            mock_client.create_policy.return_value = {}
            mock_client.create_principal.return_value = {}
            mock_client.create_action.return_value = {}
            mock_client.create_resource.return_value = {}
            mock_client.create_relationship.return_value = {}

            builder = GraphBuilder(mock_client, 'aws')

            policy = Policy()
            policy.name = "TestPolicy"
            policy.arn = "arn:aws:iam::123456789012:policy/TestPolicy"
            policy.account = "123456789012"
            policy.policy = {
                'Statement': [{
                    'Effect': 'Allow',
                    'Action': 's3:GetObject',
                    'Resource': 'arn:aws:s3:::my-bucket/*',
                    'Principal': {'AWS': 'arn:aws:iam::123456789012:user/testuser'}
                }]
            }
            policy.ai_response = "No vulnerabilities"

            stats = builder.build_policy_graph(policy)

            assert stats['policies'] >= 1


@pytest.mark.integration
class TestOutputFormatIntegration:
    """Integration tests for output formats"""

    def test_end_to_end_export(self, tmp_path):
        """Test end-to-end export workflow"""
        # Create scanner with results
        class TestScanner(ScannerBase):
            def __init__(self):
                with patch('core.scanner_base.OpenAI'):
                    super().__init__('test-key', provider='test')
                self.config['output'] = {
                    'formats': ['csv', 'json', 'html', 'sarif'],
                    'directory': str(tmp_path)
                }

            def scan(self):
                pass

            def redact_policy(self, policy):
                return policy

        scanner = TestScanner()

        # Add results
        for i in range(10):
            p = Policy()
            p.name = f"policy-{i}"
            p.ai_response = "Yes, vulnerable" if i % 2 == 0 else "No, secure"
            scanner.results.append(p)

        # Export all formats
        scanner.export_multiple_formats("integration_test")

        # Verify all formats created
        assert (tmp_path / "integration_test.json").exists()
        assert (tmp_path / "integration_test.html").exists()
        assert (tmp_path / "integration_test.sarif").exists()

        # Verify JSON content
        with open(tmp_path / "integration_test.json", 'r') as f:
            data = json.load(f)
            assert data['scan_metadata']['total_policies'] == 10
            assert data['scan_metadata']['vulnerable_count'] == 5

        # Verify SARIF content
        with open(tmp_path / "integration_test.sarif", 'r') as f:
            sarif = json.load(f)
            # Only vulnerable policies in SARIF
            assert len(sarif['runs'][0]['results']) == 5
