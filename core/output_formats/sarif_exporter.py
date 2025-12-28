"""
SARIF Exporter
Exports scan results to SARIF (Static Analysis Results Interchange Format).
SARIF is a standard format for static analysis tool output.
"""

import json
from datetime import datetime
from typing import List, Dict, Any
from core.policy import Policy
from core.output_formats.base_exporter import BaseExporter


class SARIFExporter(BaseExporter):
    """
    Export scan results to SARIF format.

    SARIF is a standard JSON format for static analysis results,
    supported by GitHub Security, VS Code, and other tools.
    """

    def export(self, policies: List[Policy], filename: str, metadata: Dict[str, Any] = None) -> str:
        """
        Export policies to SARIF format.

        Args:
            policies: List of Policy objects to export
            filename: Output filename (without extension)
            metadata: Additional metadata to include

        Returns:
            Full path to exported file
        """
        output_file = self.get_full_path(filename, '.sarif')

        # Build SARIF structure
        sarif = {
            'version': '2.1.0',
            '$schema': 'https://json.schemastore.org/sarif-2.1.0.json',
            'runs': [
                {
                    'tool': {
                        'driver': {
                            'name': 'llm-cloudpolicy-scanner',
                            'informationUri': 'https://github.com/ethanolivertroy/llm-cloudpolicy-scanner',
                            'version': '1.0.0',
                            'semanticVersion': '1.0.0',
                            'rules': self._generate_rules()
                        }
                    },
                    'results': self._generate_results(policies),
                    'properties': {
                        'scan_timestamp': datetime.utcnow().isoformat() + 'Z',
                        'total_policies': len(policies),
                        'vulnerable_count': self.count_vulnerable(policies),
                        'by_provider': self.count_by_provider(policies),
                        **(metadata or {})
                    }
                }
            ]
        }

        # Write SARIF file
        with open(output_file, 'w') as f:
            json.dump(sarif, f, indent=2, ensure_ascii=False)

        return output_file

    def _generate_rules(self) -> List[Dict[str, Any]]:
        """Generate SARIF rule definitions."""
        return [
            {
                'id': 'POLICY-VULN-001',
                'name': 'VulnerableCloudPolicy',
                'shortDescription': {
                    'text': 'Cloud policy contains security vulnerabilities'
                },
                'fullDescription': {
                    'text': 'The cloud IAM policy has been analyzed by AI and determined to contain security vulnerabilities that could lead to unauthorized access, privilege escalation, or data exposure.'
                },
                'help': {
                    'text': 'Review the AI analysis for specific vulnerabilities and remediation steps. Consider implementing least privilege principles, removing wildcard permissions, and adding appropriate conditions.'
                },
                'defaultConfiguration': {
                    'level': 'error'
                },
                'properties': {
                    'tags': ['security', 'iam', 'cloud'],
                    'precision': 'high'
                }
            },
            {
                'id': 'POLICY-OVERPERM-001',
                'name': 'OverlyPermissivePolicy',
                'shortDescription': {
                    'text': 'Policy grants overly broad permissions'
                },
                'fullDescription': {
                    'text': 'The policy uses wildcard permissions or grants access to all resources, violating the principle of least privilege.'
                },
                'defaultConfiguration': {
                    'level': 'warning'
                },
                'properties': {
                    'tags': ['security', 'permissions', 'least-privilege']
                }
            },
            {
                'id': 'POLICY-PUBLIC-001',
                'name': 'PublicAccessGranted',
                'shortDescription': {
                    'text': 'Policy allows public access to resources'
                },
                'fullDescription': {
                    'text': 'The policy grants access to public or unauthenticated principals, potentially exposing sensitive resources.'
                },
                'defaultConfiguration': {
                    'level': 'error'
                },
                'properties': {
                    'tags': ['security', 'public-access', 'exposure']
                }
            }
        ]

    def _generate_results(self, policies: List[Policy]) -> List[Dict[str, Any]]:
        """Generate SARIF results from policies."""
        results = []

        for policy in policies:
            if not policy.is_vulnerable():
                # Skip safe policies in SARIF (only report issues)
                continue

            # Determine provider and location
            provider = 'Unknown'
            location_uri = 'policy://unknown'

            if hasattr(policy, 'arn'):
                provider = 'AWS'
                location_uri = f"arn://{policy.arn}"
            elif hasattr(policy, 'subscription_id'):
                provider = 'Azure'
                location_uri = f"azure://{policy.subscription_id}/{policy.name}"
            elif hasattr(policy, 'project_id'):
                provider = 'GCP'
                location_uri = f"gcp://{policy.project_id}/{policy.name}"

            # Determine severity from AI response
            level = self._determine_severity(policy.ai_response or '')

            result = {
                'ruleId': 'POLICY-VULN-001',
                'level': level,
                'message': {
                    'text': f"Vulnerable {provider} policy detected: {policy.name}"
                },
                'locations': [
                    {
                        'physicalLocation': {
                            'artifactLocation': {
                                'uri': location_uri
                            },
                            'region': {
                                'startLine': 1
                            }
                        },
                        'logicalLocations': [
                            {
                                'fullyQualifiedName': policy.name,
                                'kind': 'policy'
                            }
                        ]
                    }
                ],
                'properties': {
                    'provider': provider,
                    'policy_name': policy.name,
                    'ai_analysis': policy.ai_response or 'No analysis available'
                }
            }

            # Add provider-specific properties
            if hasattr(policy, 'arn'):
                result['properties']['account'] = getattr(policy, 'account', '')
                result['properties']['arn'] = policy.arn
            elif hasattr(policy, 'subscription_id'):
                result['properties']['subscription_id'] = policy.subscription_id
                result['properties']['resource_group'] = getattr(policy, 'resource_group', '')
            elif hasattr(policy, 'project_id'):
                result['properties']['project_id'] = policy.project_id

            results.append(result)

        return results

    def _determine_severity(self, ai_response: str) -> str:
        """
        Determine SARIF severity level from AI response.

        Returns:
            'error', 'warning', or 'note'
        """
        response_lower = ai_response.lower()

        # Check for severity indicators
        if any(word in response_lower for word in ['critical', 'severe', 'high risk', 'dangerous']):
            return 'error'
        elif any(word in response_lower for word in ['medium', 'moderate', 'concern']):
            return 'warning'
        elif any(word in response_lower for word in ['low', 'minor', 'note']):
            return 'note'
        else:
            # Default to error for vulnerabilities
            return 'error'
