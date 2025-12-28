"""
Advanced Obfuscation Engine
Provides sophisticated redaction with consistent anonymization and audit logging.
"""

import re
import uuid
import random
import json
import hashlib
from typing import Dict, List, Tuple, Optional
from datetime import datetime

from core.redaction_patterns import RedactionPatterns


class ObfuscationEngine:
    """
    Advanced obfuscation engine with consistent anonymization.

    Features:
    - Multi-pattern redaction across different data types
    - Consistent mapping (same sensitive value always maps to same redacted value)
    - Audit logging of all redactions
    - Configurable redaction patterns
    """

    def __init__(self, provider: str, consistent_mapping: bool = True, audit_log: bool = True):
        """
        Initialize obfuscation engine.

        Args:
            provider: Cloud provider ('aws', 'azure', 'gcp')
            consistent_mapping: If True, same input always maps to same output
            audit_log: If True, track all redactions for audit purposes
        """
        self.provider = provider.lower()
        self.patterns = RedactionPatterns.get_patterns_for_provider(self.provider)
        self.consistent_mapping = consistent_mapping
        self.audit_log = audit_log

        # Mapping cache for consistent anonymization
        self.mapping_cache: Dict[str, str] = {}

        # Audit trail
        self.audit_trail: List[Dict] = []

    def _generate_deterministic_replacement(self, original: str, pattern_type: str) -> str:
        """
        Generate a deterministic replacement value.
        If consistent_mapping is True, same input always produces same output.

        Args:
            original: Original sensitive value
            pattern_type: Type of pattern being replaced

        Returns:
            Redacted replacement value
        """
        if self.consistent_mapping:
            # Check cache first
            cache_key = f"{pattern_type}:{original}"
            if cache_key in self.mapping_cache:
                return self.mapping_cache[cache_key]

        # Generate replacement based on pattern type
        if pattern_type == 'account_id':
            # AWS account ID: 12-digit number
            if self.consistent_mapping:
                # Use hash to generate consistent but different number
                hash_val = int(hashlib.md5(original.encode()).hexdigest()[:12], 16)
                replacement = str(hash_val % 1000000000000).zfill(12)
            else:
                replacement = str(random.randint(100000000000, 999999999999))

        elif pattern_type in ['subscription_id', 'tenant_id', 'principal_id']:
            # Azure UUIDs
            if self.consistent_mapping:
                # Generate deterministic UUID from hash
                hash_val = hashlib.md5(original.encode()).hexdigest()
                replacement = f"{hash_val[:8]}-{hash_val[8:12]}-{hash_val[12:16]}-{hash_val[16:20]}-{hash_val[20:32]}"
            else:
                replacement = str(uuid.uuid4())

        elif pattern_type == 'project_id':
            # GCP project ID: lowercase letters, numbers, hyphens
            if self.consistent_mapping:
                hash_val = hashlib.md5(original.encode()).hexdigest()[:8]
                replacement = f"project-{hash_val}"
            else:
                replacement = f"project-{random.randint(10000, 99999)}"

        elif pattern_type == 'project_number':
            # GCP project number: 12-digit number
            if self.consistent_mapping:
                hash_val = int(hashlib.md5(original.encode()).hexdigest()[:12], 16)
                replacement = str(hash_val % 1000000000000).zfill(12)
            else:
                replacement = str(random.randint(100000000000, 999999999999))

        elif pattern_type in ['ipv4', 'ipv6']:
            # IP addresses
            if self.consistent_mapping:
                hash_val = hashlib.md5(original.encode()).hexdigest()
                if pattern_type == 'ipv4':
                    replacement = f"{int(hash_val[:2], 16) % 256}.{int(hash_val[2:4], 16) % 256}.{int(hash_val[4:6], 16) % 256}.{int(hash_val[6:8], 16) % 256}"
                else:
                    replacement = f"{hash_val[:4]}:{hash_val[4:8]}:{hash_val[8:12]}:{hash_val[12:16]}:{hash_val[16:20]}:{hash_val[20:24]}:{hash_val[24:28]}:{hash_val[28:32]}"
            else:
                if pattern_type == 'ipv4':
                    replacement = f"{random.randint(10, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}"
                else:
                    replacement = ':'.join(f"{random.randint(0, 65535):04x}" for _ in range(8))

        elif pattern_type == 'email':
            # Email addresses
            if self.consistent_mapping:
                hash_val = hashlib.md5(original.encode()).hexdigest()[:10]
                replacement = f"user-{hash_val}@example.com"
            else:
                replacement = f"user-{random.randint(1000, 9999)}@example.com"

        elif pattern_type in ['arn', 'iam_user', 'iam_role']:
            # AWS ARNs - replace the account ID part
            if self.consistent_mapping:
                hash_val = int(hashlib.md5(original.encode()).hexdigest()[:12], 16)
                account_replacement = str(hash_val % 1000000000000).zfill(12)
                # Replace account ID in ARN
                replacement = re.sub(r'\d{12}', account_replacement, original)
            else:
                account_replacement = str(random.randint(100000000000, 999999999999))
                replacement = re.sub(r'\d{12}', account_replacement, original)

        elif pattern_type == 'service_account':
            # GCP service account
            if self.consistent_mapping:
                hash_val = hashlib.md5(original.encode()).hexdigest()[:10]
                replacement = f"sa-{hash_val}@{hash_val}.iam.gserviceaccount.com"
            else:
                random_id = f"{random.randint(1000, 9999)}"
                replacement = f"sa-{random_id}@project-{random_id}.iam.gserviceaccount.com"

        elif pattern_type == 'resource_id':
            # Azure resource IDs
            if self.consistent_mapping:
                hash_val = hashlib.md5(original.encode()).hexdigest()
                replacement = original  # Keep structure but replace subscription ID
                sub_id_replacement = f"{hash_val[:8]}-{hash_val[8:12]}-{hash_val[12:16]}-{hash_val[16:20]}-{hash_val[20:32]}"
                replacement = re.sub(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
                                    sub_id_replacement, replacement, count=1)
            else:
                replacement = re.sub(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
                                    str(uuid.uuid4()), original, count=1)

        else:
            # Generic replacement
            if self.consistent_mapping:
                hash_val = hashlib.md5(original.encode()).hexdigest()[:16]
                replacement = f"redacted-{hash_val}"
            else:
                replacement = f"redacted-{random.randint(1000, 9999)}"

        # Cache the mapping
        if self.consistent_mapping:
            cache_key = f"{pattern_type}:{original}"
            self.mapping_cache[cache_key] = replacement

        return replacement

    def redact(self, text: str, enabled_patterns: Optional[List[str]] = None) -> Tuple[str, Dict[str, str]]:
        """
        Redact sensitive information from text.

        Args:
            text: Text to redact
            enabled_patterns: List of pattern names to apply (None = all patterns)

        Returns:
            Tuple of (redacted_text, mappings_dict)
        """
        if not text:
            return text, {}

        redacted_text = text
        mappings = {}

        # Determine which patterns to use
        patterns_to_apply = self.patterns
        if enabled_patterns:
            patterns_to_apply = {k: v for k, v in self.patterns.items() if k in enabled_patterns}

        # Apply each pattern
        for pattern_name, pattern_regex in patterns_to_apply.items():
            matches = re.finditer(pattern_regex, redacted_text, re.IGNORECASE)

            for match in matches:
                original_value = match.group(0)

                # Special handling for patterns with groups
                if pattern_name == 'project_id' and match.groups():
                    original_value = match.group(1)

                # Generate replacement
                replacement = self._generate_deterministic_replacement(original_value, pattern_name)

                # Apply redaction
                redacted_text = redacted_text.replace(original_value, replacement)

                # Track mapping
                mappings[original_value] = replacement

                # Audit trail
                if self.audit_log:
                    self.audit_trail.append({
                        'timestamp': datetime.utcnow().isoformat(),
                        'pattern_type': pattern_name,
                        'original_length': len(original_value),
                        'replacement': replacement,
                        'provider': self.provider
                    })

        return redacted_text, mappings

    def get_mappings(self) -> Dict[str, str]:
        """Get all cached mappings."""
        return self.mapping_cache.copy()

    def get_audit_trail(self) -> List[Dict]:
        """Get audit trail of all redactions."""
        return self.audit_trail.copy()

    def export_audit_log(self, filename: str):
        """
        Export audit trail to JSON file.

        Args:
            filename: Output filename
        """
        with open(filename, 'w') as f:
            json.dump({
                'provider': self.provider,
                'total_redactions': len(self.audit_trail),
                'redactions': self.audit_trail,
                'mappings_count': len(self.mapping_cache)
            }, f, indent=2)

    def clear_cache(self):
        """Clear mapping cache and audit trail."""
        self.mapping_cache.clear()
        self.audit_trail.clear()
