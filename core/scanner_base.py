"""
Base scanner class with shared functionality for all cloud providers.
Eliminates code duplication across AWS, Azure, and GCP scanners.
"""

import os
import csv
import logging
from abc import ABC, abstractmethod
from datetime import datetime
from typing import List, Optional
from openai import OpenAI
import yaml

from core.policy import Policy
from core.obfuscation import ObfuscationEngine


class ScannerBase(ABC):
    """Abstract base class for cloud policy scanners."""

    def __init__(self, api_key: str, provider: str, config_path: str = "config.yaml"):
        """
        Initialize the scanner with OpenAI client and configuration.

        Args:
            api_key: OpenAI API key
            provider: Cloud provider name ('aws', 'azure', 'gcp')
            config_path: Path to configuration YAML file
        """
        self.openai_client = OpenAI(api_key=api_key)
        self.provider = provider.lower()
        self.results: List[Policy] = []
        self.config = self._load_config(config_path)
        self.logger = self._setup_logging()
        self.obfuscation_engine: Optional[ObfuscationEngine] = None
        self._init_obfuscation()

    def _load_config(self, config_path: str) -> dict:
        """Load configuration from YAML file."""
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            self.log(f"Config file {config_path} not found, using defaults")
            return self._default_config()

    def _default_config(self) -> dict:
        """Return default configuration if config file not found."""
        return {
            'llm': {
                'model': 'gpt-4',
                'temperature': 0.5,
                'max_tokens': 1000,
                'top_p': 1,
                'frequency_penalty': 0.0,
                'presence_penalty': 0.0,
                'stream': False
            },
            'output': {
                'directory': './cache',
                'include_timestamp': True
            },
            'logging': {
                'level': 'INFO',
                'format': '[%(levelname)s] %(message)s',
                'console': True
            }
        }

    def _setup_logging(self) -> logging.Logger:
        """Setup logging based on configuration."""
        log_config = self.config.get('logging', {})
        level = getattr(logging, log_config.get('level', 'INFO'))
        format_str = log_config.get('format', '[%(levelname)s] %(message)s')

        logger = logging.getLogger(self.__class__.__name__)
        logger.setLevel(level)

        # Console handler
        if log_config.get('console', True):
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(logging.Formatter(format_str))
            logger.addHandler(console_handler)

        # File handler
        if 'file' in log_config:
            file_handler = logging.FileHandler(log_config['file'])
            file_handler.setFormatter(logging.Formatter(format_str))
            logger.addHandler(file_handler)

        return logger

    def _init_obfuscation(self):
        """Initialize obfuscation engine based on configuration."""
        obf_config = self.config.get('obfuscation', {})
        if obf_config.get('enabled', True):
            self.obfuscation_engine = ObfuscationEngine(
                provider=self.provider,
                consistent_mapping=obf_config.get('consistent_mapping', True),
                audit_log=obf_config.get('audit_log', True)
            )

    def log(self, message: str):
        """Log a message (backwards compatible with old print-based logging)."""
        self.logger.info(message)

    def export_obfuscation_audit(self):
        """Export obfuscation audit log if enabled."""
        if not self.obfuscation_engine:
            return

        obf_config = self.config.get('obfuscation', {})
        if obf_config.get('export_audit', False):
            filename = obf_config.get('audit_filename', 'cache/redaction_audit.json')
            self.obfuscation_engine.export_audit_log(filename)
            self.log(f'Exported obfuscation audit log to {filename}')

    def check_policy(self, policy: Policy, cloud_provider: str) -> Policy:
        """
        Check a policy for vulnerabilities using OpenAI API.

        Args:
            policy: Policy object to check
            cloud_provider: Name of cloud provider (AWS, Azure, GCP)

        Returns:
            Policy object with ai_response populated
        """
        llm_config = self.config.get('llm', {})

        prompt = f'Does this {cloud_provider} policy have any security vulnerabilities: \n{policy.redacted_document}'

        try:
            response = self.openai_client.chat.completions.create(
                model=llm_config.get('model', 'gpt-4'),
                messages=[
                    {
                        "role": "system",
                        "content": "You are a cloud security expert. Analyze the policy and determine if it has security vulnerabilities. Start your response with 'Yes,' if it has vulnerabilities or 'No,' if it does not."
                    },
                    {"role": "user", "content": prompt}
                ],
                temperature=llm_config.get('temperature', 0.5),
                max_tokens=llm_config.get('max_tokens', 1000),
                top_p=llm_config.get('top_p', 1),
                frequency_penalty=llm_config.get('frequency_penalty', 0.0),
                presence_penalty=llm_config.get('presence_penalty', 0.0),
                stream=llm_config.get('stream', False),
            )

            policy.ai_response = response.choices[0].message.content.strip()
            is_vulnerable = policy.is_vulnerable()
            self.log(f'Policy {policy.name} [{is_vulnerable}]')

        except Exception as e:
            self.logger.error(f'Error checking policy {policy.name}: {str(e)}')
            policy.ai_response = f'ERROR: {str(e)}'

        return policy

    def preserve(self, filename: str, header: List[str], results: List[Policy],
                 row_builder: callable):
        """
        Save scan results to CSV file.

        Args:
            filename: Output filename
            header: CSV header row
            results: List of Policy objects
            row_builder: Function that takes a Policy and returns a dict for CSV row
        """
        output_config = self.config.get('output', {})
        output_dir = output_config.get('directory', './cache')

        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)

        mode = 'a' if os.path.exists(filename) else 'w'
        self.log(f'Saving scan: {filename}')

        try:
            with open(filename, mode) as f:
                writer = csv.DictWriter(f, fieldnames=header)
                if mode == 'w':
                    writer.writeheader()
                for data in results:
                    row = row_builder(data)
                    writer.writerow(row)
        except Exception as e:
            self.logger.error(f'Error saving results to {filename}: {str(e)}')
            raise

    def get_scan_timestamp(self) -> str:
        """Get formatted timestamp for scan outputs."""
        output_config = self.config.get('output', {})
        if output_config.get('include_timestamp', True):
            return datetime.utcnow().strftime("%Y-%m-%d-%H%MZ")
        return ""

    @abstractmethod
    def scan(self):
        """
        Main scan method to be implemented by each cloud provider.
        This method should retrieve policies and populate self.results.
        """
        pass

    @abstractmethod
    def redact_policy(self, policy: Policy) -> Policy:
        """
        Redact sensitive information from policy.
        Implementation is cloud-provider specific.

        Args:
            policy: Policy object to redact

        Returns:
            Policy object with redacted_document populated
        """
        pass
