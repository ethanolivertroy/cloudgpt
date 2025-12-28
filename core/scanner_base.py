"""
Base scanner class with shared functionality for all cloud providers.
Eliminates code duplication across AWS, Azure, and GCP scanners.
"""

import os
import csv
import json
import logging
import pickle
from abc import ABC, abstractmethod
from datetime import datetime
from typing import List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from openai import OpenAI
import yaml
from tqdm import tqdm

from core.policy import Policy
from core.obfuscation import ObfuscationEngine

# Import multi-agent support (optional)
try:
    from agents.orchestrator import analyze_policy_with_crew
    CREW_AVAILABLE = True
except ImportError:
    CREW_AVAILABLE = False

# Import Neo4j graph support (optional)
try:
    from core.neo4j_client import create_neo4j_client_from_config
    from core.graph_builder import GraphBuilder
    NEO4J_AVAILABLE = True
except ImportError:
    NEO4J_AVAILABLE = False

# Import output format exporters (optional)
try:
    from core.output_formats.json_exporter import JSONExporter
    from core.output_formats.html_exporter import HTMLExporter
    from core.output_formats.sarif_exporter import SARIFExporter
    EXPORTERS_AVAILABLE = True
except ImportError:
    EXPORTERS_AVAILABLE = False


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
        self.neo4j_client = None
        self.graph_builder = None
        self.scan_start_time = None
        self.scan_end_time = None
        self._init_obfuscation()
        self._init_neo4j()

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

    def _init_neo4j(self):
        """Initialize Neo4j client and graph builder based on configuration."""
        if not NEO4J_AVAILABLE:
            return

        try:
            self.neo4j_client = create_neo4j_client_from_config(self.config)
            if self.neo4j_client:
                self.graph_builder = GraphBuilder(self.neo4j_client, self.provider)
                self.log('Neo4j graph database initialized successfully')
        except Exception as e:
            self.logger.warning(f'Neo4j initialization failed: {str(e)}')

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

    def export_to_neo4j(self):
        """Export scan results to Neo4j graph database."""
        if not self.graph_builder or not self.neo4j_client:
            return

        self.log(f'Exporting {len(self.results)} policies to Neo4j graph database...')

        total_stats = {
            'principals': 0,
            'resources': 0,
            'actions': 0,
            'policies': 0,
            'relationships': 0
        }

        for policy in self.results:
            try:
                stats = self.graph_builder.build_policy_graph(policy)
                for key in total_stats:
                    total_stats[key] += stats.get(key, 0)
            except Exception as e:
                self.logger.error(f'Error exporting policy {policy.name} to Neo4j: {str(e)}')
                continue

        # Get final database statistics
        db_stats = self.neo4j_client.get_statistics()

        self.log(f'Neo4j export complete:')
        self.log(f'  - Created {total_stats["principals"]} principals')
        self.log(f'  - Created {total_stats["resources"]} resources')
        self.log(f'  - Created {total_stats["actions"]} actions')
        self.log(f'  - Created {total_stats["policies"]} policies')
        self.log(f'  - Created {total_stats["relationships"]} relationships')
        self.log(f'  - Total nodes in database: {db_stats.get("total_nodes", 0)}')
        self.log(f'  - Total relationships: {db_stats.get("relationships", 0)}')

    def check_policy(self, policy: Policy, cloud_provider: str) -> Policy:
        """
        Check a policy for vulnerabilities using AI analysis.

        Supports both single-agent and multi-agent analysis based on configuration.

        Args:
            policy: Policy object to check
            cloud_provider: Name of cloud provider (AWS, Azure, GCP)

        Returns:
            Policy object with ai_response populated
        """
        llm_config = self.config.get('llm', {})
        multi_agent_config = self.config.get('multi_agent', {})

        # Check if multi-agent analysis is enabled
        if multi_agent_config.get('enabled', False) and CREW_AVAILABLE:
            return self._check_policy_multi_agent(policy, cloud_provider)
        else:
            return self._check_policy_single_agent(policy, cloud_provider)

    def _check_policy_single_agent(self, policy: Policy, cloud_provider: str) -> Policy:
        """
        Check policy using single-agent OpenAI analysis (legacy method).

        Args:
            policy: Policy object to check
            cloud_provider: Name of cloud provider

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
            self.log(f'Policy {policy.name} [Single-Agent: {is_vulnerable}]')

        except Exception as e:
            self.logger.error(f'Error checking policy {policy.name}: {str(e)}')
            policy.ai_response = f'ERROR: {str(e)}'

        return policy

    def _check_policy_multi_agent(self, policy: Policy, cloud_provider: str) -> Policy:
        """
        Check policy using multi-agent CrewAI analysis.

        Args:
            policy: Policy object to check
            cloud_provider: Name of cloud provider

        Returns:
            Policy object with ai_response populated
        """
        try:
            self.log(f'Running multi-agent analysis on policy {policy.name}...')

            # Use OpenAI client for agents
            result = analyze_policy_with_crew(
                policy_document=policy.redacted_document,
                cloud_provider=cloud_provider,
                llm=self.openai_client,
                verbose=self.config.get('multi_agent', {}).get('verbose', False)
            )

            policy.ai_response = result
            is_vulnerable = policy.is_vulnerable()
            self.log(f'Policy {policy.name} [Multi-Agent: {is_vulnerable}]')

        except Exception as e:
            self.logger.error(f'Error in multi-agent analysis for {policy.name}: {str(e)}')
            self.logger.info(f'Falling back to single-agent analysis for {policy.name}')
            return self._check_policy_single_agent(policy, cloud_provider)

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

    def process_policies_parallel(self, policies_to_process: List[Policy], cloud_provider: str) -> List[Policy]:
        """
        Process policies in parallel using thread pool.

        Args:
            policies_to_process: List of policies to analyze
            cloud_provider: Cloud provider name

        Returns:
            List of processed policies
        """
        scanning_config = self.config.get('scanning', {})
        max_workers = scanning_config.get('max_workers', 5)

        if not scanning_config.get('parallel', False) or len(policies_to_process) < 2:
            # Sequential processing with progress bar
            return [self.check_policy(p, cloud_provider) for p in tqdm(policies_to_process, desc="Analyzing policies")]

        # Parallel processing with progress bar
        processed_policies = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self.check_policy, policy, cloud_provider): policy
                      for policy in policies_to_process}

            with tqdm(total=len(policies_to_process), desc="Analyzing policies") as pbar:
                for future in as_completed(futures):
                    try:
                        processed_policy = future.result()
                        processed_policies.append(processed_policy)
                    except Exception as e:
                        policy = futures[future]
                        self.logger.error(f'Error processing policy {policy.name} in parallel: {str(e)}')
                    pbar.update(1)

        return processed_policies

    def save_checkpoint(self, checkpoint_file: str):
        """
        Save scan checkpoint for resume capability.

        Args:
            checkpoint_file: Path to checkpoint file
        """
        checkpoint_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'provider': self.provider,
            'results_count': len(self.results),
            'results': self.results
        }

        os.makedirs(os.path.dirname(checkpoint_file) if os.path.dirname(checkpoint_file) else '.', exist_ok=True)

        with open(checkpoint_file, 'wb') as f:
            pickle.dump(checkpoint_data, f)

        self.log(f'Checkpoint saved: {checkpoint_file}')

    def load_checkpoint(self, checkpoint_file: str) -> bool:
        """
        Load scan checkpoint to resume previous scan.

        Args:
            checkpoint_file: Path to checkpoint file

        Returns:
            True if checkpoint loaded successfully
        """
        if not os.path.exists(checkpoint_file):
            return False

        try:
            with open(checkpoint_file, 'rb') as f:
                checkpoint_data = pickle.load(f)

            self.results = checkpoint_data.get('results', [])
            self.log(f'Checkpoint loaded: {len(self.results)} policies restored from {checkpoint_file}')
            return True

        except Exception as e:
            self.logger.error(f'Error loading checkpoint: {str(e)}')
            return False

    def export_multiple_formats(self, base_filename: str, metadata: dict = None):
        """
        Export scan results to multiple formats.

        Args:
            base_filename: Base filename without extension
            metadata: Additional metadata to include
        """
        if not EXPORTERS_AVAILABLE:
            self.logger.warning('Output format exporters not available')
            return

        output_config = self.config.get('output', {})
        formats = output_config.get('formats', ['csv'])
        output_dir = output_config.get('directory', './cache')

        # Create metadata
        scan_metadata = {
            'provider': self.provider,
            'scan_start': self.scan_start_time.isoformat() if self.scan_start_time else None,
            'scan_end': self.scan_end_time.isoformat() if self.scan_end_time else None,
            'scan_duration_seconds': (self.scan_end_time - self.scan_start_time).total_seconds()
                                    if self.scan_start_time and self.scan_end_time else None,
            **(metadata or {})
        }

        # Export to each format
        for fmt in formats:
            try:
                if fmt == 'json':
                    exporter = JSONExporter(output_dir)
                    output_file = exporter.export(self.results, base_filename, scan_metadata)
                    self.log(f'Exported to JSON: {output_file}')

                elif fmt == 'html':
                    exporter = HTMLExporter(output_dir)
                    output_file = exporter.export(self.results, base_filename, scan_metadata)
                    self.log(f'Exported to HTML: {output_file}')

                elif fmt == 'sarif':
                    exporter = SARIFExporter(output_dir)
                    output_file = exporter.export(self.results, base_filename, scan_metadata)
                    self.log(f'Exported to SARIF: {output_file}')

            except Exception as e:
                self.logger.error(f'Error exporting to {fmt}: {str(e)}')

    def print_scan_summary(self):
        """Print scan summary statistics."""
        if not self.results:
            self.log('No policies scanned')
            return

        vulnerable_count = sum(1 for p in self.results if p.is_vulnerable())
        safe_count = len(self.results) - vulnerable_count

        # Calculate scan duration
        duration = None
        if self.scan_start_time and self.scan_end_time:
            duration = (self.scan_end_time - self.scan_start_time).total_seconds()

        self.log('')
        self.log('=' * 60)
        self.log('SCAN SUMMARY')
        self.log('=' * 60)
        self.log(f'Provider: {self.provider.upper()}')
        self.log(f'Total Policies: {len(self.results)}')
        self.log(f'Vulnerable: {vulnerable_count} ({vulnerable_count/len(self.results)*100:.1f}%)')
        self.log(f'Safe: {safe_count} ({safe_count/len(self.results)*100:.1f}%)')

        if duration:
            self.log(f'Scan Duration: {duration:.2f} seconds')
            self.log(f'Average Time per Policy: {duration/len(self.results):.2f} seconds')

        self.log('=' * 60)
        self.log('')

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
