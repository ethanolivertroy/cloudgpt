"""
Base Exporter Class
Abstract base class for all output format exporters.
"""

import os
from abc import ABC, abstractmethod
from typing import List, Dict, Any
from core.policy import Policy


class BaseExporter(ABC):
    """Abstract base class for output format exporters."""

    def __init__(self, output_dir: str = './cache'):
        """
        Initialize exporter.

        Args:
            output_dir: Directory to save output files
        """
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    @abstractmethod
    def export(self, policies: List[Policy], filename: str, metadata: Dict[str, Any] = None) -> str:
        """
        Export policies to the format.

        Args:
            policies: List of Policy objects to export
            filename: Output filename (without extension)
            metadata: Additional metadata to include

        Returns:
            Full path to exported file
        """
        pass

    def get_full_path(self, filename: str, extension: str) -> str:
        """
        Get full file path with extension.

        Args:
            filename: Base filename
            extension: File extension (with or without dot)

        Returns:
            Full file path
        """
        if not extension.startswith('.'):
            extension = f'.{extension}'

        if not filename.endswith(extension):
            filename = f'{filename}{extension}'

        return os.path.join(self.output_dir, filename)

    def count_vulnerable(self, policies: List[Policy]) -> int:
        """Count vulnerable policies."""
        return sum(1 for p in policies if p.is_vulnerable())

    def count_by_provider(self, policies: List[Policy]) -> Dict[str, int]:
        """Count policies by cloud provider."""
        counts = {}
        for policy in policies:
            # Try to determine provider from policy attributes
            provider = 'unknown'
            if hasattr(policy, 'arn'):
                provider = 'AWS'
            elif hasattr(policy, 'subscription_id'):
                provider = 'Azure'
            elif hasattr(policy, 'project_id'):
                provider = 'GCP'

            counts[provider] = counts.get(provider, 0) + 1

        return counts
