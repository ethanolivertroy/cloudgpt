"""
HTML Exporter
Exports scan results to HTML report format.
"""

from datetime import datetime
from typing import List, Dict, Any
from core.policy import Policy
from core.output_formats.base_exporter import BaseExporter


class HTMLExporter(BaseExporter):
    """Export scan results to HTML report format."""

    def export(self, policies: List[Policy], filename: str, metadata: Dict[str, Any] = None) -> str:
        """
        Export policies to HTML format.

        Args:
            policies: List of Policy objects to export
            filename: Output filename (without extension)
            metadata: Additional metadata to include

        Returns:
            Full path to exported file
        """
        output_file = self.get_full_path(filename, '.html')

        # Generate HTML content
        html_content = self._generate_html(policies, metadata or {})

        # Write HTML file
        with open(output_file, 'w') as f:
            f.write(html_content)

        return output_file

    def _generate_html(self, policies: List[Policy], metadata: Dict[str, Any]) -> str:
        """Generate HTML content."""
        vulnerable_count = self.count_vulnerable(policies)
        safe_count = len(policies) - vulnerable_count
        by_provider = self.count_by_provider(policies)

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cloud Policy Scan Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: #f5f5f5;
            padding: 20px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            overflow: hidden;
        }}
        header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
        }}
        header h1 {{
            margin-bottom: 10px;
        }}
        header p {{
            opacity: 0.9;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 40px;
            background: #f8f9fa;
        }}
        .stat-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }}
        .stat-value {{
            font-size: 36px;
            font-weight: bold;
            margin-bottom: 5px;
        }}
        .stat-value.vulnerable {{
            color: #dc3545;
        }}
        .stat-value.safe {{
            color: #28a745;
        }}
        .stat-label {{
            color: #666;
            font-size: 14px;
        }}
        .policies {{
            padding: 40px;
        }}
        .policy-card {{
            background: #f8f9fa;
            border-left: 4px solid #667eea;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 5px;
        }}
        .policy-card.vulnerable {{
            border-left-color: #dc3545;
            background: #fff5f5;
        }}
        .policy-card.safe {{
            border-left-color: #28a745;
        }}
        .policy-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }}
        .policy-name {{
            font-size: 18px;
            font-weight: 600;
            color: #333;
        }}
        .badge {{
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
        }}
        .badge.vulnerable {{
            background: #dc3545;
            color: white;
        }}
        .badge.safe {{
            background: #28a745;
            color: white;
        }}
        .badge.provider {{
            background: #667eea;
            color: white;
            margin-right: 10px;
        }}
        .policy-details {{
            font-size: 14px;
            color: #666;
            margin-bottom: 10px;
        }}
        .policy-analysis {{
            background: white;
            padding: 15px;
            border-radius: 5px;
            margin-top: 15px;
        }}
        .policy-analysis h4 {{
            color: #333;
            margin-bottom: 10px;
        }}
        .policy-analysis pre {{
            white-space: pre-wrap;
            word-wrap: break-word;
            color: #555;
            line-height: 1.6;
        }}
        .footer {{
            padding: 20px 40px;
            background: #f8f9fa;
            text-align: center;
            color: #666;
            font-size: 14px;
        }}
        .filter-buttons {{
            margin-bottom: 20px;
            display: flex;
            gap: 10px;
        }}
        .filter-btn {{
            padding: 10px 20px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-weight: 600;
            transition: all 0.3s;
        }}
        .filter-btn.active {{
            background: #667eea;
            color: white;
        }}
        .filter-btn:not(.active) {{
            background: white;
            border: 2px solid #e0e0e0;
            color: #666;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔐 Cloud Policy Scan Report</h1>
            <p>Generated on {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC</p>
        </header>

        <div class="summary">
            <div class="stat-card">
                <div class="stat-value">{len(policies)}</div>
                <div class="stat-label">Total Policies</div>
            </div>
            <div class="stat-card">
                <div class="stat-value vulnerable">{vulnerable_count}</div>
                <div class="stat-label">Vulnerable</div>
            </div>
            <div class="stat-card">
                <div class="stat-value safe">{safe_count}</div>
                <div class="stat-label">Safe</div>
            </div>
            {self._generate_provider_stats(by_provider)}
        </div>

        <div class="policies">
            <div class="filter-buttons">
                <button class="filter-btn active" onclick="filterPolicies('all')">All ({len(policies)})</button>
                <button class="filter-btn" onclick="filterPolicies('vulnerable')">Vulnerable ({vulnerable_count})</button>
                <button class="filter-btn" onclick="filterPolicies('safe')">Safe ({safe_count})</button>
            </div>

            <div id="policy-list">
                {self._generate_policy_cards(policies)}
            </div>
        </div>

        <div class="footer">
            Generated by llm-cloudpolicy-scanner | Multi-agent AI security analysis
        </div>
    </div>

    <script>
        function filterPolicies(filter) {{
            const cards = document.querySelectorAll('.policy-card');
            const buttons = document.querySelectorAll('.filter-btn');

            buttons.forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');

            cards.forEach(card => {{
                if (filter === 'all') {{
                    card.style.display = 'block';
                }} else if (filter === 'vulnerable' && card.classList.contains('vulnerable')) {{
                    card.style.display = 'block';
                }} else if (filter === 'safe' && card.classList.contains('safe')) {{
                    card.style.display = 'block';
                }} else {{
                    card.style.display = 'none';
                }}
            }});
        }}
    </script>
</body>
</html>"""
        return html

    def _generate_provider_stats(self, by_provider: Dict[str, int]) -> str:
        """Generate provider statistics cards."""
        html = ""
        for provider, count in by_provider.items():
            html += f"""
            <div class="stat-card">
                <div class="stat-value">{count}</div>
                <div class="stat-label">{provider}</div>
            </div>"""
        return html

    def _generate_policy_cards(self, policies: List[Policy]) -> str:
        """Generate policy cards HTML."""
        html = ""

        for policy in policies:
            is_vulnerable = policy.is_vulnerable()
            status_class = 'vulnerable' if is_vulnerable else 'safe'
            status_text = 'VULNERABLE' if is_vulnerable else 'SAFE'

            # Determine provider
            provider = 'Unknown'
            details = ""
            if hasattr(policy, 'arn'):
                provider = 'AWS'
                details = f"Account: {getattr(policy, 'account', 'N/A')} | ARN: {policy.arn}"
            elif hasattr(policy, 'subscription_id'):
                provider = 'Azure'
                details = f"Subscription: {policy.subscription_id} | Resource Group: {getattr(policy, 'resource_group', 'N/A')}"
            elif hasattr(policy, 'project_id'):
                provider = 'GCP'
                details = f"Project: {policy.project_id} | Type: {getattr(policy, 'policy_type', 'N/A')}"

            ai_response = policy.ai_response or "No analysis available"

            html += f"""
            <div class="policy-card {status_class}">
                <div class="policy-header">
                    <div class="policy-name">
                        <span class="badge provider">{provider}</span>
                        {policy.name}
                    </div>
                    <span class="badge {status_class}">{status_text}</span>
                </div>
                <div class="policy-details">{details}</div>
                <div class="policy-analysis">
                    <h4>AI Security Analysis:</h4>
                    <pre>{ai_response}</pre>
                </div>
            </div>"""

        return html
