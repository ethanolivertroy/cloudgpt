"""
Network Security Agent
Specializes in network security policy analysis.
"""

from crewai import Agent


def create_network_security_agent(llm) -> Agent:
    """
    Create a network security analyst agent.

    Focuses on:
    - Overly permissive security groups/firewall rules
    - Public exposure risks
    - Network segmentation issues
    - VPC/VNet configuration weaknesses
    - Ingress/egress rule problems

    Args:
        llm: Language model instance for the agent

    Returns:
        Configured network security agent
    """
    return Agent(
        role='Network Security Analyst',
        goal='Identify network security vulnerabilities and misconfigurations in cloud policies',
        backstory="""You are a network security expert with extensive experience in cloud
        networking architectures. You've worked with AWS VPCs, Azure VNets, and GCP VPCs for
        Fortune 500 companies. You understand how attackers exploit network misconfigurations
        and have prevented numerous data breaches by identifying overly permissive firewall
        rules and security group misconfigurations. You're well-versed in zero-trust networking
        and defense-in-depth strategies.""",
        verbose=True,
        allow_delegation=False,
        llm=llm,
        max_iter=3,
    )


def get_network_analysis_task_description(policy_document: str, cloud_provider: str) -> str:
    """
    Generate task description for network security analysis.

    Args:
        policy_document: The redacted policy document to analyze
        cloud_provider: Cloud provider (AWS, Azure, GCP)

    Returns:
        Detailed task description
    """
    return f"""Analyze this {cloud_provider} policy for network security vulnerabilities:

{policy_document}

Focus on:

1. **Public Exposure**:
   - Resources exposed to the internet (0.0.0.0/0, ::/0)
   - Public IP assignments without justification
   - Unrestricted inbound access on sensitive ports

2. **Overly Permissive Rules**:
   - Security groups/firewall rules allowing too much traffic
   - Wide CIDR ranges when narrow ranges would suffice
   - "Allow all" rules that should be restricted

3. **Network Segmentation**:
   - Lack of proper network isolation
   - Missing VPC/VNet peering restrictions
   - Insufficient subnet segmentation

4. **Protocol and Port Issues**:
   - Dangerous ports open to the internet (SSH, RDP, databases)
   - Unnecessary protocol allowances
   - Missing protocol-specific security controls

5. **VPC/VNet Configuration**:
   - Flow log gaps
   - Missing network ACLs
   - Inadequate network monitoring

Provide:
- **Vulnerability Summary**: Yes/No with brief explanation
- **Risk Level**: Critical, High, Medium, Low, or None
- **Specific Issues**: List each network security issue found
- **Attack Vectors**: How attackers could leverage these issues
- **Remediation**: Specific network security improvements"""
