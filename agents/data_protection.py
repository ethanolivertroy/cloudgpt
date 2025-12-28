"""
Data Protection Agent
Specializes in data security and encryption policy analysis.
"""

from crewai import Agent


def create_data_protection_agent(llm) -> Agent:
    """
    Create a data protection analyst agent.

    Focuses on:
    - Encryption requirements and gaps
    - Data access control patterns
    - Data exfiltration risks
    - Backup and recovery policies
    - Data classification enforcement

    Args:
        llm: Language model instance for the agent

    Returns:
        Configured data protection agent
    """
    return Agent(
        role='Data Protection Analyst',
        goal='Identify data security vulnerabilities and encryption gaps in cloud policies',
        backstory="""You are a data protection specialist with deep expertise in encryption,
        data loss prevention, and compliance requirements like GDPR, HIPAA, and PCI-DSS. You've
        worked with sensitive data across healthcare, finance, and government sectors. You
        understand how data breaches occur through policy misconfigurations and have implemented
        comprehensive data protection strategies for organizations handling millions of customer
        records. Your expertise includes encryption at rest and in transit, key management, and
        data lifecycle policies.""",
        verbose=True,
        allow_delegation=False,
        llm=llm,
        max_iter=3,
    )


def get_data_protection_task_description(policy_document: str, cloud_provider: str) -> str:
    """
    Generate task description for data protection analysis.

    Args:
        policy_document: The redacted policy document to analyze
        cloud_provider: Cloud provider (AWS, Azure, GCP)

    Returns:
        Detailed task description
    """
    return f"""Analyze this {cloud_provider} policy for data protection vulnerabilities:

{policy_document}

Focus on:

1. **Encryption Requirements**:
   - Missing encryption at rest requirements
   - Lack of encryption in transit enforcement
   - Weak encryption algorithms or key sizes
   - Unencrypted storage permissions

2. **Data Access Controls**:
   - Overly broad data access permissions
   - Public read/write access to storage
   - Missing data access logging
   - Insufficient data access restrictions

3. **Data Exfiltration Risks**:
   - Permissions that allow bulk data export
   - Ability to disable logging or monitoring
   - Cross-region data transfer without controls
   - External data sharing without restrictions

4. **Key Management**:
   - Customer-managed key gaps
   - Key rotation policy issues
   - Overly permissive key access
   - Missing key usage auditing

5. **Data Lifecycle**:
   - Missing retention policies
   - Inadequate backup policies
   - Deletion/destruction policy gaps
   - Versioning and immutability issues

Provide:
- **Vulnerability Summary**: Yes/No with brief explanation
- **Risk Level**: Critical, High, Medium, Low, or None
- **Specific Issues**: List each data protection issue found
- **Data at Risk**: What data could be compromised
- **Remediation**: Specific data protection improvements"""
