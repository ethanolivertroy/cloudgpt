"""
IAM Analyst Agent
Specializes in identity and access management security analysis.
"""

from crewai import Agent


def create_iam_analyst(llm) -> Agent:
    """
    Create an IAM security analyst agent.

    Focuses on:
    - Overly permissive roles and policies
    - Privilege escalation paths
    - Least privilege violations
    - MFA enforcement gaps
    - Service account security
    - Cross-account access risks

    Args:
        llm: Language model instance for the agent

    Returns:
        Configured IAM analyst agent
    """
    return Agent(
        role='IAM Security Analyst',
        goal='Identify identity and access management vulnerabilities in cloud policies',
        backstory="""You are a seasoned IAM security expert with over 10 years of experience
        analyzing cloud identity and access policies across AWS, Azure, and GCP. You have deep
        knowledge of privilege escalation techniques, IAM best practices, and the principle of
        least privilege. You've discovered critical IAM vulnerabilities in Fortune 500 companies
        and understand how attackers exploit overly permissive permissions.""",
        verbose=True,
        allow_delegation=False,
        llm=llm,
        max_iter=3,
    )


def get_iam_analysis_task_description(policy_document: str, cloud_provider: str) -> str:
    """
    Generate task description for IAM analysis.

    Args:
        policy_document: The redacted policy document to analyze
        cloud_provider: Cloud provider (AWS, Azure, GCP)

    Returns:
        Detailed task description
    """
    return f"""Analyze this {cloud_provider} policy for IAM security vulnerabilities:

{policy_document}

Focus on:

1. **Overly Permissive Permissions**:
   - Wildcard (*) actions or resources
   - Administrative privileges granted unnecessarily
   - Broad resource access patterns

2. **Privilege Escalation Risks**:
   - Permissions that allow users to elevate their own privileges
   - Role assumption chains that bypass intended restrictions
   - Permission combinations that create escalation paths

3. **Least Privilege Violations**:
   - Permissions granted beyond what's needed for the intended function
   - Service accounts with excessive permissions
   - Unused or unnecessary permissions

4. **Access Control Gaps**:
   - Missing MFA requirements for sensitive operations
   - Lack of conditions on sensitive permissions
   - Missing IP or time-based restrictions

5. **Cross-Account/Cross-Tenant Risks**:
   - External principal access without proper constraints
   - Trust relationships that are too permissive
   - Resource sharing risks

Provide:
- **Vulnerability Summary**: Yes/No with brief explanation
- **Risk Level**: Critical, High, Medium, Low, or None
- **Specific Issues**: List each IAM vulnerability found
- **Exploitation Scenario**: How an attacker could exploit this
- **Remediation**: Specific fixes to implement"""
