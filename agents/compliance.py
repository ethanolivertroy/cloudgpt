"""
Compliance Agent
Specializes in regulatory compliance analysis.
"""

from crewai import Agent


def create_compliance_agent(llm) -> Agent:
    """
    Create a compliance analyst agent.

    Focuses on:
    - SOC 2 compliance requirements
    - HIPAA compliance for healthcare
    - PCI-DSS for payment data
    - GDPR for EU data
    - Industry best practices

    Args:
        llm: Language model instance for the agent

    Returns:
        Configured compliance agent
    """
    return Agent(
        role='Compliance and Governance Analyst',
        goal='Identify compliance violations and governance gaps in cloud policies',
        backstory="""You are a compliance expert with certifications in SOC 2, HIPAA, PCI-DSS,
        and GDPR. You've led compliance audits for major enterprises and understand the regulatory
        requirements across different industries. You have deep knowledge of cloud security
        frameworks like CIS Benchmarks, NIST, and ISO 27001. You've helped organizations achieve
        and maintain compliance certifications by identifying and remediating policy gaps. You
        understand how policy misconfigurations can lead to audit failures and regulatory fines.""",
        verbose=True,
        allow_delegation=False,
        llm=llm,
        max_iter=3,
    )


def get_compliance_task_description(policy_document: str, cloud_provider: str) -> str:
    """
    Generate task description for compliance analysis.

    Args:
        policy_document: The redacted policy document to analyze
        cloud_provider: Cloud provider (AWS, Azure, GCP)

    Returns:
        Detailed task description
    """
    return f"""Analyze this {cloud_provider} policy for compliance violations and governance gaps:

{policy_document}

Evaluate against multiple compliance frameworks:

1. **SOC 2 Requirements**:
   - Security principle violations
   - Availability control gaps
   - Processing integrity issues
   - Confidentiality concerns
   - Privacy control weaknesses

2. **HIPAA Compliance** (if applicable):
   - Protected Health Information (PHI) access controls
   - Encryption requirements for healthcare data
   - Audit logging for PHI access
   - Breach notification readiness

3. **PCI-DSS** (if applicable):
   - Cardholder data environment controls
   - Access restriction to payment data
   - Encryption of cardholder data
   - Security monitoring requirements

4. **GDPR** (if applicable):
   - Personal data protection measures
   - Right to erasure capabilities
   - Data portability provisions
   - Cross-border transfer controls

5. **Industry Best Practices**:
   - CIS Benchmark alignment
   - NIST framework compliance
   - ISO 27001 controls
   - Cloud provider security best practices

6. **Governance Issues**:
   - Missing change management controls
   - Inadequate separation of duties
   - Audit trail gaps
   - Policy review and approval processes

Provide:
- **Compliance Summary**: Compliant/Non-Compliant with frameworks affected
- **Risk Level**: Critical, High, Medium, Low, or None
- **Specific Violations**: List each compliance issue found
- **Regulatory Impact**: Potential audit findings or fines
- **Remediation**: Specific compliance improvements needed"""
