"""
Orchestrator Agent
Coordinates specialized agents and synthesizes comprehensive security reports.
"""

from crewai import Agent, Task, Crew
from typing import Dict, Any
from agents.iam_analyst import create_iam_analyst, get_iam_analysis_task_description
from agents.network_security import create_network_security_agent, get_network_analysis_task_description
from agents.data_protection import create_data_protection_agent, get_data_protection_task_description
from agents.compliance import create_compliance_agent, get_compliance_task_description


def create_orchestrator(llm) -> Agent:
    """
    Create an orchestrator agent to synthesize findings.

    Args:
        llm: Language model instance for the agent

    Returns:
        Configured orchestrator agent
    """
    return Agent(
        role='Security Orchestrator and Report Synthesizer',
        goal='Synthesize findings from specialized security agents into a comprehensive assessment',
        backstory="""You are a Chief Information Security Officer (CISO) with 15+ years of
        experience leading security teams. You excel at taking input from specialized security
        analysts and creating comprehensive, actionable security reports for executive leadership.
        You understand how to prioritize vulnerabilities by business impact, synthesize technical
        findings into clear recommendations, and present security risks in business terms. You've
        led incident response teams and understand the real-world impact of policy vulnerabilities.""",
        verbose=True,
        allow_delegation=False,
        llm=llm,
        max_iter=3,
    )


def get_orchestrator_task_description(
    iam_findings: str,
    network_findings: str,
    data_findings: str,
    compliance_findings: str
) -> str:
    """
    Generate task description for orchestrator synthesis.

    Args:
        iam_findings: IAM analyst findings
        network_findings: Network security findings
        data_findings: Data protection findings
        compliance_findings: Compliance findings

    Returns:
        Detailed synthesis task description
    """
    return f"""Synthesize these security analysis findings into a comprehensive assessment:

**IAM Analysis:**
{iam_findings}

**Network Security Analysis:**
{network_findings}

**Data Protection Analysis:**
{data_findings}

**Compliance Analysis:**
{compliance_findings}

Create a comprehensive security report with:

1. **Executive Summary**:
   - Overall vulnerability status (Yes/No)
   - Highest risk level found across all analyses
   - Top 3 critical findings
   - Business impact summary

2. **Prioritized Vulnerability List**:
   - Rank all findings by severity and exploitability
   - Cross-reference related vulnerabilities
   - Identify vulnerability chains (multiple issues that compound)

3. **Risk Assessment**:
   - Overall risk rating (Critical/High/Medium/Low/None)
   - Likelihood of exploitation
   - Potential business impact
   - Compliance exposure

4. **Recommended Actions**:
   - Immediate actions (must fix now)
   - Short-term actions (fix within 30 days)
   - Long-term improvements
   - Quick wins (easy fixes with high impact)

5. **Attack Scenarios**:
   - Most likely attack path given these vulnerabilities
   - Worst-case breach scenario
   - Defense recommendations

Format the response to start with "Yes," or "No," to indicate if vulnerabilities were found,
followed by the comprehensive analysis."""


def analyze_policy_with_crew(
    policy_document: str,
    cloud_provider: str,
    llm: Any,
    verbose: bool = True
) -> str:
    """
    Analyze a policy using the multi-agent crew.

    Args:
        policy_document: The redacted policy document to analyze
        cloud_provider: Cloud provider (AWS, Azure, GCP)
        llm: Language model instance
        verbose: Whether to show detailed agent output

    Returns:
        Comprehensive security analysis from orchestrator
    """
    # Create specialized agents
    iam_agent = create_iam_analyst(llm)
    network_agent = create_network_security_agent(llm)
    data_agent = create_data_protection_agent(llm)
    compliance_agent = create_compliance_agent(llm)
    orchestrator = create_orchestrator(llm)

    # Create tasks for each agent
    iam_task = Task(
        description=get_iam_analysis_task_description(policy_document, cloud_provider),
        agent=iam_agent,
        expected_output="Detailed IAM security analysis with vulnerabilities, risks, and remediation steps"
    )

    network_task = Task(
        description=get_network_analysis_task_description(policy_document, cloud_provider),
        agent=network_agent,
        expected_output="Detailed network security analysis with vulnerabilities, attack vectors, and remediation"
    )

    data_task = Task(
        description=get_data_protection_task_description(policy_document, cloud_provider),
        agent=data_agent,
        expected_output="Detailed data protection analysis with encryption gaps, data risks, and remediation"
    )

    compliance_task = Task(
        description=get_compliance_task_description(policy_document, cloud_provider),
        agent=compliance_agent,
        expected_output="Detailed compliance analysis with violations, regulatory impact, and remediation"
    )

    # Orchestrator task depends on all other tasks
    orchestrator_task = Task(
        description="""Synthesize all agent findings into a comprehensive security report.
        Review the IAM, network, data protection, and compliance analyses.
        Create a prioritized vulnerability assessment with executive summary and actionable recommendations.
        Start with Yes/No to indicate if vulnerabilities exist, then provide full analysis.""",
        agent=orchestrator,
        expected_output="Comprehensive security assessment starting with Yes/No, followed by executive summary, prioritized findings, risk assessment, and recommendations",
        context=[iam_task, network_task, data_task, compliance_task]
    )

    # Create and run the crew
    crew = Crew(
        agents=[iam_agent, network_agent, data_agent, compliance_agent, orchestrator],
        tasks=[iam_task, network_task, data_task, compliance_task, orchestrator_task],
        verbose=verbose
    )

    result = crew.kickoff()

    return str(result)
