# Contributing to llm-cloudpolicy-scanner

Thank you for your interest in contributing! This document provides guidelines and instructions for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Testing](#testing)
- [Code Style](#code-style)
- [Submitting Changes](#submitting-changes)
- [Adding New Features](#adding-new-features)
- [Bug Reports](#bug-reports)

## Code of Conduct

This project adheres to a code of conduct. By participating, you are expected to uphold this code:

- Be respectful and inclusive
- Welcome newcomers and help them get started
- Focus on what is best for the community
- Show empathy towards other community members

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR-USERNAME/llm-cloudpolicy-scanner.git
   cd llm-cloudpolicy-scanner
   ```

3. **Add upstream remote**:
   ```bash
   git remote add upstream https://github.com/ethanolivertroy/cloudgpt.git
   ```

4. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

## Development Setup

### Prerequisites

- Python 3.8 or higher
- pip
- virtualenv (recommended)
- Docker and Docker Compose (for Neo4j)

### Installation

1. **Create virtual environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up environment variables**:
   ```bash
   cp .env.example .env
   # Edit .env with your API keys
   ```

4. **Start Neo4j** (optional):
   ```bash
   docker-compose up -d
   ```

### Project Structure

```
llm-cloudpolicy-scanner/
├── agents/                 # Multi-agent AI modules
├── core/                   # Core functionality
│   ├── output_formats/    # Export format modules
│   ├── obfuscation.py     # Obfuscation engine
│   ├── policy.py          # Policy class
│   └── scanner_base.py    # Base scanner class
├── queries/                # Cypher query templates
├── tests/                  # Test suite
├── visualization/          # Web UI for graphs
├── aws-scan.py            # AWS scanner
├── azure-scan.py          # Azure scanner
├── gcp-scan.py            # GCP scanner
└── config.yaml            # Configuration
```

## Testing

We use pytest for testing with coverage reporting.

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=core --cov=agents --cov-report=html

# Run specific test file
pytest tests/test_policy.py

# Run specific test
pytest tests/test_policy.py::TestPolicy::test_policy_initialization

# Run with markers
pytest -m unit           # Unit tests only
pytest -m integration    # Integration tests only
pytest -m "not slow"     # Skip slow tests
```

### Writing Tests

- Place tests in the `tests/` directory
- Name test files with `test_` prefix
- Use descriptive test names: `test_feature_does_something`
- Write both unit and integration tests
- Aim for 70%+ code coverage
- Mock external APIs (AWS, Azure, GCP, OpenAI)

Example test:
```python
import pytest
from core.policy import Policy

def test_policy_vulnerability_detection():
    \"\"\"Test that vulnerable policies are detected correctly\"\"\"
    policy = Policy()
    policy.ai_response = "Yes, this policy has vulnerabilities"

    assert policy.is_vulnerable() is True
```

### Coverage Requirements

- Minimum 70% overall coverage
- Core modules should have 80%+ coverage
- New features must include tests
- Bug fixes must include regression tests

## Code Style

### Python Style Guide

We follow PEP 8 with some modifications:

- **Line length**: 100 characters (not 79)
- **Imports**: Group into stdlib, third-party, local
- **Docstrings**: Google style
- **Type hints**: Use where helpful

### Formatting

We don't enforce a specific formatter, but consistency is important:

```python
# Good
def process_policy(policy: Policy, provider: str) -> Policy:
    \"\"\"
    Process a cloud policy for security analysis.

    Args:
        policy: Policy object to process
        provider: Cloud provider name

    Returns:
        Processed policy with AI analysis
    \"\"\"
    # Implementation
    pass

# Bad - no docstring, unclear parameter names
def process(p, prov):
    pass
```

### Documentation

- Add docstrings to all public functions/classes
- Use clear, descriptive variable names
- Comment complex logic
- Update README for user-facing changes

## Submitting Changes

### Commit Messages

Write clear, descriptive commit messages:

```
Add support for GCP organization policies

- Implement GCP organization policy scanning
- Add tests for org policy parsing
- Update documentation with GCP examples

Fixes #123
```

Format:
- **First line**: Brief summary (50-72 chars)
- **Blank line**
- **Body**: Detailed explanation (wrap at 72 chars)
- **Footer**: Issue references, breaking changes

### Pull Request Process

1. **Update your branch**:
   ```bash
   git fetch upstream
   git rebase upstream/master
   ```

2. **Run tests**:
   ```bash
   pytest
   ```

3. **Push to your fork**:
   ```bash
   git push origin feature/your-feature-name
   ```

4. **Create Pull Request**:
   - Go to GitHub and create a PR
   - Fill out the PR template
   - Link related issues
   - Request review

5. **Address feedback**:
   - Make requested changes
   - Push updates to the same branch
   - Re-request review

### PR Requirements

- [ ] Tests pass (`pytest`)
- [ ] Code coverage maintained (≥70%)
- [ ] Documentation updated
- [ ] CHANGELOG.md updated (if applicable)
- [ ] No merge conflicts
- [ ] Descriptive PR title and description

## Adding New Features

### Cloud Provider Support

To add a new cloud provider:

1. Create `{provider}-scan.py` in root
2. Extend `ScannerBase` class
3. Implement required methods:
   - `scan()`: Retrieve policies
   - `redact_policy()`: Redact sensitive data
4. Add patterns to `core/redaction_patterns.py`
5. Update `core/graph_builder.py` for graph support
6. Add tests
7. Update documentation

### Output Formats

To add a new output format:

1. Create `core/output_formats/{format}_exporter.py`
2. Extend `BaseExporter` class
3. Implement `export()` method
4. Add tests
5. Update `config.yaml`
6. Update documentation

### Multi-Agent Analyzers

To add a new agent:

1. Create `agents/{agent_name}.py`
2. Define agent role, goal, and backstory
3. Create task description function
4. Update `agents/orchestrator.py`
5. Add to `config.yaml`
6. Write tests

## Bug Reports

### Reporting Bugs

Create an issue with:

- **Title**: Clear, specific description
- **Environment**: Python version, OS, cloud provider
- **Steps to reproduce**: Minimal example
- **Expected behavior**: What should happen
- **Actual behavior**: What actually happens
- **Logs**: Relevant error messages
- **Screenshots**: If applicable

Example:
```
Title: AWS scanner fails on policies with conditions

Environment:
- Python 3.9.7
- macOS 12.6
- AWS profile with 50+ policies

Steps to reproduce:
1. Run: python aws-scan.py --profile production
2. Scanner crashes when processing policy "ConditionalAccess"

Expected: All policies scanned successfully
Actual: KeyError: 'Condition'

Logs:
[ERROR] Error processing policy ConditionalAccess: 'Condition'
Traceback...
```

### Security Issues

**Do not** open public issues for security vulnerabilities.

Instead:
1. Email: security@your-domain.com
2. Include: Detailed description, impact, reproduction steps
3. Allow time for patch before public disclosure

## Development Workflow

### Typical Workflow

1. **Pick an issue** or create one for discussion
2. **Create feature branch**: `git checkout -b feature/issue-123`
3. **Develop** with tests
4. **Test locally**: `pytest`
5. **Commit** with clear messages
6. **Push** to your fork
7. **Create PR** and request review
8. **Address feedback** if needed
9. **Merge** when approved

### Branch Naming

- `feature/description` - New features
- `fix/description` - Bug fixes
- `docs/description` - Documentation
- `test/description` - Test improvements
- `refactor/description` - Code refactoring

## Questions?

- **Documentation**: Check README.md and docs/
- **Issues**: Search existing issues first
- **Discussions**: Use GitHub Discussions for questions
- **Chat**: Join our community (if applicable)

## License

By contributing, you agree that your contributions will be licensed under the same license as the project.

---

Thank you for contributing to llm-cloudpolicy-scanner! 🎉
