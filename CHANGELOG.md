# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- GitHub issue templates (bug report, feature request, enhancement, documentation)
- GitHub Actions CI/CD workflow with test, lint, security, and build jobs
- Pull request template
- Comprehensive ISSUES.md documenting 36 future improvements
- CHANGELOG.md (this file)

### Changed
- Fixed unit tests to match actual implementation behavior

## [0.7.0] - Phase 7: Testing & Documentation - 2024

### Added
- Comprehensive testing suite with pytest
  - Unit tests for Policy, ObfuscationEngine, output formats
  - Integration tests for ScannerBase, AWS scanner, Neo4j integration
  - Test fixtures and mocks for cloud provider APIs
- pytest configuration with coverage reporting
- Code coverage tracking (current: 40%, target: 70%)
- CONTRIBUTING.md with detailed contribution guidelines
- Comprehensive README.md with usage examples, architecture overview, and roadmap
- Documentation for all major features and components

### Changed
- Improved code organization and structure
- Enhanced error messages and logging throughout codebase

### Fixed
- Various bug fixes discovered during testing
- Test coverage gaps identified for future improvement

## [0.6.0] - Phase 6: UX Features - 2024

### Added
- Progress bars with tqdm for better user feedback during scans
- Parallel processing support with ThreadPoolExecutor
  - Configurable max_workers (default: 10)
  - Automatic workload distribution
- Multiple output format support:
  - JSON (structured data)
  - HTML (interactive reports with Bootstrap styling)
  - SARIF (GitHub Security integration)
  - CSV (tabular data for spreadsheet analysis)
- Checkpoint system for scan resumption
  - Automatic checkpoint saving every 100 policies
  - Resume capability with `--resume` flag
- Base exporter class for consistent output formatting

### Changed
- Refactored output generation into modular exporter classes
- Improved performance with concurrent processing
- Enhanced user experience with real-time progress feedback

## [0.5.0] - Phase 5: Graph Visualization - 2024

### Added
- Neo4j graph database integration
  - Policy relationship visualization
  - Identity and permission graph modeling
  - Interactive graph exploration with Cypher queries
- Neo4j client with connection management
- Graph builder for policy network construction
- Example Cypher queries for common analysis patterns:
  - Finding overly permissive policies
  - Analyzing trust relationships
  - Identifying permission escalation paths

### Changed
- Extended output capabilities to include graph database population
- Added graph-based analysis to security review workflow

## [0.4.0] - Phase 4: Multi-Agent AI Analysis - 2024

### Added
- CrewAI multi-agent security analysis framework
- Specialized security agents:
  - **Security Auditor**: Deep security assessment
  - **Compliance Expert**: Regulatory compliance checks (HIPAA, PCI-DSS, SOC 2, GDPR)
  - **Risk Analyst**: Risk scoring and prioritization
  - **Threat Modeler**: Attack vector analysis
  - **Remediation Advisor**: Actionable fix recommendations
  - **Orchestrator**: Multi-agent synthesis and coordination
- AI-powered policy analysis with GPT-4
- Comprehensive security insights beyond basic vulnerability detection
- Multi-perspective security review combining multiple expert viewpoints

### Changed
- Enhanced AI integration from single-pass to multi-agent analysis
- Improved analysis depth and accuracy with specialized agents
- Added consensus-based decision making across agent perspectives

## [0.3.0] - Phase 3: Enhanced Obfuscation - 2024

### Added
- Advanced ObfuscationEngine with multi-pattern redaction
- Configurable redaction patterns via YAML
- Support for redacting:
  - AWS Account IDs in ARNs and Principal fields
  - IP addresses (IPv4 and IPv6)
  - Email addresses
  - Custom regex patterns
- Pattern-based redaction system with provider-specific rules
- Preservation of policy structure while masking sensitive data

### Changed
- Replaced basic redaction with comprehensive pattern matching
- Improved data privacy and security in scan outputs
- Made redaction patterns configurable and extensible

## [0.2.0] - Phase 2: Architecture Improvements - 2024

### Added
- ScannerBase abstract base class for cloud provider scanners
- Standardized scanner interface with common methods:
  - `list_iam_policies()`
  - `analyze_policies()`
  - `export_results()`
- Plugin architecture for easy addition of new cloud providers
- Improved code reusability and maintainability

### Changed
- Refactored AWS scanner to inherit from ScannerBase
- Modularized codebase for better organization
- Improved separation of concerns

### Removed
- Deprecated monolithic scanner approach

## [0.1.0] - Phase 1: Security & Modernization - 2024

### Added
- Modern OpenAI API integration (openai >= 1.0.0)
  - Migrated from deprecated `openai.ChatCompletion.create()`
  - Using new `client.chat.completions.create()` API
- Enhanced error handling and retry logic
- Input validation and sanitization
- Secure API key management

### Changed
- Updated all dependencies to latest secure versions
- Migrated from legacy OpenAI API to modern client-based API
- Improved security posture throughout codebase

### Fixed
- Critical security vulnerabilities in dependency chain
- API deprecation warnings
- Legacy code compatibility issues

### Security
- Added dependency security scanning
- Implemented secure credential handling
- Added input validation to prevent injection attacks

## [0.0.1] - Initial Release - 2023

### Added
- Initial fork from ethanolivertroy/cloudgpt
- Basic AWS IAM policy scanning
- OpenAI GPT integration for policy analysis
- Simple vulnerability detection
- JSON output format
- Basic CLI interface

### Notes
- Original project renamed from cloudgpt to llm-cloudpolicy-scanner
- Attribution maintained to original creator
- Project detached from fork for independent development

---

## Issue Categories for Future Development

See [ISSUES.md](ISSUES.md) for detailed future improvements:

### Roadmap Features (8 issues)
- Terraform/Pulumi IaC scanning
- Real-time continuous monitoring
- Auto-remediation suggestions
- Custom rules engine
- Slack/Teams integration
- ML-based anomaly detection
- GitHub Actions integration
- VS Code extension

### Bug Fixes (4 issues)
- Policy.is_vulnerable() return type inconsistency
- TypeError handling in vulnerability checks
- Vulnerable policy counting logic
- Mapping format consistency

### Test Improvements (6 issues)
- Integration test coverage expansion
- AWS scanner test suite
- Multi-agent workflow tests
- Neo4j graph builder tests
- Target 70% code coverage
- End-to-end integration tests

### Code Enhancements (10 issues)
- Error handling improvements
- Comprehensive logging system
- Parallel processing optimization
- Policy caching layer
- Obfuscation performance tuning
- Configuration validation
- HTML exporter refactoring
- Policy diff functionality
- Neo4j query optimization
- OpenAI API rate limiting

### Documentation (8 issues)
- Sphinx API documentation
- Video tutorial series
- Example policy library
- Enhanced CONTRIBUTING guide
- Troubleshooting guide
- Security best practices
- Deployment guide
- Detailed changelog maintenance

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for information on how to contribute to this project.

## Links

- [GitHub Repository](https://github.com/ethanolivertroy/llm-cloudpolicy-scanner)
- [Issue Tracker](https://github.com/ethanolivertroy/llm-cloudpolicy-scanner/issues)
- [Pull Requests](https://github.com/ethanolivertroy/llm-cloudpolicy-scanner/pulls)
- [Discussions](https://github.com/ethanolivertroy/llm-cloudpolicy-scanner/discussions)
