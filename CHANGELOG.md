# Changelog

All notable changes to the CyberNova SIEM Detection Lab are documented here.

## Version 2.1

### Added

- SOC dashboard generation
- Incident reporting
- MITRE ATT&CK mapping
- Configurable YAML detection rules
- Detection time windows
- Hardened authentication-log parsing
- UTC-aware timestamps
- UUID-based alert identifiers
- Persistent incident numbering
- Centralized application logging
- HTML output escaping
- Risk assessment and reporting improvements
- Comprehensive pytest test coverage
- Static analysis and security validation

### Improved

- Configuration validation
- Malformed log handling
- Detection reliability
- Alert uniqueness
- Incident persistence
- Report generation
- Dashboard security
- Error handling
- Type safety
- Project documentation

### Security

- Added input validation at the authentication-log parsing boundary
- Added IPv4 and IPv6 address validation
- Added safe YAML loading with `yaml.safe_load`
- Added dependency vulnerability auditing
- Added Bandit security scanning
- Added MyPy type checking

## Version 2.0

### Added

- Modular SIEM detection pipeline
- Authentication log analysis
- Brute-force detection
- Successful-login-after-failures detection
- Alert generation
- Incident creation
- Risk scoring
- Security reporting
- SOC dashboard support
- MITRE ATT&CK detection context
