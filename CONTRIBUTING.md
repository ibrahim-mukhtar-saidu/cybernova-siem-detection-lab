# Contributing to CyberNova SIEM Detection Lab

Thank you for your interest in contributing to the CyberNova SIEM Detection Lab.

This project is primarily a cybersecurity training and portfolio laboratory focused on detection engineering, SOC workflows, defensive Python development, and security testing.

## Development Setup

Create and activate a virtual environment:

python3 -m venv venv
source venv/bin/activate

Install project dependencies:

python -m pip install -r requirements.txt

Development and security-analysis tools such as pytest, Ruff, Bandit, MyPy,
and pip-audit should be installed in the development environment.

## Before Submitting Changes

Run the test suite:

ruff check .
python -m pytest -q

Run Python compilation checks:

python -m compileall -q \
config_loader.py \
engine \
dashboards \
siem_lab.py \
siem_lab_v2.py

Run security checks:

bandit -r . -x ./tests,./venv,./.git

Run type checking:

mypy config_loader.py engine dashboards siem_lab.py siem_lab_v2.py

Audit dependencies:

pip-audit -r requirements.txt

## Code Guidelines

- Preserve existing correct behavior unless a change is required.
- Avoid unnecessary dependencies.
- Include tests for new detection or parsing behavior.
- Validate untrusted input at appropriate trust boundaries.
- Avoid sensitive information in logs and reports.
- Use clear Python naming and type hints.
- Keep detection logic deterministic and testable.
- Avoid claiming unsupported capabilities.
- Prefer simple, maintainable implementations over unnecessary abstraction.

## Detection Rules

New or modified detection rules should document:

- Rule name and identifier
- Detection condition
- Threshold
- Time window
- Severity
- MITRE ATT&CK mapping
- Expected event types

Keep detection scope focused and avoid adding unsupported enterprise integrations.

## Pull Requests

Pull requests should explain:

- What changed
- Why the change was necessary
- How the change was tested
- Security implications
- Any remaining limitations

Keep pull requests focused and avoid unrelated changes.

## Security Issues

Do not submit:

- Real credentials
- Production authentication logs
- Personally identifiable information
- Secrets
- Sensitive infrastructure information

For security issues, provide enough technical information to reproduce the
problem without exposing sensitive data.
