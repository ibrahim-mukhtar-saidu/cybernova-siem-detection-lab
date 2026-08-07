# Detection Rules Documentation

This document explains the detection logic implemented in the CyberNova SIEM Detection Lab.

---

# Rule 1: Brute Force Detection

## MITRE ATT&CK

T1110 - Brute Force

## Description

Detects repeated failed authentication attempts from the same source IP address.

This rule identifies possible password guessing attacks against user accounts.

## Detection Logic

The SIEM triggers an alert when:

- Multiple failed login attempts are detected
- Attempts originate from the same IP address
- Authentication failures happen within a short period

## Severity

High

## Investigation Steps

The SOC analyst should review:

- Source IP address
- Target username
- Number of failed attempts
- Authentication timeline
- Related suspicious activity

## Response Actions

- Block suspicious IP address
- Investigate affected accounts
- Reset credentials if compromise is suspected
- Continue monitoring activity

---

# Rule 2: Successful Login After Failures

## MITRE ATT&CK

T1078 - Valid Accounts

## Description

Detects possible account compromise when a successful login occurs after multiple failed authentication attempts.

## Detection Logic

The SIEM triggers an alert when:

- Multiple failed login attempts occur
- A successful login follows
- Activity matches suspicious authentication behavior

## Severity

Critical

## Investigation Steps

The SOC analyst should review:

- User account activity
- Login source
- Geographic location
- Authentication history
- Time of activity

## Response Actions

- Verify user identity
- Reset credentials if required
- Monitor account activity
- Escalate confirmed incidents

---

# Detection Engineering Summary

The CyberNova SIEM Detection Lab demonstrates:

- Security monitoring
- Detection rule development
- MITRE ATT&CK mapping
- Alert triage
- Incident investigation
- Blue Team SOC workflow
- Python security automation
