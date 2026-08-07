# Incident Report: Brute Force Detection

## Alert Name

Multiple Failed Authentication Attempts

## Severity

High

## MITRE ATT&CK

T1110 - Brute Force

## Investigation

The SIEM detected multiple failed login attempts from the same IP address.

The detection engine analyzed authentication logs and identified suspicious login behavior consistent with a brute force attack.

## Evidence

- Multiple failed authentication attempts
- Same source IP address
- Repeated login failures within a short time period

## Response

- Block suspicious IP
- Reset affected credentials
- Monitor additional activity
- Review authentication logs for further compromise indicators

## Analyst Notes

This incident demonstrates the SOC workflow:

Detection → Investigation → Risk Assessment → Response
