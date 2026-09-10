# CASE-002 — Password Spraying Cross-Project Case Study

## 1. Case Study Purpose

This case study demonstrates how a password-spraying investigation in the SOC Operations Lab connects with authentication detection engineering in the SIEM Detection Lab.

The case focuses on:

- Password-spraying behavior against multiple user accounts.
- Successful authentication observed during the attack sequence.
- Investigation pivoting from the detection to the successful authentication event.
- SIEM coverage for successful authentication following repeated failures.
- Related distributed/source-rotation password-spray detection coverage.
- Evidence preservation, investigation boundaries, and detection-engineering feedback.

This is an authorized synthetic SOC laboratory case study. It does not represent production SOC activity or a confirmed real-world compromise.

---

## 2. Evidence Chain

The primary SOC investigation follows this evidence chain:

```text

CASE-002 Password-Spraying Activity
              │
              ├── DET-AUTH-002
              │      ↓
              │   CASE-002
              │      ↓
              │   PB-002
              │
              └── Successful Authentication Pivot
                         ↓
                      RULE-002
                         ↓
              Successful-after-failures
                 detection coverage
```

The related distributed password-spray coverage is separate:
```text

RULE-003
   ↓
Distributed / source-rotation
password-spray coverage
   ↓
Related authentication investigation pattern
   ↓
CASE-002 / PB-002
```

RULE-003 is related coverage rather than the detector that directly generated CASE-002.

## 3. SOC Password-Spraying Detection

The SOC Operations Lab uses:

Detection ID: DET-AUTH-002
Detection name: Password Spraying Authentication Detection
Detection version: 1.0
Case ID: CASE-002
Playbook: PB-002-password-spraying.md
Alert ID: ALERT-CASE-002-DET-AUTH-002
Severity: High
Confidence: High
Protocol: SSH
Authentication method: Password

The SOC-side detection identifies repeated authentication failures from a single source against multiple accounts within a short time window.

The documented threshold is:

At least 6 failed authentication attempts.
At least 6 distinct targeted users.
Within a 5-minute detection window.

CASE-002 exceeded these conditions with:

13 failed authentication attempts.
7 distinct targeted accounts.
Approximately 4 minutes and 25 seconds of observed activity.

The targeted accounts were:

alice
bob
carol
david
erin
frank
grace

The source IP was:

198.51.100.40

The affected laboratory host was:

lab-auth-01

## 4. SIEM Successful-After-Failures Coverage

The SIEM Detection Lab contains:

RULE-002 — Successful Login After Multiple Failures

The rule is configured with:

Threshold: 3 failed logins
Window: 10 minutes
Failed event: FAILED_LOGIN
Successful event: SUCCESSFUL_LOGIN
Severity: Critical
MITRE ATT&CK: T1078 — Valid Accounts

RULE-002 tracks failed authentication attempts by source IP and evaluates whether a successful authentication occurs after the configured failure threshold.

CASE-002 contains seven failed authentication attempts from 198.51.100.40 before the successful authentication event:

EVT-002008

Therefore, the successful authentication observed during CASE-002 is directly relevant to the successful-after-failures detection logic.

This does not mean RULE-002 generated the SOC CASE-002 alert. The SOC password-spraying detection and SIEM successful-after-failures detection provide separate layers of security coverage.

## 5. Observed Authentication Activity

The primary source was:

198.51.100.40

The activity began at:

2026-09-08T10:00:03Z

The final observed failure occurred at:

2026-09-08T10:04:28Z

The authentication sequence began with failed password attempts against multiple accounts.

The observed sequence included:

Failed authentication against alice.
Failed authentication against bob.
Failed authentication against carol.
Failed authentication against david.
Failed authentication against erin.
Failed authentication against frank.
Failed authentication against grace.
Successful password authentication against alice.
Additional failures against several previously targeted accounts.
Activity ended after the final observed failure.

The successful authentication occurred at:

2026-09-08T10:01:51Z

Event:

EVT-002008

User:

alice

Source:

198.51.100.40

The complete authentication telemetry is preserved in:

telemetry/authentication/CASE-002-authentication-events.jsonl

## 6. Investigation Pivot — EVT-002008

The most important investigation pivot is:

EVT-002008

This event records a successful password authentication for alice from the same source IP associated with the preceding password-spraying activity.

The event increases investigation priority because successful authentication occurred during the suspicious authentication sequence.

The actual event sequence shows seven preceding failed authentication attempts from the same source before this successful authentication.

The event metadata contains a preceded_by_failures value of 1. This metadata value is not treated as the complete failure count because the surrounding telemetry provides the authoritative event sequence.

The investigation therefore uses the observed events rather than relying on the single metadata field.

Successful authentication does not independently establish:

Account compromise.
Unauthorized access.
Credential theft.
Privilege escalation.
Persistence.
Malware execution.
Lateral movement.
Data access.
Exfiltration.

Additional session, endpoint, and authorization telemetry would be required to establish those conditions.

## 7. Investigation Findings
Finding 1 — Password Spraying Confirmed in Lab Telemetry

The observed activity satisfies the SOC password-spraying detection threshold.

There were:

13 failed authentication attempts.
7 distinct targeted accounts.
One common source IP.
Activity occurring within approximately 4 minutes and 25 seconds.

The behavior is consistent with password spraying and maps to:

T1110.003 — Password Spraying

Finding 2 — Successful Authentication Observed

A successful password authentication occurred for:

alice

Event:

EVT-002008

Source:

198.51.100.40

This event is a priority investigation pivot because it occurred during the password-spraying sequence.

Finding 3 — Account Compromise Not Established

The available telemetry does not establish that the alice account was compromised.

The successful authentication proves that an authentication event occurred.

It does not independently prove that the credentials were unauthorized or that the account was subsequently abused.

Finding 4 — Broader Attack Activity Not Established

The available dataset does not establish:

Command execution.
Privilege escalation.
Persistence.
Malware execution.
Lateral movement.
File modification.
Data access.
Exfiltration.

Additional telemetry would be required for those conclusions.

## 8. Related Distributed Password-Spray Coverage

The SIEM Detection Lab also contains:

RULE-003 — Distributed Password Spray Detection

RULE-003 addresses a different authentication pattern.

It detects repeated failures against the same user from multiple source IP addresses.

Its purpose is to provide coverage when an attacker rotates source addresses rather than concentrating activity through one source.

CASE-002 instead demonstrates:

One source IP
      ↓
Multiple targeted accounts
      ↓
Password spraying

RULE-003 provides related coverage for:

Multiple source IPs
      ↓
Same targeted account
      ↓
Distributed / source-rotation activity

Therefore, RULE-003 should not be described as the direct SIEM detector for CASE-002.

Its relationship to CASE-002 is documented as related detection coverage.

## 9. Response Assessment

The SOC playbook for this investigation is:

PB-002-password-spraying.md

The response objectives are to:

Validate the alert.
Preserve authentication evidence.
Confirm the affected accounts and source.
Investigate the successful authentication.
Determine whether subsequent activity occurred.
Assess other affected accounts or hosts.
Perform appropriate threat-intelligence checks.
Preserve evidence and document findings.
Feed detection gaps back into detection engineering.

No production system was contained as part of this laboratory case.

Potential operational containment actions are documented as recommendations rather than actions performed.

The investigation should prioritize validation of:

Whether the alice login was authorized.
Whether the credentials were legitimate.
Whether an SSH session followed the successful authentication.
Commands executed after authentication.
Privilege changes.
Network connections.
File activity.
Account-management changes.
Persistence mechanisms.
Additional affected hosts.

The supplied dataset does not contain sufficient post-authentication telemetry to establish these conditions.

## 10. Detection Engineering Feedback

CASE-002 demonstrates the value of correlating authentication behavior rather than evaluating isolated events.

The case provides several detection-engineering opportunities.

Improvement 1 — Successful Authentication Correlation

A successful authentication following multiple failures from the same source should increase investigation priority.

RULE-002 provides this additional SIEM coverage.

Improvement 2 — Multiple Targeted Accounts

Authentication failures should be evaluated across accounts, not only as repeated failures against one user.

The SOC-side DET-AUTH-002 detection provides this password-spraying coverage.

Improvement 3 — Source Rotation

Detection coverage should also account for attackers distributing authentication attempts across multiple source addresses.

RULE-003 provides related distributed/source-rotation coverage.

Improvement 4 — Post-Authentication Correlation

Future detection coverage should correlate suspicious authentication activity with:

SSH sessions.
Process execution.
Privilege escalation.
Network connections.
File changes.
Account changes.
Persistence indicators.
Additional authentication activity.

This would help determine whether successful authentication was followed by suspicious behavior.

## 11. Testing Evidence

The SIEM Detection Lab completed its quality and adversarial testing phases with:

135 tests passed

The testing program includes validation of:

Detection thresholds.
Time-window boundaries.
Events outside the detection window.
Cross-user contamination.
Duplicate events.
Logical duplication.
Cross-rule overlap.
Counter reset behavior.
Event ordering.
Mixed event types.
Successful authentication following failures.
Malformed configuration.
Extreme valid configuration values.
Configuration validation.

The configuration quality gates also validate important rule properties such as positive integer thresholds and valid detection windows.

This provides regression evidence that the detection-engineering changes remain testable and reproducible.

## 12. Evidence and Confidence Model
Observed Evidence

The following are directly supported by the laboratory telemetry:

13 failed password authentication attempts.
7 distinct targeted accounts.
Common source IP 198.51.100.40.
Successful password authentication for alice.
Event EVT-002008.
Authentication activity occurring within approximately 4 minutes and 25 seconds.
Interpretation

The observed pattern is consistent with password-spraying behavior.

Investigation Hypothesis

The successful authentication may represent successful credential use during the password-spraying sequence and requires additional investigation.

Confirmed

The following are confirmed in the supplied laboratory evidence:

Password authentication failures occurred.
Multiple accounts were targeted.
The SOC password-spraying threshold was satisfied.
A successful authentication occurred during the sequence.
Not Confirmed

The evidence does not confirm:

Account compromise.
Unauthorized access.
Credential theft.
Privilege escalation.
Persistence.
Malware execution.
Lateral movement.
Data theft.
Exfiltration.
Real-world attribution.
## 13. Lessons Learned

CASE-002 demonstrates that password-spraying investigations require correlation across authentication events and security layers.

The initial detection identifies the broader attack pattern.

The successful authentication provides a higher-priority investigation pivot.

The investigation must then determine whether the successful authentication resulted in additional suspicious activity.

This case also demonstrates why detection rules should complement rather than duplicate each other.

The SOC password-spraying detection focuses on:

One source → multiple accounts

The SIEM successful-after-failures detection focuses on:

Repeated failures → successful authentication

The distributed password-spray detection focuses on:

Multiple sources → same account

Together these patterns provide broader authentication monitoring coverage.

## 14. Cross-Project Value

The case demonstrates a clear separation of responsibilities between the two projects.

SIEM Detection Lab

Responsible for:

Authentication event processing.
Detection rules.
Detection logic.
Configuration validation.
Alert generation.
Detection testing.
Regression testing.
Metrics.
Dashboard visibility.
Adversarial detection validation.
SOC Operations Lab

Responsible for:

Alert triage.
Case management.
Investigation.
Evidence preservation.
Timelines.
Indicators.
Threat intelligence.
Threat hunting.
Response assessment.
Playbook execution.
Final reporting.
Lessons learned.

The projects therefore operate as complementary layers rather than duplicate implementations.

## 15. Evidence References
SOC Operations Lab

Primary case:

CASE-002

Detection:

DET-AUTH-002

Playbook:

PB-002-password-spraying.md

Primary alert:

ALERT-CASE-002-DET-AUTH-002

Primary authentication evidence:

telemetry/authentication/CASE-002-authentication-events.jsonl

Primary successful-authentication pivot:

EVT-002008

SIEM Detection Lab

Successful-after-failures rule:

rules/success_after_failures.yaml

Rule:

RULE-002

Distributed password-spray rule:

rules/distributed_password_spray.yaml

Rule:

RULE-003

Detection engine:

engine/detection_engine.py

Test suite:

tests/test_detection_engine.py

## 16. Professional Portfolio Positioning

This case should be presented as evidence of:

Hands-on SOC Laboratory Experience

and:

Detection Engineering and Security Investigation Projects

The case demonstrates practical capability in:

Authentication attack detection.
Password-spraying investigation.
Alert triage.
Investigation pivoting.
Detection correlation.
Evidence preservation.
Threat-hunting methodology.
Detection engineering feedback.
Security testing.
Evidence-based reporting.

The case should not be presented as production SOC employment or as evidence of a confirmed real-world breach investigation.

## 17. Final Case Study Conclusion

CASE-002 demonstrates a complete cross-project security workflow from suspicious authentication telemetry through detection, investigation, correlation, response assessment, and detection-engineering feedback.

The SOC Operations Lab identified a password-spraying pattern involving 13 failed authentication attempts against 7 accounts from 198.51.100.40.

A successful authentication for alice occurred during the same sequence and became the primary investigation pivot.

The SIEM Detection Lab provides complementary successful-after-failures coverage through RULE-002 and related distributed password-spray coverage through RULE-003.

The evidence supports password-spraying behavior and successful authentication within the authorized laboratory environment, but it does not establish account compromise or broader post-authentication attack activity.

The strongest next improvement is additional endpoint, session, network, and account-activity telemetry that can correlate successful authentication with subsequent behavior.

This case demonstrates the intended relationship between detection engineering and SOC investigation: detect broadly, investigate systematically, preserve evidence, communicate uncertainty accurately, and continuously improve detection coverage.
