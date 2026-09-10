# CASE-007 — File Integrity Violation

## Cross-Project SOC Case Study

**Case ID:** CASE-007
**Detection:** DET-HOST-001 — File Integrity Violation Detection
**Alert:** ALERT-CASE-007-DET-HOST-001
**Primary Source Project:** CYBERNOVA SOC Operations Laboratory
**Correlation Project:** CYBERNOVA SIEM Detection Laboratory
**Incident Category:** Host Security / File Integrity
**Environment:** Authorized SOC Laboratory
**Evidence Classification:** Observed Synthetic Laboratory Evidence
**Initial Severity:** High
**Initial Confidence:** High
**Current Classification:** Suspicious File Integrity Activity
**Compromise:** Not Established

---

## 1. Executive Summary

CASE-007 documents a synthetic file-integrity security event detected by the CYBERNOVA SOC Operations Laboratory.

The laboratory detection `DET-HOST-001` identifies clustered file-integrity violations occurring on the same host within a five-minute detection window. The detector requires at least two qualifying file-state changes.

The CASE-007 telemetry contained two qualifying file-integrity violations within the configured five-minute window. These events generated the case alert.

A third file-integrity event occurred later, outside the configured detection window. That event is explicitly classified in the laboratory evidence as an authorized laboratory change and therefore did not contribute to the generated alert.

The available evidence supports the conclusion that the detection logic successfully identified the intended synthetic clustered file-integrity scenario.

The evidence does **not** independently establish malicious intent, compromise, persistence, privilege escalation, malware execution, lateral movement, or data impact.

The cross-project review found that the current CYBERNOVA SIEM Detection Laboratory contains authentication-focused rules:

* `RULE-001` — Brute Force Detection
* `RULE-002` — Successful Login After Multiple Failures
* `RULE-003` — Distributed Password Spray Detection

No equivalent host/file-integrity detection rule was identified.

Therefore, CASE-007 demonstrates a **full host/file-integrity detection coverage gap** in the current SIEM Detection Laboratory.

---

## 2. Objective

The objectives of this case study are to:

1. validate the relationship between `DET-HOST-001` and CASE-007;
2. document the observed file-integrity evidence;
3. reconstruct the detection sequence;
4. distinguish observed evidence from analytical interpretation;
5. assess the current SIEM detection coverage;
6. identify false-positive and false-negative considerations;
7. evaluate relevant ATT&CK context;
8. identify detection-engineering improvement opportunities;
9. preserve laboratory limitations;
10. demonstrate cross-project SOC engineering reasoning.

---

## 3. Detection Contract

The authoritative detection contract for CASE-007 is:

```text
Detection ID: DET-HOST-001
Name: File Integrity Violation Detection
Version: 1.0
Status: implemented
```

### Description

The detector identifies clustered file-integrity violations on the same host within a five-minute detection window.

### Data Source

```text
Event Type:
file_integrity

Required Status:
changed
```

### Supported Change Types

```text
modified
created
deleted
```

### Correlation Logic

```text
Grouping:
host

Window:
5 minutes

Minimum Violations:
2
```

### Alert Output

The detection output includes:

```text
host
user
violation_count
affected_files
change_types
first_seen
last_seen
supporting_event_ids
```

### Alert Classification

```text
Severity:
high

Confidence:
high
```

### ATT&CK Context

```text
Technique:
T1070

Name:
Indicator Removal
```

The ATT&CK mapping is contextual. The file-integrity detection itself does not establish that indicator removal occurred.

---

## 4. Detection Behavior

The detector evaluates file-integrity events that have:

```text
status = changed
```

and whose change type is one of:

```text
modified
created
deleted
```

Events are grouped by host.

An alert is generated when at least two qualifying violations occur within the five-minute detection window for the same host.

Conceptually:

```text
file_integrity event
        │
        ├── status = changed
        │
        ├── supported change type
        │
        ▼
   group by host
        │
        ▼
 five-minute window
        │
        ▼
minimum 2 violations
        │
        ▼
      ALERT
```

This is a correlation condition, not a determination of maliciousness.

---

## 5. Observed CASE-007 Evidence

The authoritative CASE-007 evidence identifies the affected laboratory host and file-integrity activity.

The first two qualifying file-integrity events occurred within the configured five-minute detection window.

These events satisfied the detector's minimum violation threshold.

The resulting alert was:

```text
ALERT-CASE-007-DET-HOST-001
```

with:

```text
Severity: High
Confidence: High
```

The evidence package identifies the supporting event IDs and affected file information.

The case evidence also documents a third file-integrity change involving:

```text
/opt/application/config.yml
```

This third change occurred outside the five-minute detection window and is explicitly classified as an authorized laboratory change.

It therefore did not contribute to the alert.

---

## 6. Detection Result

The detector generated one alert because two qualifying file-integrity violations occurred on the same host within the configured five-minute window.

This demonstrates that the intended correlation logic operated as designed for the synthetic scenario.

The detection result establishes:

* qualifying file-integrity activity was observed;
* multiple qualifying events occurred on the same host;
* the events satisfied the configured temporal threshold;
* an alert was generated;
* the alert carried High severity and High confidence according to the detection contract.

The detection result does **not** establish:

* malicious intent;
* unauthorized activity;
* successful compromise;
* attacker identity;
* persistence;
* malware execution;
* privilege escalation;
* lateral movement;
* data access;
* data exfiltration.

---

## 7. Timeline Reconstruction

The case timeline contains three file-integrity events.

### Detection Window

The first two qualifying events occurred within five minutes of one another.

These events formed the correlation sequence that triggered `DET-HOST-001`.

```text
Event 1
   │
   │ within detection window
   ▼
Event 2
   │
   ▼
minimum violation threshold reached
   │
   ▼
ALERT-CASE-007-DET-HOST-001
```

### Third Event

A third file-integrity event involving:

```text
/opt/application/config.yml
```

occurred approximately 18 minutes after the first event.

It was therefore outside the five-minute detection window.

The laboratory evidence explicitly identifies this change as authorized.

Consequently:

```text
Event 1 ───── Event 2
     │
     └── within 5-minute window → ALERT

Event 3
     │
     └── outside window
         authorized laboratory change
         does not contribute to alert
```

This distinction is important because events outside the detector's configured correlation window must not be retrospectively treated as alert-supporting evidence.

---

## 8. Evidence vs Interpretation

### Observed Evidence

The laboratory evidence supports the following observations:

* file-integrity changes occurred;
* at least two qualifying changes occurred within the five-minute detection window;
* the events were associated with the same host;
* the detection generated an alert;
* the alert was classified High severity and High confidence;
* a third file-integrity change occurred outside the detection window;
* the third change was classified as an authorized laboratory change.

### Analytical Interpretation

The clustered changes justify investigation because multiple security-sensitive file-state changes occurred within a short interval.

However, file-state changes alone do not establish that an attacker performed them.

Potential legitimate explanations include:

* authorized administration;
* software installation or update activity;
* configuration management;
* maintenance;
* deployment activity;
* security tooling;
* laboratory simulation.

The available telemetry must therefore be evaluated alongside authorization, process, authentication, endpoint, and other relevant evidence.

---

## 9. Investigation Assessment

The primary investigation question is:

> Were the observed file-integrity changes authorized or indicative of suspicious host activity?

The detection itself cannot answer that question.

An analyst should correlate:

* host identity;
* user identity;
* process activity;
* command execution;
* authentication activity;
* privilege changes;
* persistence mechanisms;
* package-management activity;
* configuration-management activity;
* network activity;
* malware evidence;
* related file-integrity events.

The existing CASE-007 investigation evidence documents several telemetry limitations.

In particular, the dataset does not provide sufficient evidence to establish:

* malicious execution;
* persistence;
* network activity;
* malware involvement;
* package-management activity;
* configuration-management activity;
* broader host impact.

These gaps must remain explicit.

---

## 10. File Integrity Findings

The CASE-007 evidence identifies:

```text
/etc/passwd
```

as one of the security-sensitive files involved in the observed file-integrity activity.

Modification of `/etc/passwd` is security-relevant because the file participates in local account configuration.

However, the presence of a modification event does not independently establish unauthorized account manipulation.

Additional evidence would be required to determine:

* which account-related fields changed;
* who initiated the change;
* which process performed the modification;
* whether the modification was authorized;
* whether account privileges changed;
* whether persistence was established;
* whether subsequent authentication activity occurred.

The investigation therefore remains proportional to the available telemetry.

---

## 11. Threat Intelligence Assessment

The CASE-007 dataset does not contain direct network indicators associated with the observed file modifications.

No malware sample is associated with the case.

This limits external threat-intelligence enrichment.

The absence of network or malware indicators should not be interpreted as proof that no such activity occurred.

It means only that the available CASE-007 dataset does not provide that evidence.

---

## 12. Hunting Considerations

A host-focused investigation should consider:

```text
same host
same user
same process
same command
same affected files
same file paths
same modification pattern
related authentication
related privilege changes
related persistence
related network activity
```

Additional hunting hypotheses include:

* other security-sensitive files may have changed;
* similar changes may have occurred outside the initial five-minute window;
* the same process may have modified multiple files;
* a legitimate administrative process may explain the activity;
* persistence activity may exist outside the observed telemetry.

These remain hypotheses unless supported by additional evidence.

---

## 13. False Positive Analysis

Potential false positives include:

* authorized system administration;
* software installation;
* software updates;
* configuration management;
* automated deployment;
* security-agent activity;
* backup or restoration operations;
* authorized laboratory testing.

The third CASE-007 event demonstrates why temporal correlation alone cannot determine maliciousness.

An authorized change outside the detection window should not be used to inflate the original alert.

---

## 14. False Negative Analysis

The current detection may miss:

* a single file-integrity violation;
* changes separated by more than five minutes;
* activity occurring across multiple hosts;
* unsupported change types;
* telemetry with missing or incorrect host identity;
* events with incorrect status values;
* low-volume modification activity;
* attacks that modify files without generating supported telemetry.

An attacker could also distribute changes over time to avoid the minimum-event threshold.

These limitations are detection-engineering concerns rather than evidence that the current detector failed in CASE-007.

---

## 15. Adversarial Detection Review

Potential evasion strategies include:

* making only one file modification;
* spacing modifications beyond five minutes;
* distributing activity across hosts;
* modifying files without generating file-integrity telemetry;
* using processes that appear legitimate;
* performing changes through authorized administrative mechanisms;
* altering telemetry provenance;
* modifying unsupported file-state categories;
* deleting or manipulating evidence after modification.

The current detector is designed to identify clustered file-integrity violations, not every possible form of host tampering.

The limitations are therefore documented rather than hidden.

---

## 16. Cross-Project SIEM Coverage Assessment

The current SIEM Detection Laboratory contains:

```text
RULE-001 — Brute Force Detection
RULE-002 — Successful Login After Multiple Failures
RULE-003 — Distributed Password Spray Detection
```

These rules provide authentication-focused coverage.

No equivalent host/file-integrity detection rule was identified.

Therefore:

```text
DET-HOST-001
      ↓
CASE-007
      ↓
PB-007 / SOC investigation context
      ↓
SIEM Detection Laboratory
      ↓
No equivalent host/file-integrity rule
```

### Coverage Classification

**FULL HOST/FILE-INTEGRITY DETECTION COVERAGE GAP**

This is not a partial-coverage relationship.

The existing authentication rules do not provide equivalent detection of clustered file-integrity violations.

---

## 17. Cross-Project Correlation

CASE-007 demonstrates the value of separating operational SOC detection from SIEM detection-engineering coverage.

The SOC Operations Laboratory demonstrates:

```text
host telemetry
     ↓
DET-HOST-001
     ↓
alert
     ↓
CASE-007
     ↓
investigation
```

The SIEM Detection Laboratory currently demonstrates:

```text
authentication telemetry
     ↓
RULE-001 / RULE-002 / RULE-003
     ↓
authentication detections
```

The missing capability is:

```text
file-integrity telemetry
     ↓
host/file-integrity detection
     ↓
SIEM alert
```

This creates a clearly documented engineering opportunity rather than an undocumented weakness.

---

## 18. Detection Engineering Feedback

CASE-007 provides several detection-engineering lessons.

### Finding 1 — File Integrity Is Not Currently Covered

**Observation:**
The SOC Operations Laboratory contains implemented file-integrity detection, while the SIEM Detection Laboratory does not.

**Engineering implication:**
Host/file-integrity detection should be considered for future SIEM expansion.

### Finding 2 — Temporal Correlation Matters

**Observation:**
Two qualifying events within five minutes generated the alert.

**Engineering implication:**
Future implementation should preserve configurable time-window correlation.

### Finding 3 — File Changes Require Context

**Observation:**
File changes alone do not establish malicious intent.

**Engineering implication:**
Future detection engineering should consider process, user, command, authorization, and related endpoint context.

### Finding 4 — Authorized Changes Must Be Represented

**Observation:**
The third change was outside the detection window and explicitly authorized.

**Engineering implication:**
Future validation should include legitimate administrative activity to measure false-positive behavior.

### Finding 5 — Negative Evidence Must Remain Qualified

**Observation:**
The current dataset lacks network and malware telemetry.

**Engineering implication:**
The absence of those indicators should be recorded as a telemetry limitation rather than treated as proof of absence.

---

## 19. Recommended Future Validation

Any future host/file-integrity SIEM implementation should be tested against at least:

```text
single modification
multiple modifications within window
multiple modifications outside window
created file
modified file
deleted file
multiple hosts
multiple users
authorized administrative activity
duplicate events
malformed events
missing host field
missing timestamp
unsupported change type
invalid status
rapid repeated modifications
slow distributed modifications
```

Testing should include both positive and negative cases.

Only executed validation results should be reported as completed results.

---

## 20. Response Considerations

The available CASE-007 evidence does not justify claiming that eradication or containment was performed.

A real investigation would first preserve evidence and establish authorization before modifying the affected system.

Potential response considerations include:

* preserve the original alert;
* preserve supporting telemetry;
* identify the affected host;
* identify the responsible user and process;
* determine whether changes were authorized;
* investigate account and privilege implications;
* investigate persistence;
* correlate endpoint and network telemetry;
* contain only when justified by evidence;
* restore known-good configuration where required;
* validate file integrity after recovery;
* monitor for recurrence.

These are response considerations, not claims that the actions were actually performed in the laboratory case.

---

## 21. Closure Assessment

CASE-007 demonstrates successful execution of the intended `DET-HOST-001` synthetic detection scenario.

The case establishes:

* two qualifying file-integrity violations occurred within the configured five-minute window;
* the detector generated the intended alert;
* a third authorized laboratory change occurred outside the detection window;
* the evidence supports investigation of suspicious file-integrity activity;
* the available telemetry does not independently establish compromise;
* the current SIEM Detection Laboratory has no equivalent host/file-integrity detection rule;
* future detection improvements have been identified.

The case should therefore be classified according to the evidence available rather than escalated to confirmed compromise.

---

## 22. Lessons Learned

### Detection

Temporal clustering provides useful prioritization for file-integrity activity, but it is not sufficient to establish maliciousness.

### Investigation

File changes should be correlated with user, process, command, authentication, privilege, persistence, and network evidence.

### Evidence

Authorized activity must be explicitly separated from suspicious activity.

### SIEM Engineering

The current SIEM rule inventory has a clear host/file-integrity coverage gap.

### Portfolio Engineering

Cross-project analysis provides stronger evidence of engineering capability than simply listing separate security projects.

### Professional Boundary

This case demonstrates controlled laboratory SOC and detection-engineering capability. It does not represent production SOC employment or a real customer incident.

---

## 23. Portfolio Evidence

CASE-007 demonstrates practical capability in:

* file-integrity monitoring;
* host-based detection;
* temporal correlation;
* alert validation;
* SOC investigation;
* evidence classification;
* timeline reconstruction;
* false-positive analysis;
* false-negative analysis;
* threat-intelligence boundaries;
* MITRE ATT&CK contextual mapping;
* adversarial detection review;
* detection-engineering feedback;
* SIEM coverage analysis;
* cross-project security engineering.

These capabilities are demonstrated through controlled laboratory evidence.

They must not be represented as professional production SOC experience.

---

## 24. Reproducibility

Primary SOC evidence:

```text
~/cybernova-soc-operations-lab/cases/CASE-007/
```

Detection contract:

```text
~/cybernova-soc-operations-lab/detections/host/DET-HOST-001-file-integrity.yml
```

Relevant telemetry:

```text
~/cybernova-soc-operations-lab/telemetry/host/CASE-007.jsonl
```

Alert evidence:

```text
~/cybernova-soc-operations-lab/alerts/CASE-007-DET-HOST-001.json
```

SIEM rules reviewed:

```text
~/cybernova-siem-detection-lab/rules/
```

---

## 25. Final Analyst Statement

> The CYBERNOVA SOC Detection Engine generated a high-confidence `DET-HOST-001` alert after two qualifying file-integrity violations were observed on the same laboratory host within the configured five-minute detection window. The evidence supports investigation of clustered host file-state changes, including a security-sensitive file modification. A third authorized laboratory change occurred outside the detection window and did not contribute to the alert. The available telemetry does not independently establish malicious intent, compromise, persistence, or attacker attribution. Cross-project review identified a full host/file-integrity detection coverage gap in the current SIEM Detection Laboratory. Additional endpoint, authentication, process, network, authorization, and file evidence would be required before reaching a stronger conclusion.

---

## 26. Limitations

This case study is based on controlled synthetic laboratory telemetry.

It does not claim:

* production SOC deployment;
* real customer incidents;
* professional SOC employment;
* confirmed compromise;
* real-world attacker attribution;
* complete host-security coverage;
* complete file-integrity coverage;
* successful remediation of a real system.

All conclusions remain proportional to the available evidence.

---

## 27. Case Status

**CASE-007 — READY FOR VALIDATION**

Validation must be completed before the case is marked closed.

Required repository checks:

```text
git diff --check
pytest -q
git status --short
```

Only after the checks pass and the case study is committed and pushed should CASE-007 be marked:

```text
CLOSED
```

---

**Author:**
**Ibrahim Mukhtar Saidu**

**CYBERNOVA SOC Operations Laboratory**
Defensive Cybersecurity Research and SOC Engineering Portfolio
