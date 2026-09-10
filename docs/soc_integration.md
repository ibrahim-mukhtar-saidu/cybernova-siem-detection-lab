# SOC Operations Integration

## Purpose

This document establishes the traceability relationship between detection rules implemented in the CYBERNOVA SIEM Detection Lab and the corresponding investigation and response evidence maintained in the CYBERNOVA SOC Operations Laboratory.

The integration provides an evidence chain from detection engineering through SOC investigation and response.

```text
SIEM Detection Rule
        ↓
SOC Detection
        ↓
SOC Case
        ↓
SOC Response Playbook
```

This document records repository-level traceability. It does not imply that the SIEM Detection Lab is a production SIEM or that the SOC Operations Laboratory represents production SOC experience.

## Detection Traceability Matrix

| SIEM Rule | Detection Behavior                                   | SOC Detection                     | SOC Case                                | SOC Playbook |
| --------- | ---------------------------------------------------- | --------------------------------- | --------------------------------------- | ------------ |
| RULE-001  | Same-source failed-login / brute-force detection     | DET-AUTH-001                      | CASE-001                                | PB-001       |
| RULE-003  | Distributed/source-rotation password-spray detection | Authentication detection coverage | Related password-spraying investigation | PB-002       |

## RULE-001 — Brute Force

### SIEM Detection

* Rule ID: `RULE-001`
* Rule Name: `Brute Force Detection`

The SIEM rule detects repeated failed authentication attempts originating from a single source IP within the configured detection window.

### SOC Mapping

* SOC Detection: `DET-AUTH-001`
* SOC Case: `CASE-001`
* SOC Playbook: `PB-001`

The SOC case represents an SSH brute-force investigation involving repeated failed authentication attempts against the root account.

The case evidence includes:

* detection alert;
* supporting authentication event IDs;
* source IP;
* targeted account;
* authentication timeline;
* analyst interpretation;
* investigation objectives;
* escalation criteria; and
* response and investigation artifacts.

PB-001 provides the corresponding operational workflow for suspected brute-force authentication activity.

### Evidence Relationship

```text
RULE-001
   ↓
DET-AUTH-001
   ↓
CASE-001
   ↓
PB-001
```

The SIEM rule and SOC detection use different identifiers because they belong to separate project layers. The mapping above establishes their documented relationship without treating the identifiers as interchangeable.

## RULE-003 — Distributed Password Spray

### SIEM Detection

* Rule ID: `RULE-003`
* Rule Name: `Distributed Password Spray Detection`

The SIEM rule detects repeated failed login attempts against the same user from multiple source IP addresses within the configured detection window.

This rule was introduced to extend authentication detection coverage for source-IP rotation and distributed password-spraying behavior.

### SOC Relationship

The SOC Operations Laboratory contains a separate password-spraying investigation, `CASE-002`, with corresponding detection `DET-AUTH-002` and playbook `PB-002`.

`CASE-002` represents a different password-spraying pattern: multiple targeted accounts from a common source.

Therefore, `RULE-003` is documented as related authentication/password-spray coverage rather than as the direct detection implementation that generated `CASE-002`.

The distinction preserves detection semantics while demonstrating cross-project coverage.

### Related SOC Evidence

* SOC Detection: `DET-AUTH-002`
* SOC Case: `CASE-002`
* SOC Playbook: `PB-002`

The SOC case evidence includes:

* detection alert;
* targeted users;
* failed authentication events;
* successful authentication pivot;
* investigation timeline;
* indicators;
* threat-intelligence assessment;
* threat hunting;
* response decision-making; and
* final investigation reporting.

PB-002 provides the corresponding operational workflow for password-spraying authentication alerts.

### Detection Coverage Relationship

```text
RULE-003
   ↓
Distributed / source-rotation
password-spray coverage
   ↓
Related SOC authentication
investigation patterns
   ↓
CASE-002 / PB-002
```

The SIEM rule represents detection-engineering coverage for distributed password spraying, while the SOC detection and case represent the operational investigation layer for a related password-spraying scenario.

## Cross-Project Evidence Model

The two repositories intentionally maintain different responsibilities.

### CYBERNOVA SIEM Detection Lab

Responsible for:

* event parsing;
* detection rules;
* detection logic;
* alert generation;
* alert normalization;
* metrics;
* dashboard presentation;
* detection testing; and
* adversarial detection validation.

### CYBERNOVA SOC Operations Laboratory

Responsible for:

* alert triage;
* case management;
* investigation;
* evidence preservation;
* timeline reconstruction;
* indicator analysis;
* threat intelligence;
* threat hunting;
* response decision-making;
* playbooks; and
* final reporting.

The integration relationship is therefore:

```text
Telemetry
    ↓
SIEM Detection Rule
    ↓
Generated Detection
    ↓
SOC Alert / Case
    ↓
Investigation
    ↓
Playbook
    ↓
Response Decision
    ↓
Lessons Learned
    ↓
Detection Engineering Feedback
```

## Evidence and Confidence Boundary

Cross-project traceability does not change the evidentiary status of an alert or case.

A detection indicates that configured analytical conditions were satisfied.

It does not independently establish:

* account compromise;
* unauthorized access;
* attacker attribution;
* credential theft;
* persistence;
* privilege escalation;
* lateral movement; or
* malicious intent.

The SOC investigation remains responsible for distinguishing:

```text
Observed Evidence
        ↓
Analyst Interpretation
        ↓
Hypothesis
        ↓
Confirmed Finding
        ↓
Recommended Action
```

This separation prevents detection output from being incorrectly represented as confirmed compromise.

## Current Integration Scope

The current documented mappings cover authentication scenarios for which corresponding SIEM and SOC evidence has been established:

```text
RULE-001 ↔ DET-AUTH-001 ↔ CASE-001 ↔ PB-001
```

For distributed password-spray coverage, the relationship is intentionally documented as related rather than one-to-one:

```text
RULE-003
   ↕
Related password-spray coverage
   ↕
DET-AUTH-002 / CASE-002 / PB-002
```

No additional rule-to-case mappings are asserted without corresponding evidence in both repositories.

## Engineering Principle

Cross-project integration should preserve evidence traceability without duplicating implementation.

The SIEM Detection Lab remains the detection-engineering source for its rules and tests.

The SOC Operations Laboratory remains the operational source for cases, investigations, and playbooks.

Future integrations should extend the documented evidence chain only when a corresponding detection, investigation, and response artifact exists.
