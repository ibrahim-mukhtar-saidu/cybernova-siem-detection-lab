# CASE-001 — Cross-Project SSH Brute-Force Case Study

## 1. Case Study Purpose

This case study demonstrates the end-to-end relationship between SIEM detection engineering and SOC investigation using CASE-001.

It connects the detection-engineering evidence maintained in the CYBERNOVA SIEM Detection Lab with the investigation and response evidence maintained in the CYBERNOVA SOC Operations Laboratory.

The case is based on an authorized laboratory scenario.

It does not represent production SOC experience or a confirmed real-world compromise.

---

## 2. Evidence Chain

```text
Authentication Telemetry
        ↓
RULE-001
        ↓
Brute-Force Detection
        ↓
DET-AUTH-001
        ↓
CASE-001
        ↓
PB-001
        ↓
Investigation
        ↓
Lessons Learned
        ↓
Detection Engineering Feedback
```

### Repository Responsibilities

**CYBERNOVA SIEM Detection Lab**

* authentication event parsing;
* detection rules;
* detection logic;
* alert generation;
* detection testing;
* detection metrics;
* dashboard presentation; and
* adversarial detection validation.

**CYBERNOVA SOC Operations Laboratory**

* alert triage;
* case management;
* evidence preservation;
* investigation;
* timeline reconstruction;
* threat intelligence;
* threat hunting;
* response planning;
* playbooks; and
* final reporting.

---

## 3. Detection Engineering

### Detection Rule

**Rule ID:** `RULE-001`

**Rule Name:** Brute Force Detection

**MITRE ATT&CK:** T1110 — Brute Force

**Severity:** HIGH

**Threshold:** 5 failed attempts

**Detection Window:** 10 minutes

**Event Type:** `FAILED_LOGIN`

The SIEM detection identifies repeated failed authentication attempts originating from the same source IP within the configured detection window.

The rule is implemented in:

`rules/brute_force.yaml`

The detection logic is implemented in:

`engine/detection_engine.py`

The detector sorts authentication events by timestamp, evaluates failed-login events, maintains a time window per source IP, and generates one brute-force alert when the configured threshold is reached.

---

## 4. SOC Detection Relationship

The corresponding SOC detection is:

`DET-AUTH-001 — SSH Brute-Force Authentication Detection`

The corresponding SOC investigation is:

`CASE-001`

The corresponding response playbook is:

`PB-001 — Brute-Force Authentication`

The identifiers belong to separate repository layers and are therefore not interchangeable.

The documented relationship is:

```text
RULE-001
   ↓
DET-AUTH-001
   ↓
CASE-001
   ↓
PB-001
```

---

## 5. Observed Authentication Activity

CASE-001 contains the following observed authentication sequence.

**Host:** `lab-auth-01`

**Protocol:** SSH

**Target Account:** `root`

**Source IP:** `198.51.100.25`

**Failed Attempts:** 8

**Successful Authentication:** Yes

**Successful Event:** `EVT-001012`

The supporting authentication events are:

```text
EVT-001004
EVT-001005
EVT-001006
EVT-001007
EVT-001008
EVT-001009
EVT-001010
EVT-001011
EVT-001012
```

Events `EVT-001004` through `EVT-001011` represent eight failed SSH authentication attempts.

`EVT-001012` represents the subsequent successful SSH authentication.

The eight failures exceeded the SOC case detection threshold of five failures within five minutes.

---

## 6. Investigation Pivot

The most important investigative pivot was the successful authentication event:

`EVT-001012`

This event connected:

```text
Source IP
    ↓
Target Account
    ↓
Repeated Authentication Failures
    ↓
Successful Authentication
```

The successful authentication increased investigation priority because it followed repeated failures against the privileged `root` account.

However, the successful authentication is itself only observed telemetry.

It does not independently establish:

* account compromise;
* unauthorized access;
* credential theft;
* malicious execution;
* persistence;
* privilege escalation;
* lateral movement; or
* data exfiltration.

Additional identity, endpoint, network, and authorization evidence would be required.

---

## 7. SOC Investigation

The SOC investigation expanded beyond the original detection alert.

CASE-001 contains dedicated evidence for:

* alert preservation;
* authentication timeline;
* indicators;
* investigation;
* threat intelligence;
* threat hunting;
* response;
* final reporting; and
* lessons learned.

The investigation used the source IP, account, event sequence, and successful authentication as primary pivots.

Threat hunting confirmed the relevant authentication activity in the available dataset.

The available evidence did not provide endpoint or network telemetry sufficient to establish post-authentication activity.

That limitation was recorded as an evidence gap rather than interpreted as proof that no additional activity occurred.

---

## 8. Threat Intelligence Boundary

The source address `198.51.100.25` is a documentation/test address used for the laboratory scenario.

External attribution was therefore intentionally avoided.

The case uses behavioral evidence rather than unsupported actor attribution.

This preserves the distinction between:

**Observed Evidence**

and

**Attribution or Hypothesis**

---

## 9. Response Assessment

PB-001 provides the corresponding operational workflow for suspected brute-force authentication activity.

CASE-001 response documentation distinguishes between:

**Recommended Response**

and

**Response Actually Performed**

Recommended containment and protection actions include appropriate evidence preservation, validation of authorization, account protection, source restriction where authorized, and additional investigation.

No production containment, credential rotation, host isolation, eradication, or recovery is claimed as performed.

The case remains an authorized laboratory investigation.

---

## 10. Detection Engineering Feedback

The investigation identified several opportunities for improving authentication detection coverage.

### Existing Coverage

`RULE-001` detects repeated failures from a common source IP.

### Related Detection Coverage

The SIEM Detection Lab also contains:

`RULE-002` — Successful Login After Failures

and:

`RULE-003` — Distributed Password Spray Detection

These rules extend authentication coverage beyond the original same-source brute-force pattern.

### Further Improvements

Future detection engineering can consider:

* privileged-account risk weighting;
* authentication success following repeated failures;
* multiple-account targeting;
* multiple-host targeting;
* source-IP rotation;
* endpoint correlation;
* network correlation; and
* additional regression scenarios.

Detection improvements should be introduced only when supported by a concrete requirement or observed limitation.

---

## 11. Testing Evidence

The detection pipeline has been tested against positive and negative authentication scenarios.

Relevant validation includes:

* threshold reached;
* threshold not reached;
* events outside the detection window;
* successful authentication following failures;
* multiple accounts;
* multiple source IPs;
* duplicate events;
* malformed configuration;
* event ordering; and
* mixed event types.

The SIEM Detection Lab's full automated test suite passed with:

**135 tests passed**

at the completion of the current quality-gate phase.

The case study does not treat test results as proof of real-world detection performance.

---

## 12. Evidence and Confidence Model

The investigation follows this evidence model:

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

### Observed Evidence

Eight failed SSH authentication attempts from `198.51.100.25` against `root`, followed by successful authentication event `EVT-001012`.

### Analyst Interpretation

The sequence is consistent with an SSH brute-force authentication pattern followed by successful authentication.

### Hypothesis

The successful authentication may represent unauthorized access.

### Confirmed Finding

The documented authentication events occurred in the supplied laboratory telemetry.

### Not Confirmed

Account compromise, malicious execution, persistence, lateral movement, and data impact remain unconfirmed.

This boundary prevents detection output from being represented as confirmed compromise.

---

## 13. Lessons Learned

The case demonstrates several important SOC engineering principles.

### Detection Is the Beginning

A detection identifies a condition that requires analyst evaluation.

It does not end the investigation.

### Successful Authentication Matters

A successful authentication following repeated failures is an important investigation pivot, particularly when a privileged account is involved.

### Evidence Gaps Must Become Tasks

Missing endpoint or network telemetry should produce concrete investigation requirements rather than unsupported conclusions.

### Preserve Original Evidence

The original alert and supporting telemetry should remain available for reproducibility and auditability.

### Recommendations Are Not Actions

A professional case record must clearly distinguish what was recommended from what was actually performed.

### Detection Must Improve

Completed investigations should produce actionable detection-engineering feedback when a genuine coverage opportunity is identified.

---

## 14. Cross-Project Value

This case demonstrates how separate cybersecurity projects can form a coherent engineering workflow without duplicating responsibilities.

```text
SIEM Engineering
      ↓
Detection
      ↓
SOC Triage
      ↓
Investigation
      ↓
Threat Hunting
      ↓
Response Planning
      ↓
Lessons Learned
      ↓
Detection Engineering Feedback
```

The SIEM repository provides the detection-engineering implementation and validation.

The SOC repository provides the operational investigation and response evidence.

The cross-project case study provides the narrative connecting those layers.

---

## 15. Evidence References

### SIEM Detection Lab

* `rules/brute_force.yaml`
* `engine/detection_engine.py`
* `reports/detection_rules_documentation.md`
* `docs/soc_integration.md`

### SOC Operations Laboratory

* `cases/CASE-001/README.md`
* `cases/CASE-001/alert.json`
* `cases/CASE-001/timeline.md`
* `cases/CASE-001/investigation.md`
* `cases/CASE-001/threat-intelligence.md`
* `cases/CASE-001/hunting.md`
* `cases/CASE-001/response.md`
* `cases/CASE-001/lessons-learned.md`
* `cases/CASE-001/final-report.md`
* `playbooks/PB-001-brute-force-authentication.md`

These references identify the source artifacts used to establish the cross-project case narrative.

---

## 16. Professional Portfolio Positioning

This case study demonstrates hands-on laboratory experience with:

* SIEM detection engineering;
* authentication telemetry analysis;
* alert validation;
* SOC triage;
* case investigation;
* timeline reconstruction;
* threat hunting;
* threat intelligence assessment;
* incident-response planning;
* evidence integrity;
* detection testing; and
* detection-engineering feedback.

The appropriate positioning is:

**Hands-on SOC Laboratory Experience**

and

**Detection Engineering and Security Investigation Projects**

This case study should not be represented as production SOC employment or a real-world confirmed breach.

---

## 17. Final Case Study Conclusion

CASE-001 demonstrates an evidence-driven path from SIEM detection to SOC investigation.

The SIEM detected repeated failed SSH authentication attempts from a common source.

The SOC investigation then expanded the alert into a structured case using authentication evidence, timelines, threat hunting, threat intelligence, response planning, and lessons learned.

The subsequent successful authentication increased investigative priority but did not independently establish compromise.

The investigation therefore maintained a clear boundary between observed evidence, interpretation, hypothesis, and confirmed findings.

The principal engineering lesson is:

> **Detect suspicious behavior, preserve the evidence, investigate systematically, state uncertainty honestly, and feed genuine findings back into detection engineering.**
