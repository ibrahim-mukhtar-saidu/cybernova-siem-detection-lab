# CASE-010 — Multi-Stage Attack Cross-Project Case Study

## 1. Case Overview

**Case ID:** `CASE-010`
**Scenario:** Multi-Stage Attack
**Correlation Detection:** `DET-CORR-001`
**Primary Playbook:** `PB-010 — Multi-Stage Attack`
**Environment:** Synthetic SOC laboratory
**Host:** `lab-linux-10`
**User:** `root`
**Source IP:** `198.51.100.90`
**Severity:** Critical
**Confidence:** High
**Stage Count:** 3
**Supporting Alerts:** 3
**Supporting Events:** 13

**SIEM Coverage Classification:**
**FULL SIEM MULTI-STAGE/CORRELATION DETECTION COVERAGE GAP**

---

## 2. Executive Summary

CASE-010 demonstrates cross-project correlation of three independently generated security detections into a single bounded multi-stage investigation.

The correlated sequence consists of:

1. `DET-AUTH-001` — SSH brute-force authentication activity.
2. `DET-AUTH-003` — successful authentication followed by post-authentication privileged/discovery activity.
3. `DET-LINUX-001` — suspicious Linux cron persistence activity.

`DET-CORR-001` requires all three stages, shared investigation pivots, chronological ordering, and occurrence within a 30-minute correlation window.

The observed sequence begins at `2026-09-09T10:02:03Z` and ends at `2026-09-09T10:12:00Z`, spanning approximately ten minutes.

The correlation strengthens the multi-stage investigation hypothesis but does not independently prove compromise.

---

## 3. Cross-Project Evidence Chain

```text
Synthetic telemetry
        ↓
DET-AUTH-001
        ↓
Authentication attack
        ↓
DET-AUTH-003
        ↓
Post-authentication activity
        ↓
DET-LINUX-001
        ↓
Suspicious Linux persistence
        ↓
DET-CORR-001
        ↓
CASE-010
        ↓
PB-010 — Multi-Stage Attack
```

The SOC Operations Laboratory supplies the detection and investigation evidence.

The SIEM Detection Laboratory is used to assess whether equivalent detection and correlation capability exists.

---

## 4. Authoritative Detection Contract

`DET-CORR-001` is defined as:

```text
ID: DET-CORR-001
Name: Multi-Stage Attack Correlation
Version: 1.0
Status: implemented
```

The detector correlates independent high-confidence detection alerts into a multi-stage sequence when they share investigation pivots and occur chronologically within the configured window.

Required input fields include:

```text
alert_id
detection_id
timestamp
severity
confidence
host
user
supporting_event_ids
```

---

## 5. Correlation Logic

The required stages are:

```text
DET-AUTH-001
DET-AUTH-003
DET-LINUX-001
```

Correlation pivots are:

```text
host
user
source_ip
```

The configured correlation window is:

```text
30 minutes
```

The minimum required stage count is:

```text
3
```

The expected sequence is:

```text
credential_access
        ↓
post_authentication_activity
        ↓
persistence
```

The alert is generated with:

```text
Severity: Critical
Confidence: High
```

---

## 6. Correlation Result

The generated alert is:

```text
ALERT-CASE-010-DET-CORR-001
```

Observed result:

| Field             | Value          |
| ----------------- | -------------- |
| Detection         | `DET-CORR-001` |
| Severity          | Critical       |
| Confidence        | High           |
| Stages            | 3              |
| Supporting alerts | 3              |
| Supporting events | 13             |
| Window            | 30 minutes     |
| Observed span     | ~10 minutes    |

The correlation therefore satisfied the configured minimum stage requirement.

---

## 7. Stage 1 — Authentication Attack

Detection:

`DET-AUTH-001 — SSH Brute-Force Authentication Detection`

Observed evidence includes six failed SSH authentication attempts from:

```text
198.51.100.90
```

against:

```text
lab-linux-10
```

The failed attempts were followed by successful authentication.

Supporting events:

```text
EVT-010001
EVT-010002
EVT-010003
EVT-010004
EVT-010005
EVT-010006
EVT-010007
```

The detection threshold was five failed attempts within five minutes.

This stage establishes observed authentication attack behavior within the synthetic environment.

---

## 8. Stage 2 — Post-Authentication Activity

Detection:

`DET-AUTH-003 — Suspicious Post-Authentication Privileged Session`

The successful authentication was followed by a session and four commands:

```text
whoami
id
sudo -l
uname -a
```

The activity shares the same laboratory host, user, and source-IP context required by the correlation contract.

The sequence provides post-authentication discovery and privilege-related context.

The evidence does not independently establish malicious intent or compromise.

---

## 9. Stage 3 — Linux Persistence

Detection:

`DET-LINUX-001 — Suspicious Linux Cron Persistence Detection`

Observed evidence includes:

```text
File: /etc/cron.d/system-update
Process: bash
Behavior: curl download-and-execute pattern
Shell: sh
Hidden payload indicator: true
```

Supporting event:

```text
EVT-010013
```

The benign `crontab -e` event:

```text
EVT-010014
```

was not included in the correlated alert.

This demonstrates that ordinary cron administration should not automatically be treated as part of the multi-stage sequence.

---

## 10. Timeline Assessment

| Stage | Detection       | Time                   |
| ----- | --------------- | ---------------------- |
| 1     | `DET-AUTH-001`  | `2026-09-09T10:02:03Z` |
| 2     | `DET-AUTH-003`  | `2026-09-09T10:03:21Z` |
| 3     | `DET-LINUX-001` | `2026-09-09T10:12:00Z` |

The complete sequence spans approximately ten minutes.

The configured correlation window is thirty minutes.

Therefore:

```text
Observed span:       ~10 minutes
Configured window:   30 minutes
Required stages:     3
Observed stages:     3
```

The sequence satisfies the correlation contract.

---

## 11. Investigation Assessment

The evidence supports a coherent investigation hypothesis connecting:

```text
Repeated authentication failures
        ↓
Successful authentication
        ↓
Post-authentication discovery/privilege activity
        ↓
Suspicious cron persistence
```

The shared host, user, source-IP context and chronology increase the investigative significance of the sequence.

However, correlation is an investigative prioritization mechanism rather than independent proof of compromise.

---

## 12. Threat-Intelligence Assessment

The source address:

```text
198.51.100.90
```

is synthetic documentation-range infrastructure used within the laboratory scenario.

It must not be treated as evidence of a real external actor or malicious infrastructure.

The cron resource and command-line behavior are suspicious within the scenario, but the available evidence does not establish external attribution.

No real-world actor attribution is claimed.

---

## 13. MITRE ATT&CK Context

The correlation contract references:

| Technique   | Context                                   |
| ----------- | ----------------------------------------- |
| `T1110`     | Brute Force                               |
| `T1078`     | Valid Accounts                            |
| `T1087`     | Account Discovery                         |
| `T1069.001` | Permission Groups Discovery: Local Groups |
| `T1053.003` | Scheduled Task/Job: Cron                  |

These mappings describe behaviors represented by the synthetic telemetry.

They do not independently prove attacker intent, compromise, or successful persistence.

---

## 14. Threat-Hunting Assessment

Relevant hunting pivots include:

* source IP;
* target host;
* user;
* authentication failures;
* successful authentication;
* session identifier;
* privileged commands;
* cron configuration;
* `/etc/cron.d/`;
* shell download-and-execute behavior;
* process ancestry;
* network connections;
* subsequent process execution;
* persistence-related file activity.

The available CASE-010 evidence supports reconstruction of the supplied sequence.

No additional activity outside the supplied synthetic telemetry is claimed.

---

## 15. Response Assessment

The appropriate laboratory response workflow is:

```text
Validate correlated alert
        ↓
Preserve supporting evidence
        ↓
Reconstruct timeline
        ↓
Validate authentication activity
        ↓
Validate post-authentication session
        ↓
Inspect cron persistence
        ↓
Validate payload/network/process evidence
        ↓
Assess containment and eradication requirements
        ↓
Document limitations
        ↓
Close only when evidence requirements are satisfied
```

No production containment, credential reset, eradication, recovery, or customer notification is claimed.

---

## 16. Root Cause Assessment

The available evidence does not establish:

* initial access mechanism;
* credential origin;
* whether the authentication was authorized;
* whether the payload was successfully retrieved;
* whether the payload executed successfully;
* whether cron persistence became active;
* whether additional systems were affected.

Root cause therefore remains undetermined.

---

## 17. Impact Assessment

The available evidence does not establish:

* confirmed compromise;
* data access;
* data exfiltration;
* lateral movement;
* privilege escalation;
* successful malware execution;
* persistence activation;
* service disruption;
* affected systems beyond the supplied laboratory host.

Impact therefore remains unconfirmed.

---

## 18. Evidence Limitations

Important limitations include:

* synthetic laboratory telemetry;
* limited event population;
* no production endpoint telemetry;
* no complete authentication environment;
* no independent payload analysis;
* no complete process ancestry;
* no full network telemetry;
* no external attribution evidence;
* possible timestamp/schema differences between detection outputs;
* correlation only over supplied alerts;
* fixed 30-minute correlation window.

These limitations prevent conclusions beyond the observed evidence.

---

## 19. SIEM Cross-Project Coverage Assessment

The current SIEM Detection Laboratory contains:

```text
RULE-001 — Brute Force Detection
RULE-002 — Successful Login After Multiple Failures
RULE-003 — Distributed Password Spray Detection
```

There is no equivalent SIEM rule implementing:

```text
DET-CORR-001
```

The existing authentication rules do not implement the complete three-stage correlation of:

```text
DET-AUTH-001
        +
DET-AUTH-003
        +
DET-LINUX-001
        ↓
DET-CORR-001
```

Therefore the correct classification is:

```text
FULL SIEM MULTI-STAGE/CORRELATION
DETECTION COVERAGE GAP
```

This is not a partial-coverage claim.

`RULE-001` and `RULE-002` provide related authentication coverage, but they do not reproduce the cross-detection correlation contract.

---

## 20. Engineering Significance

CASE-010 demonstrates the correlation layer above individual detections.

Individual detections answer questions such as:

```text
Did repeated authentication failures occur?
Did suspicious post-authentication activity occur?
Did suspicious persistence activity occur?
```

Correlation asks:

```text
Do these independent signals form a coherent sequence
when evaluated using shared pivots and bounded time?
```

This distinction is important for SOC triage and investigation prioritization.

---

## 21. Detection Improvement Feedback

Future engineering improvements should consider:

1. normalized alert timestamps;
2. explicit schema contracts between detection layers;
3. configurable correlation windows;
4. stronger session correlation;
5. process ancestry;
6. network-to-process correlation;
7. persistence-event correlation;
8. cross-host sequence detection;
9. negative/benign multi-stage test cases;
10. adversarial sequence testing;
11. missing-stage handling;
12. duplicate-alert handling;
13. timestamp-boundary testing;
14. source-IP normalization;
15. correlation confidence scoring.

These are engineering opportunities, not implemented capabilities of the current SIEM project.

---

## 22. False-Positive Considerations

Potential legitimate scenarios include:

* authorized penetration testing;
* security validation;
* administrator authentication troubleshooting;
* privileged system administration;
* legitimate cron configuration;
* automated maintenance;
* approved vulnerability testing.

Shared host, user, and source context can occur during legitimate administrative activity.

Correlation should therefore increase investigative priority without eliminating analyst validation.

---

## 23. False-Negative Considerations

The correlation layer may fail to identify related activity when:

* one detection stage does not fire;
* telemetry is missing;
* source IP is unavailable;
* timestamps are inaccurate;
* events fall outside the 30-minute window;
* an attacker changes users;
* an attacker changes hosts;
* source addresses rotate;
* one stage is not represented by an existing detector;
* alert schemas cannot be normalized.

These limitations are explicitly consistent with the `DET-CORR-001` contract.

---

## 24. Evidence Quality

Evidence quality is assessed separately from analyst interpretation.

### Observed

* six authentication failures;
* successful authentication;
* four post-authentication commands;
* suspicious cron persistence event;
* three independent detection stages;
* three supporting alerts;
* thirteen supporting events;
* correlated alert generated.

### Interpreted

* sequence is consistent with a multi-stage attack;
* activity warrants high-priority investigation;
* correlation increases investigative confidence.

### Not established

* confirmed compromise;
* attacker identity;
* unauthorized access;
* successful payload execution;
* successful persistence execution;
* data theft;
* production impact.

This separation preserves portfolio evidence integrity.

---

## 25. Portfolio Integrity Statement

CASE-010 is presented as a controlled SOC laboratory exercise.

It does not represent:

* production SOC employment;
* a real customer incident;
* a real victim;
* real credentials;
* real malware;
* real attacker infrastructure;
* confirmed compromise;
* verified production impact.

All conclusions are limited to the supplied synthetic evidence.

---

## 26. Validation Evidence

The authoritative SOC Operations Laboratory reports that the dedicated correlation workflow was validated against the CASE-010 synthetic detection outputs.

The resulting correlation contained:

```text
1 correlated alert
3 stages
3 supporting alerts
13 supporting events
```

The correlation implementation also accommodates compatible temporal fields such as:

```text
timestamp
first_seen
last_seen
```

This addresses schema differences between the independent detection outputs.

---

## 27. Cross-Project Relationship

The complete relationship is:

```text
CYBERNOVA SOC Operations Lab
        │
        ├── DET-AUTH-001
        ├── DET-AUTH-003
        ├── DET-LINUX-001
        ├── PB-010
        └── CASE-010
                 │
                 ↓
       CYBERNOVA SIEM Detection Lab
                 │
                 ├── RULE-001
                 ├── RULE-002
                 └── RULE-003
                         │
                         ↓
              CORRELATION COVERAGE GAP
```

The SIEM project currently does not reproduce the correlation capability demonstrated by the SOC Operations Laboratory.

---

## 28. Final Assessment

The synthetic evidence supports a coherent multi-stage investigation sequence involving:

```text
Authentication attack
        ↓
Successful authentication
        ↓
Post-authentication activity
        ↓
Suspicious Linux persistence
```

The sequence satisfies the `DET-CORR-001` laboratory correlation contract.

The evidence supports high-priority investigation.

The evidence does **not** independently establish confirmed compromise, attacker attribution, successful payload execution, or successful persistence activation.

---

## 29. Final Disposition

```text
Disposition:
Correlated multi-stage attack investigation candidate

Evidence confidence:
High for observed telemetry and correlation

Compromise status:
Not established

Attribution:
Not established

Production impact:
Not assessed

SIEM coverage:
Full multi-stage/correlation detection gap

Environment:
Synthetic SOC laboratory
```

---

## 30. Closure Criteria

CASE-010 case-study work should be considered technically complete only after:

* the case study accurately reflects authoritative SOC evidence;
* the SIEM coverage classification is evidence-backed;
* Markdown structure is valid;
* `git diff --check` is clean;
* the complete SIEM test suite passes;
* only the intended CASE-010 file is staged;
* the case-study commit is pushed;
* local and remote commit hashes match;
* the worktree is clean.

---

## 31. Cross-Project Conclusion

CASE-010 is the correlation-layer culmination of the Phase 22 case-study sequence.

It demonstrates how independent detections can be connected into a bounded investigation while preserving the distinction between:

```text
Telemetry
   ↓
Detection
   ↓
Alert
   ↓
Correlation
   ↓
Investigation
   ↓
Analyst interpretation
   ↓
Evidence-backed conclusion
```

The case also exposes a genuine engineering boundary: the SOC Operations Laboratory contains a dedicated multi-stage correlation capability, while the SIEM Detection Laboratory currently contains only individual authentication detection rules.

That gap is valuable portfolio evidence because it demonstrates both **what has been engineered** and **what has not yet been implemented**.

**Final conclusion:**

> CASE-010 contains a coherent synthetic sequence linking authentication attack activity, successful authentication, post-authentication discovery and privilege-related activity, and suspicious Linux cron persistence on the same laboratory host and user within the configured correlation window. The evidence supports investigation of a correlated multi-stage attack sequence, but does not independently prove compromise.
