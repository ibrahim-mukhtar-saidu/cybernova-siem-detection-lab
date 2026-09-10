# CASE-003 — Suspicious PowerShell Cross-Project Case Study

## 1. Case Study Purpose

This case study documents the relationship between the CYBERNOVA SOC Operations Laboratory's suspicious PowerShell investigation and the CYBERNOVA SIEM Detection Lab.

CASE-003 demonstrates an important cross-project engineering condition:

- the SOC Operations Laboratory contains an implemented endpoint detection;
- the detection generated two high-severity, high-confidence alerts;
- the alerts were investigated through a documented SOC workflow;
- the SIEM Detection Lab does not currently contain an equivalent PowerShell/endpoint detection rule.

The absence of an equivalent SIEM rule is documented as a detection-coverage gap rather than being represented as an existing integration.

This preserves evidence traceability and avoids fabricating SIEM capability.

---

## 2. Evidence Chain

The established SOC evidence chain is:

Synthetic Windows Endpoint Telemetry
              |
              v
       DET-ENDPOINT-001
              |
              v
           CASE-003
              |
              v
           PB-003
              |
              v
      Investigation Findings

The current SIEM relationship is:

CASE-003 / DET-ENDPOINT-001
              |
              |  coverage comparison
              v
CYBERNOVA SIEM Detection Lab
              |
              v
No equivalent PowerShell rule
currently implemented

This is a coverage relationship, not a direct SIEM rule-to-case mapping.

## 3. SOC Endpoint Detection
Detection
Detection ID: DET-ENDPOINT-001
Detection Name: Suspicious PowerShell Execution
Detection Version: 1.0
Severity: High
Confidence: High
MITRE ATT&CK: T1059.001 — PowerShell
Environment: Synthetic Windows endpoint telemetry

The SOC detection generated two alerts.

Both alerts involved:

Host: lab-win-04
User: david
Process: powershell.exe
Parent process: winword.exe
Encoded PowerShell execution

The second alert contained additional correlated activity.

## 4. SIEM Coverage Assessment

The current SIEM Detection Lab contains three authentication-focused rules:

RULE-001 — Brute Force Detection
RULE-002 — Successful Login After Multiple Failures
RULE-003 — Distributed Password Spray Detection

No current rule implements equivalent PowerShell or Windows endpoint detection logic.

The SIEM repository therefore cannot legitimately claim that it generated the DET-ENDPOINT-001 alerts.

This distinction is intentional.

The SOC Operations Laboratory and SIEM Detection Lab have different responsibilities, and cross-project integration must only be asserted where corresponding implementation evidence exists.

## 5. CASE-003 Observed Activity

The primary host was:

lab-win-04

The primary user was:

david

The suspicious execution pattern involved:

winword.exe
    |
    v
powershell.exe
    |
    +-- encoded command
    |
    +-- hidden execution
    |
    +-- outbound HTTPS activity
    |
    +-- child cmd.exe

The available telemetry supports a suspicious endpoint execution pattern.

It does not independently establish malicious intent or compromise.

## 6. Alert 1 — EVT-003006

The first alert referenced:

Event: EVT-003006
Process ID: 4632
Process: powershell.exe
Parent: winword.exe
Encoded command: present
Risk score: 100
Severity: High
Confidence: High

The command line contained:

powershell.exe -NoProfile -EncodedCommand SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA==

The alert indicators were:

encoded_command
suspicious_parent

No network or child-process correlation was associated with this process ID in the available detection output.

## 7. Alert 2 — EVT-003007

The second alert referenced:

Event: EVT-003007
Process ID: 4638
Process: powershell.exe
Parent: winword.exe
Encoded command: present
Hidden window: present
Network event: EVT-003008
Child process event: EVT-003009
Risk score: 100
Severity: High
Confidence: High

The command line contained:

powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand SQBFAFgA

The alert indicators were:

encoded_command
suspicious_parent
hidden_window
correlated_network_activity
correlated_child_process

This was the stronger investigative pivot because several independent telemetry characteristics correlated to the same PowerShell process.

## 8. Process and Network Correlation

The suspicious process was:

powershell.exe PID 4638

The associated network event was:

EVT-003008

Observed network information:

Destination IP: 203.0.113.80
Destination domain: updates.example.test
Destination port: 443
Protocol: HTTPS

The destination belongs to the controlled documentation/test dataset.

Therefore, the network event demonstrates process correlation within the synthetic laboratory environment.

It does not establish communication with real malicious infrastructure or command-and-control.

## 9. Child-Process Correlation

The child process event was:

EVT-003009

Observed relationship:

powershell.exe PID 4638
        |
        v
cmd.exe PID 4671

The child process command was:

cmd.exe /c whoami

This establishes an observed parent-child process relationship in the synthetic endpoint telemetry.

It does not independently establish malicious execution.

## 10. SOC Investigation

The SOC investigation established:

Two high-severity, high-confidence alerts were generated.
Both alerts involved encoded PowerShell launched by winword.exe.
The second alert included hidden execution.
PowerShell PID 4638 correlated with outbound HTTPS activity.
PowerShell PID 4638 spawned cmd.exe.
The destination was a documentation/test address.
The activity occurred in synthetic laboratory telemetry.

The investigation therefore confirmed a suspicious execution pattern within the laboratory dataset.

## 11. Negative Evidence and Benign Baseline

The dataset intentionally contains legitimate PowerShell activity.

Examples include:

EVT-003001
EVT-003002
EVT-003004
EVT-003005
EVT-003010

These represent routine administrative PowerShell behavior.

The SOC detection testing demonstrated that the legitimate subset generated zero alerts.

This is important because PowerShell itself is not a malicious indicator.

Detection quality depends on contextual correlation rather than simply matching every PowerShell process.

## 12. Investigation Determination
Confirmed

The following are supported by the available evidence:

suspicious PowerShell execution;
encoded-command indicators;
suspicious Office-to-PowerShell process lineage;
hidden PowerShell execution for EVT-003007;
correlated network activity;
correlated child-process activity.
Not Confirmed

The evidence does not establish:

confirmed malware execution;
confirmed compromise;
persistence;
credential theft;
privilege escalation;
data exfiltration;
real-world command-and-control;
attacker attribution;
malicious intent.

These conclusions would require additional telemetry and validation.

## 13. SOC Playbook Relationship

The operational workflow is:

DET-ENDPOINT-001
        |
        v
CASE-003
        |
        v
PB-003

PB-003 — Suspicious PowerShell Execution provides the SOC investigation workflow.

The playbook covers:

alert validation;
evidence preservation;
process lineage analysis;
command-line review;
encoded-command investigation;
network correlation;
child-process analysis;
related authentication and endpoint pivots;
threat and response assessment;
detection-engineering feedback.

This establishes the operational layer for the case.

## 14. Detection Coverage Gap

The cross-project comparison identifies the following gap:

SOC Operations Laboratory
        |
        +-- DET-ENDPOINT-001
        +-- CASE-003
        +-- PB-003
        |
        v
Suspicious PowerShell coverage exists


SIEM Detection Lab
        |
        +-- RULE-001
        +-- RULE-002
        +-- RULE-003
        |
        v
Authentication coverage exists
        |
        v
No equivalent PowerShell rule

This is a real engineering distinction.

The SIEM Detection Lab should not claim endpoint/PowerShell detection coverage that has not been implemented and tested in that repository.

## 15. Detection Engineering Feedback

The SOC investigation identifies several requirements that could inform future SIEM endpoint detection engineering:

encoded PowerShell command detection;
suspicious Office parent-process correlation;
hidden PowerShell execution;
PowerShell-to-network correlation;
PowerShell-to-child-process correlation;
process lineage preservation;
benign administrative PowerShell baselines;
Windows Event Log correlation;
PowerShell script-block telemetry;
EDR process lineage;
DNS telemetry;
file and document metadata;
negative testing for legitimate Office automation.

These are candidate engineering improvements, not current SIEM capabilities.

No new SIEM rule is claimed by this case study.

## 16. Testing and Validation Evidence

The SOC CASE-003 investigation includes negative testing using legitimate PowerShell activity.

The test objective was to demonstrate that routine PowerShell usage does not automatically trigger the suspicious execution detection.

The case also distinguishes between:

Observed Evidence
        |
        v
Analyst Interpretation
        |
        v
Hypothesis
        |
        v
Confirmed Finding
        |
        v
Recommended Action

This evidence model prevents synthetic laboratory results from being overstated as production incidents.

The SIEM Detection Lab's existing test suite validates its current authentication rules, but those tests do not constitute PowerShell detection tests.

## 17. Lessons Learned
Context Matters

PowerShell is a legitimate Windows administration and automation technology.

A useful detection should therefore evaluate contextual indicators rather than treating every PowerShell process as malicious.

Correlation Improves Triage

The second CASE-003 alert was more significant because encoded execution, Office parentage, hidden execution, network activity, and child-process activity correlated to the same process.

Negative Testing Matters

Benign PowerShell activity provides an important baseline for testing false-positive behavior.

Evidence Boundaries Matter

A suspicious execution pattern can be confirmed in laboratory telemetry without claiming confirmed compromise.

Integration Must Be Evidence-Based

A SOC detection and a SIEM rule should not be described as directly integrated unless corresponding implementation evidence exists in both projects.

## 18. Cross-Project Value

CASE-003 demonstrates a different type of integration value from CASE-001 and CASE-002.

CASE-001 demonstrated direct brute-force traceability:

RULE-001
   |
   v
DET-AUTH-001
   |
   v
CASE-001
   |
   v
PB-001

CASE-002 demonstrated related authentication coverage:

RULE-003
   |
   v
Related password-spray coverage
   |
   v
CASE-002 / PB-002

CASE-003 demonstrates a detection-coverage boundary:

SOC endpoint detection
        |
        v
CASE-003
        |
        v
SIEM endpoint coverage gap

This demonstrates that cross-project engineering is not simply about creating one-to-one mappings. It also involves identifying where detection capabilities exist, where they do not, and what evidence would be required to close the gap.

## 19. Evidence References

Primary SOC evidence:

../cybernova-soc-operations-lab/cases/CASE-003/alert.json
../cybernova-soc-operations-lab/cases/CASE-003/README.md
../cybernova-soc-operations-lab/cases/CASE-003/investigation.md
../cybernova-soc-operations-lab/cases/CASE-003/timeline.md
../cybernova-soc-operations-lab/cases/CASE-003/final-report.md
../cybernova-soc-operations-lab/cases/CASE-003/lessons-learned.md
../cybernova-soc-operations-lab/playbooks/PB-003-suspicious-powershell.md

Current SIEM detection inventory:

rules/brute_force.yaml
rules/success_after_failures.yaml
rules/distributed_password_spray.yaml

Current SIEM integration documentation:

docs/soc_integration.md

This case study does not claim that any of the authentication rules generated DET-ENDPOINT-001.

## 20. Professional Portfolio Positioning

CASE-003 demonstrates hands-on experience with:

endpoint detection analysis;
PowerShell investigation;
Windows process lineage;
encoded-command analysis;
parent-child process correlation;
network correlation;
negative testing;
evidence preservation;
SOC triage;
detection-coverage analysis;
cross-project security engineering;
evidence-based technical documentation.

The appropriate portfolio representation is:

Hands-on SOC Laboratory Experience — Suspicious PowerShell Investigation and Detection Coverage Analysis

It should not be represented as production SOC employment or as a real-world compromise investigation.

## 21. Final Case Study Conclusion

CASE-003 provides evidence of a high-confidence suspicious PowerShell execution pattern within synthetic Windows endpoint telemetry.

The SOC Operations Laboratory successfully documents the detection, investigation, process lineage, network correlation, child-process correlation, evidence boundaries, and response considerations.

The SIEM Detection Lab currently does not implement an equivalent PowerShell detection rule.

That gap is intentionally preserved in this case study rather than being represented as an unsupported integration.

The resulting cross-project evidence demonstrates an important SOC engineering principle:

Detect
  ↓
Investigate
  ↓
Preserve Evidence
  ↓
Assess Coverage
  ↓
Identify Gaps
  ↓
Feed Findings Back Into Detection Engineering

CASE-003 is therefore valuable not only as an endpoint investigation but also as evidence of disciplined detection-engineering coverage analysis.
