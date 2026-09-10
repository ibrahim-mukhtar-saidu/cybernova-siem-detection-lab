# CASE-005 — Suspicious C2 Beaconing

## 1. Case Overview

`CASE-005` documents the cross-project investigation of suspicious outbound network activity identified by the CYBERNOVA SOC Operations Laboratory.

The SOC-side detection was:

- Detection ID: `DET-NET-001`
- Detection Name: `Suspicious C2 Beaconing Activity`
- Detection Version: `1.0`
- SOC Case: `CASE-005`
- SOC Playbook: `PB-005 — Suspicious Network Activity`

The case demonstrates how a network detection can identify repeated and highly regular outbound communication and how an analyst should investigate that behavior without automatically treating periodic communication as confirmed command-and-control activity.

This case study also records the current detection-coverage relationship between the SOC Operations Laboratory and the CYBERNOVA SIEM Detection Laboratory.

The SIEM Detection Laboratory currently contains no equivalent network-beaconing detection rule or implementation. Therefore, this case represents a **full network-detection coverage gap**, not an equivalent or partial SIEM implementation.

---

## 2. Environment

The investigation was performed using synthetic telemetry within an authorized cybersecurity laboratory environment.

No production systems, real-world incidents, real victims, or real-world attacker infrastructure are claimed.

The case is intended to demonstrate:

- network detection engineering;
- SOC alert validation;
- evidence preservation;
- behavioral analysis;
- process/network correlation;
- threat hunting;
- threat-intelligence assessment;
- response planning;
- detection-coverage analysis;
- evidence-based documentation.

---

## 3. Cross-Project Detection Chain

The authoritative SOC-side relationship is:

```text
Synthetic Network Telemetry
          |
          v
DET-NET-001
Suspicious C2 Beaconing Activity
          |
          v
CASE-005
Suspicious C2 Beaconing Investigation
          |
          v
PB-005
Suspicious Network Activity

The corresponding SIEM relationship is:

SOC Detection
DET-NET-001
          |
          v
CASE-005
          |
          v
SIEM Detection Laboratory
          |
          v
No Equivalent Network/Beaconing Rule
          |
          v
Full Detection Coverage Gap

This relationship is intentionally documented as a coverage gap.

No SIEM rule is being invented or implied where no implementation exists.

4. Detection Definition

DET-NET-001 identifies repeated outbound network connections exhibiting regular timing characteristics.

The current laboratory detection contract specifies:

Parameter	Value
Minimum connections	5
Detection window	10 minutes
Expected interval	60 seconds
Interval tolerance	10 seconds
Minimum regularity ratio	0.75
Minimum risk score	70

The detection evaluates chronological network connection events.

A candidate window must contain at least five connections.

The detector calculates intervals between consecutive connections and evaluates their regularity.

A candidate is rejected when the regularity ratio is below 0.75.

Additional behavioral indicators can increase the risk score, which is capped at 100.

The risk score is a prioritization signal and is not proof of malicious activity.

5. CASE-005 Alert

The laboratory CASE-005 alert contained the following observed values:

Field	Observed Value
Detection ID	DET-NET-001
Alert ID	ALERT-CASE-005-DET-NET-001
Detection Name	Suspicious C2 Beaconing Activity
Detection Version	1.0
Host	lab-ws-01
Source IP	192.0.2.50
Process	svchost_update.exe
Process Path	C:\Users\Public\svchost_update.exe
Destination IP	198.51.100.77
Destination Port	8443
Destination Domain	cdn-update.example
Connections	7
First Connection	2026-09-08T11:10:10Z
Last Connection	2026-09-08T11:16:10Z
Average Interval	60 seconds
Regularity Ratio	1.0
Risk Score	100
Severity	High
Confidence	High
Correlation Event	EVT-005013

The alert contained indicators including:

repeated connections;
regular beacon interval;
non-standard destination port;
user-writable process path;
suspicious process name;
process/network correlation.
6. Detection Validation

The CASE-005 activity satisfies the current DET-NET-001 detection contract.

The observed connection count was seven, exceeding the minimum of five.

The activity occurred over six minutes from the first to last connection, remaining inside the ten-minute detection window.

The average interval was approximately sixty seconds.

The observed regularity ratio was 1.0, exceeding the minimum required value of 0.75.

The risk score was 100, exceeding the minimum alert threshold of 70.

The alert was therefore internally consistent with the current laboratory detection definition.

The presence of a valid alert establishes that the defined detection conditions were satisfied. It does not independently establish compromise or malicious ownership of the destination.

7. Network Behavior

The central behavioral characteristic was repeated outbound communication from the same process toward the same destination.

Observed characteristics included:

repeated outbound connections;
approximately sixty-second intervals;
regularity ratio of 1.0;
destination port 8443;
process/network correlation;
a process executing from a user-writable path;
a suspicious process name.

The combination of these characteristics makes the activity highly suspicious within the laboratory scenario.

The strongest detection value is behavioral rather than attribution-based.

The observed periodicity provides a useful pivot for further investigation and hunting.

8. Evidence Classification
8.1 Observed Evidence

The following are directly supported by the CASE-005 laboratory evidence:

seven outbound network connections;
source host lab-ws-01;
source IP 192.0.2.50;
process svchost_update.exe;
process path C:\Users\Public\svchost_update.exe;
destination IP 198.51.100.77;
destination port 8443;
destination domain cdn-update.example;
approximately sixty-second connection intervals;
regularity ratio 1.0;
risk score 100;
high severity;
high confidence;
process/network correlation;
supporting event identifiers;
correlation event EVT-005013.
8.2 Analyst Interpretation

The observed behavior is consistent with automated periodic network communication and is suspicious enough to justify investigation.

The combined process and network characteristics are also consistent with a potential C2 beaconing pattern.

However, this is analyst interpretation rather than directly observed proof of malicious activity.

8.3 Not Established

The available evidence does not independently establish:

successful host compromise;
attacker identity;
malicious ownership of the destination;
malware identity;
successful command execution;
persistence;
lateral movement;
privilege escalation;
data access;
data exfiltration;
real-world campaign attribution;
production impact.
9. Why the Activity Is Suspicious

Several independent characteristics increase investigative priority.

9.1 Regular Timing

Seven connections occurring at approximately sixty-second intervals produce a regularity ratio of 1.0.

Highly regular periodic communication can be characteristic of automated software behavior.

It is not, by itself, proof of C2.

9.2 Suspicious Process Name

The process was named:

svchost_update.exe

The name resembles a legitimate Windows service-process naming convention while also containing an update-related term.

A suspicious filename alone does not establish maliciousness.

Its significance increases when correlated with the network behavior.

9.3 User-Writable Process Path

The process executed from:

C:\Users\Public\svchost_update.exe

Execution from a user-writable location can increase suspicion because such locations may be accessible to software that does not require privileged installation paths.

Again, this is a risk indicator rather than proof of malware.

9.4 Non-Standard Destination Port

The destination port was:

8443

The use of a non-standard HTTPS-like port warrants investigation but does not inherently indicate malicious traffic.

9.5 Process/Network Correlation

The strongest combined signal is the correlation between the suspicious process characteristics and repeated outbound communication.

This creates a more useful investigation pivot than any single indicator considered independently.

10. Investigation Objective

The analyst objective is:

Determine what network behavior occurred, which process generated it, where it communicated, how regularly it communicated, and whether additional evidence supports or contradicts a malicious explanation.

The investigation should begin from observed evidence rather than assuming that the destination is C2 infrastructure.

11. Timeline

The documented CASE-005 activity begins at:

2026-09-08T11:10:10Z

and ends at:

2026-09-08T11:16:10Z

The observed communication pattern is approximately:

Connection 1
11:10:10Z
    |
    | ~60 seconds
    v
Connection 2
    |
    | ~60 seconds
    v
Connection 3
    |
    | ~60 seconds
    v
Connection 4
    |
    | ~60 seconds
    v
Connection 5
    |
    | ~60 seconds
    v
Connection 6
    |
    | ~60 seconds
    v
Connection 7
11:16:10Z

The regularity ratio was 1.0.

The available case evidence also identifies correlation event EVT-005013.

12. Indicators
Network Indicators
Type	Value
Source IP	192.0.2.50
Destination IP	198.51.100.77
Destination Port	8443
Destination Domain	cdn-update.example
Endpoint Indicators
Type	Value
Host	lab-ws-01
Process	svchost_update.exe
Process Path	C:\Users\Public\svchost_update.exe
Behavioral Indicators
repeated outbound connections;
approximately 60-second interval;
regularity ratio 1.0;
process/network correlation;
user-writable execution path;
suspicious process naming.
13. Threat Intelligence Assessment

The destination IP uses the documentation/test address:

198.51.100.77

The source and destination values in this laboratory scenario must therefore be treated as synthetic documentation-space indicators rather than evidence of a real malicious infrastructure attribution.

The domain:

cdn-update.example

is also presented as laboratory/example data.

Consequently, the primary intelligence value of CASE-005 is behavioral.

The investigation demonstrates how an analyst can pivot on:

destination IP;
destination port;
destination domain;
process name;
process path;
connection frequency;
regularity;
host;
process/network correlation.

No real-world threat actor or campaign attribution is claimed.

14. Threat Hunting

The CASE-005 behavioral pattern provides several useful hunting hypotheses.

Hypothesis 1 — Repeated Destination Communication

Search for other hosts communicating repeatedly with:

198.51.100.77

The objective is to determine whether the activity is isolated or distributed across multiple systems.

Hypothesis 2 — Process Reuse

Search for:

svchost_update.exe

across available endpoint telemetry.

The objective is to determine whether the process appears on other hosts.

Hypothesis 3 — Similar Beacon Timing

Search for outbound connections exhibiting approximately sixty-second intervals.

The objective is to identify similar automated communication patterns even when process or destination indicators differ.

Hypothesis 4 — User-Writable Execution

Search for network-connected processes executing from user-writable locations.

The objective is to identify other process/network combinations with similar risk characteristics.

Hypothesis 5 — Destination-Port Correlation

Search for suspicious outbound communication using destination port 8443.

The objective is to identify related network activity without assuming that the port itself is malicious.

Hunting results must remain separated from confirmed case evidence unless independently supported by telemetry.

15. False-Positive Considerations

Periodic communication can occur legitimately.

Potential explanations include:

software update services;
health checks;
monitoring agents;
endpoint-management software;
cloud agents;
scheduled tasks;
synchronization services;
backup applications;
telemetry systems;
legitimate polling applications.

An analyst should therefore validate:

whether the process is authorized;
whether the software is expected on the host;
whether the process path is legitimate;
whether the destination is expected;
whether the communication is documented;
whether the process has a legitimate publisher or signature;
whether the user or administrator recognizes the activity;
whether additional endpoint evidence supports malicious execution.

The detection should prioritize suspicious behavior without treating periodicity as an automatic malicious classification.

16. Response Considerations

The appropriate response depends on additional evidence.

Immediate Investigative Priorities
preserve the original alert;
preserve supporting network events;
preserve process/network correlation evidence;
validate the affected host;
identify the process owner;
establish whether the process is authorized;
inspect endpoint execution evidence;
review persistence locations;
review outbound connections;
determine whether additional hosts show the same behavior.
Potential Containment

If independent evidence establishes unauthorized malicious activity, containment may include:

isolating the affected host;
blocking confirmed malicious infrastructure;
terminating confirmed malicious execution;
disabling confirmed malicious persistence;
protecting affected accounts where applicable.

These actions are response considerations, not actions claimed to have been performed in the laboratory.

No production containment, eradication, or recovery action is claimed.

17. Detection Engineering Feedback

CASE-005 provides direct feedback for future detection engineering.

Current Strengths

DET-NET-001 already combines multiple useful behavioral characteristics:

connection frequency;
timing regularity;
destination port;
process characteristics;
execution path;
process/network correlation;
risk scoring.

This produces a high-priority alert when several suspicious characteristics occur together.

Future Improvements

Potential future improvements include:

process signing information;
executable hash correlation;
parent-process information;
process creation telemetry;
DNS resolution history;
destination reputation;
TLS metadata where available;
user context;
host prevalence;
destination prevalence;
persistence telemetry;
cross-host correlation;
configurable beacon intervals;
additional protocol awareness;
suppression for known-good applications.

These are improvement opportunities rather than claims that the current laboratory detector already implements them.

18. SIEM Detection Coverage Assessment

The CYBERNOVA SIEM Detection Laboratory was inspected for equivalent network-beaconing coverage.

The current SIEM rule inventory contains authentication-focused detections, including:

RULE-001 — Brute Force Detection;
RULE-002 — Successful Login After Multiple Failures;
RULE-003 — Distributed Password Spray Detection.

The inspection found no equivalent implementation for:

DET-NET-001;
network beaconing;
repeated outbound connection detection;
interval regularity analysis;
beacon regularity scoring;
process/network beacon correlation.

Existing references to network activity in SIEM documentation do not constitute an implemented network detection rule.

Therefore:

CASE-005 represents a full SIEM network-detection coverage gap.

No existing SIEM rule should be labeled equivalent to DET-NET-001.

19. Cross-Project Relationship

The current evidence-backed relationship is:

CYBERNOVA SOC Operations Laboratory
-----------------------------------

DET-NET-001
Suspicious C2 Beaconing Activity
        |
        v
CASE-005
        |
        v
PB-005
Suspicious Network Activity


CYBERNOVA SIEM Detection Laboratory
-----------------------------------

No equivalent network detection
        |
        v
FULL COVERAGE GAP

This distinction is important because the SOC Operations Laboratory demonstrates the operational investigation workflow while the SIEM Detection Laboratory currently provides no implementation for this network detection.

The absence of an equivalent rule is itself useful engineering evidence.

20. Detection Coverage Gap Significance

The gap means that the SIEM Detection Laboratory cannot currently reproduce the full DET-NET-001 detection contract.

Specifically, the current SIEM does not implement the combination of:

minimum connections
        +
time window
        +
expected interval
        +
interval tolerance
        +
regularity ratio
        +
network risk indicators
        +
process/network correlation
        +
risk-score threshold

Therefore, a CASE-005-style network beaconing scenario cannot currently be detected by the SIEM rule engine as an equivalent detection.

This is documented as a known limitation rather than silently filled with an invented rule.

21. Evidence Integrity

The following distinction must remain explicit.

Observed
seven network connections;
repeated destination;
approximately sixty-second intervals;
regularity ratio 1.0;
suspicious process characteristics;
process/network correlation;
high-confidence alert;
risk score 100.
Interpretation
behavior is consistent with automated beaconing;
activity warrants investigation;
the process/network combination is suspicious.
Hypothesis

An unauthorized process may be communicating periodically with external infrastructure.

Confirmed

The laboratory telemetry confirms the defined suspicious network-behavior pattern.

Not Confirmed

The evidence does not confirm:

compromise;
malware;
attacker identity;
malicious infrastructure ownership;
command execution;
persistence;
lateral movement;
exfiltration;
production impact.
22. Limitations

The CASE-005 scenario is synthetic.

Important limitations include:

limited laboratory telemetry;
no real endpoint compromise;
no real attacker attribution;
no production network;
no independent malware identification;
no confirmed command execution;
no demonstrated persistence;
no demonstrated lateral movement;
no demonstrated data exfiltration.

The detector may also miss or deprioritize activity when:

fewer than five connections occur;
connections fall outside the configured window;
timing is irregular;
regularity falls below 0.75;
risk score remains below 70;
endpoint/process telemetry is unavailable;
process/network correlation is unavailable;
beacon timing varies significantly.

These limitations define the boundaries of the current laboratory implementation.

23. Validation and Regression Testing Opportunities

Future tests for DET-NET-001 should include:

Positive Tests
five connections at approximately sixty-second intervals;
seven regular connections;
regularity ratio exactly at the minimum threshold;
risk score exactly at the alert threshold;
suspicious process plus regular network behavior;
process/network correlation.
Negative Tests
fewer than five connections;
more than ten-minute detection window;
regularity ratio below 0.75;
risk score below 70;
irregular communication;
legitimate periodic software behavior;
missing process correlation.
Edge Cases
duplicate events;
malformed timestamps;
missing destination fields;
missing process information;
multiple simultaneous beacon candidates;
multiple processes contacting the same destination;
multiple destinations from the same process;
variable beacon intervals.

These tests should be implemented only when the corresponding detection is actually added to the SIEM or detection-engineering test environment.

24. Portfolio Evidence Value

CASE-005 demonstrates several practical SOC and detection-engineering competencies:

validating a network detection;
analyzing behavioral indicators;
calculating and interpreting connection regularity;
correlating process and network telemetry;
preserving evidence boundaries;
developing threat-hunting hypotheses;
considering false-positive explanations;
assessing threat-intelligence value;
planning defensive response;
identifying detection limitations;
providing detection-engineering feedback;
identifying cross-project detection coverage gaps.

The appropriate portfolio framing is:

Hands-on SOC Laboratory Experience — Network Detection and Investigation

and:

Detection Engineering — Suspicious Network Beaconing Analysis

It should not be presented as a real-world incident response engagement.

25. Interview Evidence

CASE-005 can support questions such as:

How did you determine the alert was valid?

The alert satisfied the laboratory detection contract: seven connections exceeded the minimum five, the activity remained within the ten-minute window, the average interval was approximately sixty seconds, the regularity ratio was 1.0, and the risk score was 100.

Does this prove C2?

No.

The observed behavior is consistent with automated beaconing, but periodic communication alone does not establish command-and-control activity or compromise.

What made the activity more suspicious?

The combination of regular outbound communication, a suspicious process name, execution from a user-writable path, a non-standard destination port, and process/network correlation increased the investigative priority.

What would you investigate next?

I would validate whether the process is authorized, examine endpoint execution and persistence telemetry, investigate the destination, search for similar activity across other hosts, and correlate additional network and process evidence.

What did you discover about the SIEM?

The current SIEM Detection Laboratory has no equivalent network-beaconing detection. Therefore, CASE-005 represents a full detection-coverage gap rather than a partially implemented SIEM detection.

Why didn't you add a SIEM rule immediately?

The cross-project case-study phase is documenting evidence-backed relationships first. Inventing a rule solely to make the projects appear integrated would misrepresent the current implementation. A network detector can be designed and tested later as a separate detection-engineering task.

26. Final Determination

CASE-005 successfully demonstrates a high-confidence laboratory detection of suspicious periodic outbound network behavior.

The evidence confirms:

seven repeated outbound connections;
approximately sixty-second intervals;
regularity ratio 1.0;
suspicious process characteristics;
process/network correlation;
risk score 100;
high severity;
high confidence.

The behavior is consistent with automated C2-style beaconing and is sufficient to justify investigation and defensive response planning within the laboratory.

However:

Compromise is not confirmed.

No claim is made regarding real-world malware, attacker identity, malicious infrastructure ownership, command execution, persistence, lateral movement, exfiltration, or production impact.

The cross-project assessment also confirms:

The current CYBERNOVA SIEM Detection Laboratory has no equivalent network-beaconing detection implementation for DET-NET-001. CASE-005 therefore represents a full detection-coverage gap.

This gap is documented intentionally and remains available as a future detection-engineering improvement opportunity.

27. Status

CASE-005 Cross-Project Case Study: COMPLETE

Evidence-Backed Mapping
DET-NET-001
    ↓
CASE-005
    ↓
PB-005
    ↓
Network Detection Investigation
    ↓
SIEM Coverage Assessment
    ↓
Full Detection Coverage Gap
Evidence Boundary
Observed suspicious network behavior
                ≠
Confirmed compromise
Project Boundary
SOC operational detection exists
                ≠
Equivalent SIEM detection exists
