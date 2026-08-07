#!/usr/bin/env python3

from collections import Counter

from engine.log_parser import parse_authentication_logs
from engine.detection_engine import run_detection
from engine.alert_manager import process_alerts
from engine.incident_manager import create_incident
from engine.report_generator import generate_report

LOG_FILE = "logs/authentication.log"


def main():

    print("=" * 60)
    print("       CyberNova SIEM Detection Lab")
    print("              Version 2.1")
    print("=" * 60)


    # 1. Parse logs
    events = parse_authentication_logs(LOG_FILE)


    # 2. Detect threats
    alerts = run_detection(events)


    # 3. Format alerts
    processed_alerts = process_alerts(alerts)


    # 4. Create incidents
    incidents = create_incident(processed_alerts)


    # 5. Generate report
    report = generate_report(
        events,
        processed_alerts,
        incidents
    )


    # Dashboard

    print("\n")
    print("=" * 60)
    print("             CyberNova SOC Dashboard v2.1")
    print("=" * 60)


    print("\nEvents Analyzed:")
    print(len(events))


    print("\nSecurity Alerts:")

    severity_count = Counter()

    mitre = set()
    ips = []

    for alert in processed_alerts:

        details = alert["details"]

        severity = details.get("severity", "UNKNOWN")
        severity_count[severity] += 1

        if "mitre" in details:
            mitre.add(details["mitre"])

        if "ip" in details:
            ips.append(details["ip"])


    for level, count in severity_count.items():
        print(f"{level}: {count}")


    print("\nRisk Assessment:")

    risk = report["risk_assessment"]

    print(f"Score : {risk['risk_score']}")
    print(f"Level : {risk['risk_level']}")


    print("\nTop Attacking IP:")

    if ips:
        print(Counter(ips).most_common(1)[0][0])
    else:
        print("None")


    print("\nMITRE ATT&CK:")

    for technique in mitre:
        print(f"- {technique}")


    print("\nIncident Status:")

    for incident in incidents:
        print(
            f"{incident['incident_id']}  {incident['status']}"
        )


    print("\nReports:")
    print("✓ reports/final_siem_report.json")


    print("=" * 60)



if __name__ == "__main__":
    main()
