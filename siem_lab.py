#!/usr/bin/env python3

from datetime import datetime
from collections import defaultdict
import json
import os

LOG_FILE = "logs/authentication.log"
REPORT_DIR = "reports"
INCIDENT_DIR = "incidents"

os.makedirs(REPORT_DIR, exist_ok=True)
os.makedirs(INCIDENT_DIR, exist_ok=True)


def parse_logs():
    events = []

    with open(LOG_FILE, "r") as f:
        for line in f:
            line = line.strip()

            if not line:
                continue

            parts = line.split()

            timestamp = f"{parts[0]} {parts[1]}"
            event_type = parts[2]
            user = parts[3].split("=")[1]
            ip = parts[4].split("=")[1]

            events.append({
                "timestamp": timestamp,
                "event_type": event_type,
                "user": user,
                "ip": ip
            })

    return events


def detect_bruteforce(events):
    failed_counts = defaultdict(int)

    for event in events:
        if event["event_type"] == "FAILED_LOGIN":
            failed_counts[event["ip"]] += 1

    alerts = []

    for ip, count in failed_counts.items():
        if count >= 5:
            alerts.append({
                "type": "BRUTE_FORCE",
                "ip": ip,
                "attempts": count,
                "severity": "HIGH",
                "mitre": "T1110 - Brute Force"
            })

    return alerts


def detect_success_after_failures(events):
    failed_counts = defaultdict(int)
    alerts = []

    for event in events:
        ip = event["ip"]

        if event["event_type"] == "FAILED_LOGIN":
            failed_counts[ip] += 1

        elif event["event_type"] == "SUCCESSFUL_LOGIN" and failed_counts[ip] >= 3:
            alerts.append({
                "type": "SUCCESS_AFTER_FAILURES",
                "ip": ip,
                "attempts_before_success": failed_counts[ip],
                "severity": "CRITICAL",
                "mitre": "T1078 - Valid Accounts"
            })

    return alerts


def generate_incidents(alerts):
    incidents = []

    for i, alert in enumerate(alerts, start=1):
        incident = {
            "incident_id": f"INC-{i:03}",
            "created": str(datetime.now()),
            "alert": alert
        }

        incidents.append(incident)

        with open(f"{INCIDENT_DIR}/incident_{i:03}.json", "w") as f:
            json.dump(incident, f, indent=4)

    return incidents


def save_reports(events, alerts, incidents):
    report = {
        "tool": "CyberNova SIEM Detection Lab",
        "version": "1.0",
        "generated": str(datetime.now()),
        "events_processed": len(events),
        "alerts_generated": len(alerts),
        "incidents_created": len(incidents),
        "alerts": alerts
    }

    with open(f"{REPORT_DIR}/siem_report.json", "w") as f:
        json.dump(report, f, indent=4)

    with open(f"{REPORT_DIR}/siem_report.txt", "w") as f:
        f.write("CyberNova SIEM Detection Lab Report\\n")
        f.write("================================\\n\\n")
        f.write(f"Events Processed: {len(events)}\\n")
        f.write(f"Alerts Generated: {len(alerts)}\\n")
        f.write(f"Incidents Created: {len(incidents)}\\n\\n")

        for alert in alerts:
            f.write(f"[{alert['severity']}] {alert['type']}\\n")
            f.write(f"IP: {alert['ip']}\\n")
            f.write(f"MITRE: {alert['mitre']}\\n\\n")


def main():
    print("=" * 60)
    print("        CyberNova SIEM Detection Lab")
    print("             Version 1.0")
    print("=" * 60)

    events = parse_logs()

    alerts = []
    alerts.extend(detect_bruteforce(events))
    alerts.extend(detect_success_after_failures(events))

    incidents = generate_incidents(alerts)

    save_reports(events, alerts, incidents)

    print("\\nSOC Dashboard")
    print("-" * 30)
    print(f"Events Processed: {len(events)}")
    print(f"Alerts Generated: {len(alerts)}")
    print(f"Incidents Created: {len(incidents)}")

    print("\\nMITRE ATT&CK Techniques")
    print("-" * 30)
    techniques = sorted({alert["mitre"] for alert in alerts})
    for t in techniques:
        print(t)

    print("\\nReports Generated:")
    print("JSON: reports/siem_report.json")
    print("TXT : reports/siem_report.txt")


if __name__ == "__main__":
    main()
