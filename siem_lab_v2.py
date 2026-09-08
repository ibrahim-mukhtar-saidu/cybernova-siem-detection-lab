#!/usr/bin/env python3

"""Entry point for the CyberNova SIEM detection pipeline."""

from __future__ import annotations

import logging
import sys
from collections import Counter

from config_loader import ConfigError, load_config
from engine.alert_manager import process_alerts
from engine.detection_engine import run_detection
from engine.incident_manager import create_incident
from engine.log_parser import parse_authentication_logs
from engine.logging_config import configure_logging
from engine.report_generator import generate_report

LOG_FILE = "logs/authentication.log"

logger = logging.getLogger(__name__)


def main() -> int:
    """Run the SIEM detection pipeline and print a terminal summary."""
    configure_logging()

    print("=" * 60)
    print("       CyberNova SIEM Detection Lab")
    print("              Version 2.1")
    print("=" * 60)

    try:
        events = parse_authentication_logs(LOG_FILE)
    except (
        FileNotFoundError,
        IsADirectoryError,
        PermissionError,
        ValueError,
    ) as exc:
        logger.error("failed to read authentication log: %s", exc)
        print(f"\nError: {exc}")
        return 1

    logger.info("parsed %d authentication events", len(events))

    try:
        alerts = run_detection(events)
    except ConfigError as exc:
        logger.error("failed to load detection rules: %s", exc)
        print(f"\nError: {exc}")
        return 1

    if alerts:
        logger.warning(
            "detection engine generated %d alert(s)",
            len(alerts),
        )

    processed_alerts = process_alerts(alerts)
    incidents = create_incident(processed_alerts)

    if incidents:
        logger.critical(
            "created %d security incident(s)",
            len(incidents),
        )

    try:
        config = load_config()
        risk_levels = config.get("risk", {}).get("levels")
    except ConfigError as exc:
        logger.warning(
            "could not load siem_config.yaml, using default risk levels: %s",
            exc,
        )
        risk_levels = None

    report = generate_report(
        events,
        processed_alerts,
        incidents,
        risk_levels,
    )

    print("\n")
    print("=" * 60)
    print("             CyberNova SOC Dashboard v2.1")
    print("=" * 60)

    print("\nEvents Analyzed:")
    print(len(events))

    print("\nSecurity Alerts:")

    severity_count: Counter[str] = Counter()
    mitre: set[str] = set()
    ips: list[str] = []

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

    for technique in sorted(mitre):
        print(f"- {technique}")

    print("\nIncident Status:")

    for incident in incidents:
        print(f"{incident['incident_id']}  {incident['status']}")

    print("\nReports:")
    print("- reports/final_siem_report.json")

    print("=" * 60)

    return 0


if __name__ == "__main__":
    sys.exit(main())
