"""Detection logic for authentication-log based threats.

Rule parameters (threshold, severity, MITRE mapping, time window) are loaded
from rules/*.yaml so tuning a rule does not require a code change.
"""

from __future__ import annotations

from collections import defaultdict, deque
from datetime import timedelta
from typing import Any

from config_loader import load_rule
from engine.log_parser import AuthEvent

BRUTE_FORCE_RULE_FILE = "rules/brute_force.yaml"
SUCCESS_AFTER_FAILURES_RULE_FILE = "rules/success_after_failures.yaml"
DISTRIBUTED_PASSWORD_SPRAY_RULE_FILE = "rules/distributed_password_spray.yaml"

DEFAULT_WINDOW_MINUTES = 10


def detect_bruteforce(
    events: list[AuthEvent], rule: dict[str, Any]
) -> list[dict[str, Any]]:
    threshold = rule["threshold"]
    window = timedelta(minutes=rule.get("window_minutes", DEFAULT_WINDOW_MINUTES))
    severity = rule["severity"]
    mitre = rule["mitre"]

    failure_times: dict[str, deque] = defaultdict(deque)
    alerted_ips: set[str] = set()
    alerts: list[dict[str, Any]] = []

    for event in sorted(events, key=lambda item: item.timestamp):
        if event.event_type != "FAILED_LOGIN":
            continue

        timestamps = failure_times[event.ip]
        timestamps.append(event.timestamp)

        while timestamps and event.timestamp - timestamps[0] > window:
            timestamps.popleft()

        if len(timestamps) >= threshold and event.ip not in alerted_ips:
            alerted_ips.add(event.ip)
            alerts.append(
                {
                    "type": "BRUTE_FORCE",
                    "ip": event.ip,
                    "attempts": len(timestamps),
                    "severity": severity,
                    "mitre": mitre,
                }
            )

    return alerts


def detect_success_after_failures(
    events: list[AuthEvent], rule: dict[str, Any]
) -> list[dict[str, Any]]:
    threshold = rule["threshold"]
    window = timedelta(minutes=rule.get("window_minutes", DEFAULT_WINDOW_MINUTES))
    severity = rule["severity"]
    mitre = rule["mitre"]

    failure_times: dict[str, deque] = defaultdict(deque)
    alerts: list[dict[str, Any]] = []

    for event in sorted(events, key=lambda item: item.timestamp):
        timestamps = failure_times[event.ip]

        while timestamps and event.timestamp - timestamps[0] > window:
            timestamps.popleft()

        if event.event_type == "FAILED_LOGIN":
            timestamps.append(event.timestamp)
        elif event.event_type == "SUCCESSFUL_LOGIN":
            if len(timestamps) >= threshold:
                alerts.append(
                    {
                        "type": "SUCCESS_AFTER_FAILURES",
                        "ip": event.ip,
                        "attempts_before_success": len(timestamps),
                        "severity": severity,
                        "mitre": mitre,
                    }
                )
            # A successful login clears the IP's failure history: it is the
            # boundary of the "attempts before success" window described by
            # this rule, not a running total across unrelated sessions.
            timestamps.clear()

    return alerts


def detect_distributed_password_spraying(
    events: list[AuthEvent], rule: dict[str, Any]
) -> list[dict[str, Any]]:
    """Detect repeated failed logins against one user from multiple IPs."""
    threshold = rule["threshold"]
    window = timedelta(minutes=rule.get("window_minutes", DEFAULT_WINDOW_MINUTES))
    severity = rule["severity"]
    mitre = rule["mitre"]

    failure_events: dict[str, deque] = defaultdict(deque)
    alerted_users: set[str] = set()
    alerts: list[dict[str, Any]] = []

    for event in sorted(events, key=lambda item: item.timestamp):
        if event.event_type != "FAILED_LOGIN":
            continue

        failures = failure_events[event.user]
        failures.append(event)

        while failures and event.timestamp - failures[0].timestamp > window:
            failures.popleft()

        source_ips = {failure.ip for failure in failures}

        if (
            len(failures) >= threshold
            and len(source_ips) >= 2
            and event.user not in alerted_users
        ):
            alerted_users.add(event.user)
            alerts.append(
                {
                    "type": "DISTRIBUTED_PASSWORD_SPRAY",
                    "user": event.user,
                    "attempts": len(failures),
                    "source_ips": len(source_ips),
                    "severity": severity,
                    "mitre": mitre,
                }
            )

    return alerts


def run_detection(events: list[AuthEvent]) -> list[dict[str, Any]]:
    brute_force_rule = load_rule(BRUTE_FORCE_RULE_FILE)
    success_rule = load_rule(SUCCESS_AFTER_FAILURES_RULE_FILE)
    distributed_spray_rule = load_rule(DISTRIBUTED_PASSWORD_SPRAY_RULE_FILE)

    alerts: list[dict[str, Any]] = []
    alerts.extend(detect_bruteforce(events, brute_force_rule))
    alerts.extend(detect_success_after_failures(events, success_rule))
    alerts.extend(
        detect_distributed_password_spraying(events, distributed_spray_rule)
    )

    return alerts
