from collections import defaultdict


def detect_bruteforce(events, threshold):
    failed_counts = defaultdict(int)

    for event in events:
        if event["event_type"] == "FAILED_LOGIN":
            failed_counts[event["ip"]] += 1

    alerts = []

    for ip, count in failed_counts.items():
        if count >= threshold:
            alerts.append({
                "type": "BRUTE_FORCE",
                "ip": ip,
                "attempts": count,
                "severity": "HIGH",
                "mitre": "T1110 - Brute Force"
            })

    return alerts


def detect_success_after_failures(events, threshold):
    failed_counts = defaultdict(int)
    alerts = []

    for event in events:
        ip = event["ip"]

        if event["event_type"] == "FAILED_LOGIN":
            failed_counts[ip] += 1

        elif event["event_type"] == "SUCCESSFUL_LOGIN":
            if failed_counts[ip] >= threshold:
                alerts.append({
                    "type": "SUCCESS_AFTER_FAILURES",
                    "ip": ip,
                    "attempts_before_success": failed_counts[ip],
                    "severity": "CRITICAL",
                    "mitre": "T1078 - Valid Accounts"
                })

    return alerts
    
def run_detection(events):

    alerts = []

    alerts.extend(
        detect_bruteforce(events, 5)
    )

    alerts.extend(
        detect_success_after_failures(events, 3)
    )

    return alerts
