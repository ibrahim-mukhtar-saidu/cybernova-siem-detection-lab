from datetime import datetime


def create_alert(alert):
    return {
        "alert_id": f"ALERT-{datetime.now().strftime('%Y%m%d%H%M%S')}",
        "created": str(datetime.now()),
        "details": alert
    }


def process_alerts(alerts):

    processed = []

    for alert in alerts:
        processed.append(create_alert(alert))

    return processed
