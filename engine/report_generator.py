import json
import os
from datetime import datetime

from engine.risk_engine import calculate_risk


REPORT_DIR = "reports"

os.makedirs(REPORT_DIR, exist_ok=True)


def generate_report(events, alerts, incidents):

    risk = calculate_risk(alerts)

    report = {
        "tool": "CyberNova SIEM Detection Lab",
        "version": "2.0",
        "generated": str(datetime.now()),

        "summary": {
            "events_processed": len(events),
            "alerts_generated": len(alerts),
            "incidents_created": len(incidents)
        },

        "risk_assessment": risk,

        "alerts": alerts,

        "incidents": incidents
    }


    with open(
        f"{REPORT_DIR}/final_siem_report.json",
        "w"
    ) as file:
        json.dump(
            report,
            file,
            indent=4
        )


    return report
