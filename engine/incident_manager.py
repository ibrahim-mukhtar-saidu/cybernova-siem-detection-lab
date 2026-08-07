import os
import json
from datetime import datetime


INCIDENT_DIR = "incidents"


os.makedirs(INCIDENT_DIR, exist_ok=True)


def create_incident(alerts):

    incidents = []

    for index, alert in enumerate(alerts, start=1):

        incident = {
            "incident_id": f"INC-{index:03}",
            "created": str(datetime.now()),
            "status": "OPEN",
            "alert": alert
        }

        incidents.append(incident)


        with open(
            f"{INCIDENT_DIR}/incident_{index:03}.json",
            "w"
        ) as file:
            json.dump(
                incident,
                file,
                indent=4
            )

    return incidents
