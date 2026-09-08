"""Alert normalization and identifier assignment."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any


def create_alert(alert: dict[str, Any]) -> dict[str, Any]:
    return {
        "alert_id": f"ALERT-{uuid.uuid4().hex}",
        "created": datetime.now(timezone.utc).isoformat(),
        "details": alert,
    }


def process_alerts(alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [create_alert(alert) for alert in alerts]
