"""Final SIEM report assembly and persistence."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from engine.risk_engine import calculate_risk

DEFAULT_REPORT_DIR = Path("reports")
REPORT_FILENAME = "final_siem_report.json"


def generate_report(
    events: list[Any],
    alerts: list[dict[str, Any]],
    incidents: list[dict[str, Any]],
    risk_levels: dict[str, int] | None = None,
    report_dir: str | Path = DEFAULT_REPORT_DIR,
) -> dict[str, Any]:
    risk = calculate_risk(alerts, risk_levels)

    report = {
        "tool": "CyberNova SIEM Detection Lab",
        "version": "2.1",
        "generated": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "events_processed": len(events),
            "alerts_generated": len(alerts),
            "incidents_created": len(incidents),
        },
        "risk_assessment": risk,
        "alerts": alerts,
        "incidents": incidents,
    }

    report_dir = Path(report_dir)
    report_dir.mkdir(parents=True, exist_ok=True)

    report_path = report_dir / REPORT_FILENAME
    with report_path.open("w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=4)

    return report
