"""Incident record creation and persistence.

Incident numbers are drawn from a sequence file stored alongside the
incident records themselves, so re-running the pipeline appends new
incidents instead of overwriting or orphaning files from a previous run.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

DEFAULT_INCIDENT_DIR = Path("incidents")
SEQUENCE_FILENAME = ".sequence"


def _next_sequence_numbers(incident_dir: Path, count: int) -> range:
    if count == 0:
        return range(0)

    incident_dir.mkdir(parents=True, exist_ok=True)
    sequence_file = incident_dir / SEQUENCE_FILENAME

    last = 0
    if sequence_file.exists():
        try:
            last = int(sequence_file.read_text(encoding="utf-8").strip())
        except ValueError:
            logger.warning(
                "incident sequence file corrupted, resetting to 0: %s",
                sequence_file,
            )
            last = 0

    next_last = last + count
    sequence_file.write_text(str(next_last), encoding="utf-8")

    return range(last + 1, next_last + 1)


def create_incident(
    alerts: list[dict[str, Any]],
    incident_dir: str | Path = DEFAULT_INCIDENT_DIR,
) -> list[dict[str, Any]]:
    incident_dir = Path(incident_dir)
    incidents: list[dict[str, Any]] = []

    for number, alert in zip(
        _next_sequence_numbers(incident_dir, len(alerts)), alerts
    ):
        incident = {
            "incident_id": f"INC-{number:03}",
            "created": datetime.now(timezone.utc).isoformat(),
            "status": "OPEN",
            "alert": alert,
        }

        incidents.append(incident)

        incident_path = incident_dir / f"incident_{number:03}.json"
        with incident_path.open("w", encoding="utf-8") as handle:
            json.dump(incident, handle, indent=4)

    return incidents
