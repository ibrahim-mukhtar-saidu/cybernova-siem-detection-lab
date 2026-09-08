"""Risk scoring based on generated alert severities."""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

SEVERITY_SCORES: dict[str, int] = {
    "CRITICAL": 100,
    "HIGH": 80,
    "MEDIUM": 50,
    "LOW": 20,
}

DEFAULT_RISK_LEVELS: dict[str, int] = {
    "LOW": 20,
    "MEDIUM": 50,
    "HIGH": 80,
    "CRITICAL": 100,
}


def _risk_level(score: int, levels: dict[str, int]) -> str:
    """Map a cumulative risk score to a configured risk level."""
    if score >= levels.get("CRITICAL", DEFAULT_RISK_LEVELS["CRITICAL"]):
        return "CRITICAL"

    if score >= levels.get("HIGH", DEFAULT_RISK_LEVELS["HIGH"]):
        return "HIGH"

    if score >= levels.get("MEDIUM", DEFAULT_RISK_LEVELS["MEDIUM"]):
        return "MEDIUM"

    return "LOW"


def calculate_risk(
    alerts: list[dict[str, Any]],
    risk_levels: dict[str, int] | None = None,
) -> dict[str, Any]:
    """Calculate cumulative risk from alert severities."""
    levels = risk_levels or DEFAULT_RISK_LEVELS
    score = 0

    for alert in alerts:
        severity = alert.get("details", {}).get("severity", "LOW")

        if severity not in SEVERITY_SCORES:
            logger.warning(
                "unrecognized alert severity %r, treating as LOW",
                severity,
            )
            severity = "LOW"

        score += SEVERITY_SCORES[severity]

    return {
        "risk_score": score,
        "risk_level": _risk_level(score, levels),
    }
