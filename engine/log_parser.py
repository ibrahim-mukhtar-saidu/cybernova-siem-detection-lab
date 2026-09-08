"""Authentication log parsing."""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"
VALID_EVENT_TYPES = {"FAILED_LOGIN", "SUCCESSFUL_LOGIN"}


class LogParseError(ValueError):
    """Raised when a single log line cannot be parsed."""


@dataclass(frozen=True)
class AuthEvent:
    """Normalized authentication event."""

    timestamp: datetime
    event_type: str
    user: str
    ip: str
    line_number: int


def _parse_line(line: str, line_number: int) -> AuthEvent:
    """Parse one whitespace-delimited authentication log line."""
    parts = line.split()

    if len(parts) < 5:
        raise LogParseError(
            f"line {line_number}: expected at least 5 fields, got {len(parts)}"
        )

    timestamp_raw = f"{parts[0]} {parts[1]}"

    try:
        timestamp = datetime.strptime(
            timestamp_raw,
            TIMESTAMP_FORMAT,
        ).replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise LogParseError(
            f"line {line_number}: invalid timestamp {timestamp_raw!r}"
        ) from exc

    event_type = parts[2].strip().upper()

    if event_type not in VALID_EVENT_TYPES:
        raise LogParseError(
            f"line {line_number}: unrecognized event type {parts[2]!r}"
        )

    user_field = parts[3]
    ip_field = parts[4]

    if "=" not in user_field or "=" not in ip_field:
        raise LogParseError(
            f"line {line_number}: malformed user/ip field"
        )

    user = user_field.split("=", 1)[1]
    ip_raw = ip_field.split("=", 1)[1]

    if not user:
        raise LogParseError(
            f"line {line_number}: empty user field"
        )

    try:
        ip = str(ipaddress.ip_address(ip_raw))
    except ValueError as exc:
        raise LogParseError(
            f"line {line_number}: invalid IP address {ip_raw!r}"
        ) from exc

    return AuthEvent(
        timestamp=timestamp,
        event_type=event_type,
        user=user,
        ip=ip,
        line_number=line_number,
    )


def parse_authentication_logs(log_file: str | Path) -> list[AuthEvent]:
    """Parse valid authentication events from a UTF-8 log file.

    Malformed individual lines are skipped and logged. File-level errors
    remain visible to the caller.
    """
    path = Path(log_file)

    if not path.exists():
        raise FileNotFoundError(
            f"authentication log not found: {path}"
        )

    if path.is_dir():
        raise IsADirectoryError(
            f"expected a file, got a directory: {path}"
        )

    events: list[AuthEvent] = []
    skipped = 0

    try:
        with path.open("r", encoding="utf-8") as handle:
            for line_number, raw_line in enumerate(handle, start=1):
                line = raw_line.strip()

                if not line:
                    continue

                try:
                    events.append(_parse_line(line, line_number))
                except LogParseError as exc:
                    skipped += 1
                    logger.warning(
                        "skipping malformed log line: %s",
                        exc,
                    )
    except UnicodeDecodeError as exc:
        raise ValueError(
            f"authentication log is not valid UTF-8: {path}"
        ) from exc
    except PermissionError as exc:
        raise PermissionError(
            f"permission denied reading log file: {path}"
        ) from exc

    if skipped:
        logger.info(
            "parsed %d events, skipped %d malformed line(s) in %s",
            len(events),
            skipped,
            path,
        )
    else:
        logger.info(
            "parsed %d events from %s",
            len(events),
            path,
        )

    return events
