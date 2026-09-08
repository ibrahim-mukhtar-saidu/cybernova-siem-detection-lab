from datetime import datetime, timezone

import pytest

from engine.log_parser import (
    AuthEvent,
    LogParseError,
    _parse_line,
    parse_authentication_logs,
)


def test_parse_line_valid_returns_auth_event():
    event = _parse_line(
        "2026-08-07 19:44:15 FAILED_LOGIN user=admin ip=45.33.32.156",
        1,
    )

    assert event == AuthEvent(
        timestamp=datetime(
            2026,
            8,
            7,
            19,
            44,
            15,
            tzinfo=timezone.utc,
        ),
        event_type="FAILED_LOGIN",
        user="admin",
        ip="45.33.32.156",
        line_number=1,
    )


def test_parse_line_normalizes_event_type():
    event = _parse_line(
        "2026-08-07 19:44:15 failed_login user=admin ip=45.33.32.156",
        1,
    )

    assert event.event_type == "FAILED_LOGIN"


def test_parse_line_supports_successful_login():
    event = _parse_line(
        "2026-08-07 19:44:15 SUCCESSFUL_LOGIN user=admin ip=45.33.32.156",
        2,
    )

    assert event.event_type == "SUCCESSFUL_LOGIN"


@pytest.mark.parametrize(
    "line",
    [
        "",
        "2026-08-07",
        "2026-08-07 19:44:15",
        "2026-08-07 19:44:15 FAILED_LOGIN",
        "2026-08-07 19:44:15 FAILED_LOGIN user=admin",
    ],
)
def test_parse_line_rejects_too_few_fields(line):
    with pytest.raises(LogParseError):
        _parse_line(line, 1)


def test_parse_line_rejects_invalid_timestamp():
    with pytest.raises(LogParseError, match="invalid timestamp"):
        _parse_line(
            "not-a-date 19:44:15 FAILED_LOGIN user=admin ip=1.1.1.1",
            2,
        )


def test_parse_line_rejects_invalid_event_type():
    with pytest.raises(LogParseError, match="unrecognized event type"):
        _parse_line(
            "2026-08-07 19:44:15 LOGIN user=admin ip=1.1.1.1",
            3,
        )


@pytest.mark.parametrize(
    "line",
    [
        "2026-08-07 19:44:15 FAILED_LOGIN admin ip=1.1.1.1",
        "2026-08-07 19:44:15 FAILED_LOGIN user=admin 1.1.1.1",
    ],
)
def test_parse_line_rejects_malformed_user_or_ip_fields(line):
    with pytest.raises(LogParseError, match="malformed user/ip field"):
        _parse_line(line, 4)


def test_parse_line_rejects_empty_user():
    with pytest.raises(LogParseError, match="empty user field"):
        _parse_line(
            "2026-08-07 19:44:15 FAILED_LOGIN user= ip=1.1.1.1",
            5,
        )


@pytest.mark.parametrize(
    "ip",
    [
        "999.999.999.999",
        "not-an-ip",
        "300.1.1.1",
        "1.2.3",
    ],
)
def test_parse_line_rejects_invalid_ip(ip):
    with pytest.raises(LogParseError, match="invalid IP address"):
        _parse_line(
            f"2026-08-07 19:44:15 FAILED_LOGIN user=admin ip={ip}",
            6,
        )


def test_parse_line_accepts_ipv6():
    event = _parse_line(
        "2026-08-07 19:44:15 FAILED_LOGIN user=admin ip=2001:db8::1",
        7,
    )

    assert event.ip == "2001:db8::1"


def test_parse_line_accepts_additional_fields():
    event = _parse_line(
        ("2026-08-07 19:44:15 FAILED_LOGIN user=admin ip=1.1.1.1 extra=value"),
        8,
    )

    assert event.user == "admin"
    assert event.ip == "1.1.1.1"


def test_parse_line_preserves_line_number():
    event = _parse_line(
        "2026-08-07 19:44:15 FAILED_LOGIN user=admin ip=1.1.1.1",
        42,
    )

    assert event.line_number == 42


def test_parse_line_far_future_timestamp_accepted():
    event = _parse_line(
        "2099-12-31 23:59:59 FAILED_LOGIN user=admin ip=1.1.1.1",
        14,
    )

    assert event.timestamp == datetime(
        2099,
        12,
        31,
        23,
        59,
        59,
        tzinfo=timezone.utc,
    )


def test_parse_line_returns_timezone_aware_timestamp():
    event = _parse_line(
        "2026-08-07 19:44:15 FAILED_LOGIN user=admin ip=1.1.1.1",
        15,
    )

    assert event.timestamp.tzinfo == timezone.utc


def test_parse_authentication_logs_reads_valid_file(tmp_path):
    log_file = tmp_path / "authentication.log"
    log_file.write_text(
        (
            "2026-08-07 19:40:01 FAILED_LOGIN "
            "user=admin ip=45.33.32.156\n"
            "2026-08-07 19:41:20 SUCCESSFUL_LOGIN "
            "user=admin ip=45.33.32.156"
        ),
        encoding="utf-8",
    )

    events = parse_authentication_logs(log_file)

    assert len(events) == 2
    assert events[0].event_type == "FAILED_LOGIN"
    assert events[1].event_type == "SUCCESSFUL_LOGIN"


def test_parse_authentication_logs_skips_blank_lines(tmp_path):
    log_file = tmp_path / "authentication.log"
    log_file.write_text(
        ("\n2026-08-07 19:40:01 FAILED_LOGIN user=admin ip=1.1.1.1\n\n"),
        encoding="utf-8",
    )

    events = parse_authentication_logs(log_file)

    assert len(events) == 1


def test_parse_authentication_logs_skips_malformed_lines(tmp_path):
    log_file = tmp_path / "authentication.log"
    log_file.write_text(
        (
            "malformed line\n"
            "2026-08-07 19:40:01 FAILED_LOGIN "
            "user=admin ip=1.1.1.1\n"
            "2026-08-07 19:40:02 INVALID_EVENT "
            "user=admin ip=1.1.1.1"
        ),
        encoding="utf-8",
    )

    events = parse_authentication_logs(log_file)

    assert len(events) == 1
    assert events[0].line_number == 2


def test_parse_authentication_logs_missing_file(tmp_path):
    missing_file = tmp_path / "missing.log"

    with pytest.raises(FileNotFoundError, match="authentication log not found"):
        parse_authentication_logs(missing_file)


def test_parse_authentication_logs_rejects_directory(tmp_path):
    directory = tmp_path / "authentication.log"
    directory.mkdir()

    with pytest.raises(IsADirectoryError, match="expected a file"):
        parse_authentication_logs(directory)


def test_parse_authentication_logs_rejects_invalid_utf8(tmp_path):
    log_file = tmp_path / "authentication.log"
    log_file.write_bytes(b"\xff\xfe\xfd")

    with pytest.raises(ValueError, match="not valid UTF-8"):
        parse_authentication_logs(log_file)


def test_parse_authentication_logs_preserves_event_order(tmp_path):
    log_file = tmp_path / "authentication.log"
    log_file.write_text(
        (
            "2026-08-07 19:40:03 FAILED_LOGIN "
            "user=third ip=1.1.1.3\n"
            "2026-08-07 19:40:01 FAILED_LOGIN "
            "user=first ip=1.1.1.1\n"
            "2026-08-07 19:40:02 FAILED_LOGIN "
            "user=second ip=1.1.1.2"
        ),
        encoding="utf-8",
    )

    events = parse_authentication_logs(log_file)

    assert [event.user for event in events] == [
        "third",
        "first",
        "second",
    ]


def test_parse_authentication_logs_handles_large_file(tmp_path):
    log_file = tmp_path / "authentication.log"
    base = datetime(
        2026,
        1,
        1,
        0,
        0,
        0,
        tzinfo=timezone.utc,
    )

    lines = []

    for index in range(1000):
        timestamp = base.replace(second=index % 60)
        lines.append(
            f"{timestamp:%Y-%m-%d %H:%M:%S} FAILED_LOGIN user=user{index} ip=192.0.2.1"
        )

    log_file.write_text("\n".join(lines), encoding="utf-8")

    events = parse_authentication_logs(log_file)

    assert len(events) == 1000
    assert events[0].timestamp.tzinfo == timezone.utc
    assert events[-1].line_number == 1000
