
from datetime import datetime, timedelta, timezone

import pytest

from config_loader import ConfigError
from engine import detection_engine
from engine.detection_engine import (
    detect_bruteforce,
    detect_distributed_password_spraying,
    detect_success_after_failures,
)
from engine.log_parser import AuthEvent

BASE_TIME = datetime(
    2026,
    1,
    1,
    0,
    0,
    0,
    tzinfo=timezone.utc,
)

BRUTE_FORCE_RULE = {
    "threshold": 5,
    "window_minutes": 10,
    "severity": "HIGH",
    "mitre": "T1110 - Brute Force",
}

SUCCESS_RULE = {
    "threshold": 3,
    "window_minutes": 10,
    "severity": "CRITICAL",
    "mitre": "T1078 - Valid Accounts",
}

DISTRIBUTED_SPRAY_RULE = {
    "threshold": 5,
    "window_minutes": 10,
    "severity": "HIGH",
    "mitre": "T1110 - Brute Force",
}


def make_event(
    timestamp,
    event_type,
    ip,
    user="user",
    line_number=1,
):
    return AuthEvent(
        timestamp=timestamp,
        event_type=event_type,
        user=user,
        ip=ip,
        line_number=line_number,
    )


def test_detect_bruteforce_no_events_no_alert():
    assert detect_bruteforce([], BRUTE_FORCE_RULE) == []


def test_detect_bruteforce_below_threshold_no_alert():
    events = [
        make_event(
            BASE_TIME + timedelta(seconds=i),
            "FAILED_LOGIN",
            "1.2.3.4",
        )
        for i in range(4)
    ]

    assert detect_bruteforce(events, BRUTE_FORCE_RULE) == []


def test_detect_bruteforce_at_threshold_triggers_alert():
    events = [
        make_event(
            BASE_TIME + timedelta(seconds=i),
            "FAILED_LOGIN",
            "1.2.3.4",
        )
        for i in range(5)
    ]

    alerts = detect_bruteforce(events, BRUTE_FORCE_RULE)

    assert len(alerts) == 1
    assert alerts[0]["type"] == "BRUTE_FORCE"
    assert alerts[0]["ip"] == "1.2.3.4"
    assert alerts[0]["attempts"] == 5
    assert alerts[0]["severity"] == "HIGH"
    assert alerts[0]["mitre"] == "T1110 - Brute Force"


def test_detect_bruteforce_above_threshold_alerts_once_per_ip():
    events = [
        make_event(
            BASE_TIME + timedelta(seconds=i),
            "FAILED_LOGIN",
            "1.2.3.4",
        )
        for i in range(10)
    ]

    alerts = detect_bruteforce(events, BRUTE_FORCE_RULE)

    assert len(alerts) == 1


def test_detect_bruteforce_distributed_across_ips_evades_detection():
    events = []

    for ip_suffix in range(4):
        events.extend(
            make_event(
                BASE_TIME + timedelta(seconds=i),
                "FAILED_LOGIN",
                f"1.2.3.{ip_suffix}",
            )
            for i in range(4)
        )

    assert detect_bruteforce(events, BRUTE_FORCE_RULE) == []


def test_detect_bruteforce_events_outside_time_window_do_not_accumulate():
    window = timedelta(minutes=BRUTE_FORCE_RULE["window_minutes"])

    events = [
        make_event(BASE_TIME, "FAILED_LOGIN", "1.2.3.4"),
        make_event(
            BASE_TIME + window + timedelta(seconds=1),
            "FAILED_LOGIN",
            "1.2.3.4",
        ),
        make_event(
            BASE_TIME + window + timedelta(seconds=2),
            "FAILED_LOGIN",
            "1.2.3.4",
        ),
        make_event(
            BASE_TIME + window + timedelta(seconds=3),
            "FAILED_LOGIN",
            "1.2.3.4",
        ),
        make_event(
            BASE_TIME + window + timedelta(seconds=4),
            "FAILED_LOGIN",
            "1.2.3.4",
        ),
    ]

    assert detect_bruteforce(events, BRUTE_FORCE_RULE) == []


def test_detect_bruteforce_boundary_at_exact_window_edge_is_included():
    window = timedelta(minutes=BRUTE_FORCE_RULE["window_minutes"])

    events = [make_event(BASE_TIME, "FAILED_LOGIN", "1.2.3.4")]
    events += [
        make_event(
            BASE_TIME + window,
            "FAILED_LOGIN",
            "1.2.3.4",
        )
        for _ in range(4)
    ]

    alerts = detect_bruteforce(events, BRUTE_FORCE_RULE)

    assert len(alerts) == 1
    assert alerts[0]["attempts"] == 5


def test_detect_bruteforce_handles_out_of_order_input():
    events = [
        make_event(
            BASE_TIME + timedelta(seconds=i),
            "FAILED_LOGIN",
            "1.2.3.4",
        )
        for i in range(5)
    ]

    alerts = detect_bruteforce(
        list(reversed(events)),
        BRUTE_FORCE_RULE,
    )

    assert len(alerts) == 1
    assert alerts[0]["attempts"] == 5


def test_detect_bruteforce_multiple_ips_each_alert_independently():
    events = []

    for ip in ("1.1.1.1", "2.2.2.2"):
        events.extend(
            make_event(
                BASE_TIME + timedelta(seconds=i),
                "FAILED_LOGIN",
                ip,
            )
            for i in range(5)
        )

    alerts = detect_bruteforce(events, BRUTE_FORCE_RULE)

    assert {alert["ip"] for alert in alerts} == {
        "1.1.1.1",
        "2.2.2.2",
    }


def test_detect_bruteforce_ignores_successful_logins():
    events = [
        make_event(
            BASE_TIME + timedelta(seconds=i),
            "SUCCESSFUL_LOGIN",
            "1.2.3.4",
        )
        for i in range(10)
    ]

    assert detect_bruteforce(events, BRUTE_FORCE_RULE) == []


def test_success_after_failures_no_prior_failures_no_alert():
    events = [
        make_event(
            BASE_TIME,
            "SUCCESSFUL_LOGIN",
            "1.2.3.4",
        )
    ]

    assert detect_success_after_failures(events, SUCCESS_RULE) == []


def test_success_after_failures_below_threshold_no_alert():
    events = [
        make_event(
            BASE_TIME + timedelta(seconds=i),
            "FAILED_LOGIN",
            "1.2.3.4",
        )
        for i in range(2)
    ]

    events.append(
        make_event(
            BASE_TIME + timedelta(seconds=3),
            "SUCCESSFUL_LOGIN",
            "1.2.3.4",
        )
    )

    assert detect_success_after_failures(events, SUCCESS_RULE) == []


def test_success_after_failures_at_threshold_triggers_alert():
    events = [
        make_event(
            BASE_TIME + timedelta(seconds=i),
            "FAILED_LOGIN",
            "1.2.3.4",
        )
        for i in range(3)
    ]

    events.append(
        make_event(
            BASE_TIME + timedelta(seconds=4),
            "SUCCESSFUL_LOGIN",
            "1.2.3.4",
        )
    )

    alerts = detect_success_after_failures(events, SUCCESS_RULE)

    assert len(alerts) == 1
    assert alerts[0]["type"] == "SUCCESS_AFTER_FAILURES"
    assert alerts[0]["ip"] == "1.2.3.4"
    assert alerts[0]["attempts_before_success"] == 3
    assert alerts[0]["severity"] == "CRITICAL"
    assert alerts[0]["mitre"] == "T1078 - Valid Accounts"


def test_success_after_failures_resets_counter_after_success():
    events = [
        make_event(
            BASE_TIME + timedelta(seconds=i),
            "FAILED_LOGIN",
            "1.2.3.4",
        )
        for i in range(3)
    ]

    events.extend(
        [
            make_event(
                BASE_TIME + timedelta(seconds=4),
                "SUCCESSFUL_LOGIN",
                "1.2.3.4",
            ),
            make_event(
                BASE_TIME + timedelta(seconds=5),
                "FAILED_LOGIN",
                "1.2.3.4",
            ),
            make_event(
                BASE_TIME + timedelta(seconds=6),
                "SUCCESSFUL_LOGIN",
                "1.2.3.4",
            ),
        ]
    )

    alerts = detect_success_after_failures(events, SUCCESS_RULE)

    assert len(alerts) == 1


def test_success_after_failures_clears_counter_even_without_alert():
    events = [
        make_event(
            BASE_TIME + timedelta(seconds=i),
            "FAILED_LOGIN",
            "1.2.3.4",
        )
        for i in range(2)
    ]

    events.append(
        make_event(
            BASE_TIME + timedelta(seconds=3),
            "SUCCESSFUL_LOGIN",
            "1.2.3.4",
        )
    )

    events.extend(
        make_event(
            BASE_TIME + timedelta(seconds=4 + i),
            "FAILED_LOGIN",
            "1.2.3.4",
        )
        for i in range(2)
    )

    events.append(
        make_event(
            BASE_TIME + timedelta(seconds=10),
            "SUCCESSFUL_LOGIN",
            "1.2.3.4",
        )
    )

    assert detect_success_after_failures(events, SUCCESS_RULE) == []


def test_success_after_failures_independent_per_ip():
    events = [
        make_event(
            BASE_TIME + timedelta(seconds=i),
            "FAILED_LOGIN",
            "1.1.1.1",
        )
        for i in range(3)
    ]

    events.extend(
        [
            make_event(
                BASE_TIME + timedelta(seconds=4),
                "SUCCESSFUL_LOGIN",
                "1.1.1.1",
            ),
            make_event(
                BASE_TIME + timedelta(seconds=5),
                "SUCCESSFUL_LOGIN",
                "2.2.2.2",
            ),
        ]
    )

    alerts = detect_success_after_failures(events, SUCCESS_RULE)

    assert len(alerts) == 1
    assert alerts[0]["ip"] == "1.1.1.1"


def test_success_after_failures_respects_time_window():
    window = timedelta(minutes=SUCCESS_RULE["window_minutes"])

    events = [
        make_event(
            BASE_TIME + timedelta(seconds=i),
            "FAILED_LOGIN",
            "1.2.3.4",
        )
        for i in range(3)
    ]

    events.append(
        make_event(
            BASE_TIME + window + timedelta(seconds=1),
            "SUCCESSFUL_LOGIN",
            "1.2.3.4",
        )
    )

    assert detect_success_after_failures(events, SUCCESS_RULE) == []


def test_distributed_password_spraying_detects_same_user_across_ips():
    events = [
        make_event(
            BASE_TIME + timedelta(seconds=i),
            "FAILED_LOGIN",
            f"10.0.0.{i + 1}",
            user="alice",
        )
        for i in range(5)
    ]

    alerts = detect_distributed_password_spraying(
        events,
        DISTRIBUTED_SPRAY_RULE,
    )

    assert len(alerts) == 1
    assert alerts[0]["type"] == "DISTRIBUTED_PASSWORD_SPRAY"
    assert alerts[0]["user"] == "alice"
    assert alerts[0]["attempts"] == 5
    assert alerts[0]["source_ips"] == 5
    assert alerts[0]["severity"] == "HIGH"
    assert alerts[0]["mitre"] == "T1110 - Brute Force"


def test_distributed_password_spraying_requires_multiple_source_ips():
    events = [
        make_event(
            BASE_TIME + timedelta(seconds=i),
            "FAILED_LOGIN",
            "10.0.0.1",
            user="alice",
        )
        for i in range(5)
    ]

    assert (
        detect_distributed_password_spraying(
            events,
            DISTRIBUTED_SPRAY_RULE,
        )
        == []
    )


def test_distributed_password_spraying_requires_same_target_user():
    events = [
        make_event(
            BASE_TIME + timedelta(seconds=i),
            "FAILED_LOGIN",
            f"10.0.0.{i + 1}",
            user=f"user{i + 1}",
        )
        for i in range(5)
    ]

    assert (
        detect_distributed_password_spraying(
            events,
            DISTRIBUTED_SPRAY_RULE,
        )
        == []
    )


def test_distributed_password_spraying_respects_time_window():
    window = timedelta(minutes=DISTRIBUTED_SPRAY_RULE["window_minutes"])

    events = [
        make_event(
            BASE_TIME,
            "FAILED_LOGIN",
            "10.0.0.1",
            user="alice",
        ),
        make_event(
            BASE_TIME + window + timedelta(seconds=1),
            "FAILED_LOGIN",
            "10.0.0.2",
            user="alice",
        ),
        make_event(
            BASE_TIME + window + timedelta(seconds=2),
            "FAILED_LOGIN",
            "10.0.0.3",
            user="alice",
        ),
        make_event(
            BASE_TIME + window + timedelta(seconds=3),
            "FAILED_LOGIN",
            "10.0.0.4",
            user="alice",
        ),
        make_event(
            BASE_TIME + window + timedelta(seconds=4),
            "FAILED_LOGIN",
            "10.0.0.5",
            user="alice",
        ),
    ]

    assert (
        detect_distributed_password_spraying(
            events,
            DISTRIBUTED_SPRAY_RULE,
        )
        == []
    )


def test_distributed_password_spraying_alerts_users_independently():
    events = []

    for user in ("alice", "bob"):
        events.extend(
            make_event(
                BASE_TIME + timedelta(seconds=i),
                "FAILED_LOGIN",
                f"10.0.{1 if user == 'alice' else 2}.{i + 1}",
                user=user,
            )
            for i in range(5)
        )

    alerts = detect_distributed_password_spraying(
        events,
        DISTRIBUTED_SPRAY_RULE,
    )

    assert {alert["user"] for alert in alerts} == {"alice", "bob"}


def test_run_detection_combines_both_rules(tmp_path, monkeypatch):
    brute_force_rule_file = tmp_path / "brute_force.yaml"
    success_rule_file = tmp_path / "success.yaml"
    distributed_spray_rule_file = tmp_path / "distributed_spray.yaml"

    brute_force_rule_file.write_text(
        """threshold: 2
severity: HIGH
mitre: T1110 - Brute Force
window_minutes: 10
""",
        encoding="utf-8",
    )

    success_rule_file.write_text(
        """threshold: 1
severity: CRITICAL
mitre: T1078 - Valid Accounts
window_minutes: 10
""",
        encoding="utf-8",
    )

    distributed_spray_rule_file.write_text(
        """threshold: 5
severity: HIGH
mitre: T1110 - Brute Force
window_minutes: 10
""",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        detection_engine,
        "BRUTE_FORCE_RULE_FILE",
        str(brute_force_rule_file),
    )

    monkeypatch.setattr(
        detection_engine,
        "SUCCESS_AFTER_FAILURES_RULE_FILE",
        str(success_rule_file),
    )

    monkeypatch.setattr(
        detection_engine,
        "DISTRIBUTED_PASSWORD_SPRAY_RULE_FILE",
        str(distributed_spray_rule_file),
    )

    events = [
        make_event(
            BASE_TIME,
            "FAILED_LOGIN",
            "1.2.3.4",
        ),
        make_event(
            BASE_TIME + timedelta(seconds=1),
            "FAILED_LOGIN",
            "1.2.3.4",
        ),
        make_event(
            BASE_TIME + timedelta(seconds=2),
            "SUCCESSFUL_LOGIN",
            "1.2.3.4",
        ),
    ]

    alerts = detection_engine.run_detection(events)

    assert {alert["type"] for alert in alerts} == {
        "BRUTE_FORCE",
        "SUCCESS_AFTER_FAILURES",
    }


def test_run_detection_detects_distributed_password_spray(tmp_path, monkeypatch):
    distributed_spray_rule_file = tmp_path / "distributed_spray.yaml"

    distributed_spray_rule_file.write_text(
        """threshold: 5
severity: HIGH
mitre: T1110 - Brute Force
window_minutes: 10
""",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        detection_engine,
        "DISTRIBUTED_PASSWORD_SPRAY_RULE_FILE",
        str(distributed_spray_rule_file),
    )

    events = [
        make_event(
            BASE_TIME + timedelta(seconds=i),
            "FAILED_LOGIN",
            f"10.10.0.{i + 1}",
            user="alice",
        )
        for i in range(5)
    ]

    alerts = detection_engine.run_detection(events)

    spray_alerts = [
        alert
        for alert in alerts
        if alert["type"] == "DISTRIBUTED_PASSWORD_SPRAY"
    ]

    assert spray_alerts == [
        {
            "type": "DISTRIBUTED_PASSWORD_SPRAY",
            "user": "alice",
            "attempts": 5,
            "source_ips": 5,
            "severity": "HIGH",
            "mitre": "T1110 - Brute Force",
        }
    ]


def test_run_detection_raises_config_error_when_rule_missing(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(
        detection_engine,
        "BRUTE_FORCE_RULE_FILE",
        str(tmp_path / "missing.yaml"),
    )

    with pytest.raises(ConfigError):
        detection_engine.run_detection([])
