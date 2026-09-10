import json
from pathlib import Path

import pytest

import siem_lab_v2

RULE_BRUTE_FORCE = """\
threshold: 5
severity: HIGH
mitre: T1110 - Brute Force
window_minutes: 10
"""

RULE_SUCCESS = """\
threshold: 3
severity: CRITICAL
mitre: T1078 - Valid Accounts
window_minutes: 10
"""

RULE_DISTRIBUTED_SPRAY = """\
threshold: 5
severity: HIGH
mitre: T1110 - Brute Force
window_minutes: 10
"""

CONFIG = """\
project:
  name: Test SIEM
  version: 1.0
risk:
  levels:
    LOW: 20
    MEDIUM: 50
    HIGH: 80
    CRITICAL: 100
"""


def _write_workspace(base: Path, log_content: str = "") -> None:
    (base / "rules").mkdir()
    (base / "rules" / "brute_force.yaml").write_text(
        RULE_BRUTE_FORCE,
        encoding="utf-8",
    )
    (base / "rules" / "success_after_failures.yaml").write_text(
        RULE_SUCCESS,
        encoding="utf-8",
    )
    (base / "rules" / "distributed_password_spray.yaml").write_text(
        RULE_DISTRIBUTED_SPRAY,
        encoding="utf-8",
    )

    (base / "config").mkdir()
    (base / "config" / "siem_config.yaml").write_text(
        CONFIG,
        encoding="utf-8",
    )

    (base / "logs").mkdir()
    (base / "logs" / "authentication.log").write_text(
        log_content,
        encoding="utf-8",
    )


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    _write_workspace(tmp_path)
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_main_happy_path_generates_report_and_incidents(
    workspace,
    capsys,
):
    log_lines = [
        f"2026-01-01 00:00:{i:02} "
        f"FAILED_LOGIN user=admin ip=45.33.32.156"
        for i in range(5)
    ]

    (
        workspace / "logs" / "authentication.log"
    ).write_text(
        "\n".join(log_lines),
        encoding="utf-8",
    )

    exit_code = siem_lab_v2.main()

    assert exit_code == 0

    report_path = (
        workspace
        / "reports"
        / "final_siem_report.json"
    )

    assert report_path.exists()

    report = json.loads(
        report_path.read_text(encoding="utf-8")
    )

    assert report["summary"]["events_processed"] == 5
    assert report["summary"]["alerts_generated"] == 1
    assert report["risk_assessment"]["risk_level"] == "HIGH"

    incidents_dir = workspace / "incidents"

    assert (
        incidents_dir / "incident_001.json"
    ).exists()

    output = capsys.readouterr().out

    assert "CyberNova SIEM Detection Lab" in output
    assert "45.33.32.156" in output


def test_main_missing_log_file_returns_error(
    tmp_path,
    monkeypatch,
    capsys,
):
    _write_workspace(tmp_path)

    (
        tmp_path
        / "logs"
        / "authentication.log"
    ).unlink()

    monkeypatch.chdir(tmp_path)

    exit_code = siem_lab_v2.main()

    assert exit_code == 1

    output = capsys.readouterr().out

    assert "Error" in output


def test_main_missing_rule_file_returns_error(
    tmp_path,
    monkeypatch,
    capsys,
):
    _write_workspace(tmp_path)

    (
        tmp_path
        / "rules"
        / "brute_force.yaml"
    ).unlink()

    monkeypatch.chdir(tmp_path)

    exit_code = siem_lab_v2.main()

    assert exit_code == 1

    output = capsys.readouterr().out

    assert "Error" in output


def test_main_missing_config_falls_back_to_defaults(
    tmp_path,
    monkeypatch,
):
    _write_workspace(tmp_path)

    (
        tmp_path
        / "config"
        / "siem_config.yaml"
    ).unlink()

    monkeypatch.chdir(tmp_path)

    log_lines = [
        f"2026-01-01 00:00:{i:02} "
        f"FAILED_LOGIN user=admin ip=45.33.32.156"
        for i in range(5)
    ]

    (
        tmp_path
        / "logs"
        / "authentication.log"
    ).write_text(
        "\n".join(log_lines),
        encoding="utf-8",
    )

    exit_code = siem_lab_v2.main()

    assert exit_code == 0

    report = json.loads(
        (
            tmp_path
            / "reports"
            / "final_siem_report.json"
        ).read_text(encoding="utf-8")
    )

    assert report["risk_assessment"]["risk_level"] == "HIGH"


def test_main_empty_log_reports_no_attacking_ip(
    workspace,
    capsys,
):
    exit_code = siem_lab_v2.main()

    assert exit_code == 0

    output = capsys.readouterr().out

    assert "Top Attacking IP:" in output
    assert "None" in output

    report = json.loads(
        (
            workspace
            / "reports"
            / "final_siem_report.json"
        ).read_text(encoding="utf-8")
    )

    assert report["summary"]["events_processed"] == 0
    assert report["summary"]["alerts_generated"] == 0


def test_main_second_run_appends_incidents_without_overwriting(
    workspace,
):
    log_lines = [
        f"2026-01-01 00:00:{i:02} "
        f"FAILED_LOGIN user=admin ip=45.33.32.156"
        for i in range(5)
    ]

    (
        workspace
        / "logs"
        / "authentication.log"
    ).write_text(
        "\n".join(log_lines),
        encoding="utf-8",
    )

    siem_lab_v2.main()
    siem_lab_v2.main()

    incidents_dir = workspace / "incidents"

    assert (
        incidents_dir / "incident_001.json"
    ).exists()

    assert (
        incidents_dir / "incident_002.json"
    ).exists()
