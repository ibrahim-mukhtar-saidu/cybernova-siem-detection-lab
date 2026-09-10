import json
from datetime import datetime

from engine.report_generator import REPORT_FILENAME, generate_report


def test_generate_report_empty_inputs(tmp_path):
    report = generate_report([], [], [], report_dir=tmp_path)

    assert report["summary"] == {
        "events_processed": 0,
        "alerts_generated": 0,
        "incidents_created": 0,
    }
    assert report["risk_assessment"] == {
        "risk_score": 0,
        "risk_level": "LOW",
    }
    assert report["alerts"] == []
    assert report["incidents"] == []
    datetime.fromisoformat(report["generated"])


def test_generate_report_writes_json_file(tmp_path):
    events = [object(), object()]
    alerts = [{"details": {"severity": "HIGH"}}]
    incidents = [{"incident_id": "INC-001", "status": "OPEN"}]

    report = generate_report(
        events,
        alerts,
        incidents,
        report_dir=tmp_path,
    )

    report_path = tmp_path / REPORT_FILENAME

    assert report_path.exists()

    on_disk = json.loads(
        report_path.read_text(encoding="utf-8")
    )

    assert on_disk == report


def test_generate_report_counts_match_input_lengths(tmp_path):
    events = list(range(7))
    alerts = [{"details": {"severity": "LOW"}}] * 3
    incidents = [
        {"incident_id": f"INC-{i:03}"}
        for i in range(2)
    ]

    report = generate_report(
        events,
        alerts,
        incidents,
        report_dir=tmp_path,
    )

    assert report["summary"]["events_processed"] == 7
    assert report["summary"]["alerts_generated"] == 3
    assert report["summary"]["incidents_created"] == 2


def test_generate_report_uses_custom_risk_levels(tmp_path):
    alerts = [
        {"details": {"severity": "LOW"}}
    ]

    custom_levels = {
        "LOW": 0,
        "MEDIUM": 5,
        "HIGH": 10,
        "CRITICAL": 15,
    }

    report = generate_report(
        [],
        alerts,
        [],
        risk_levels=custom_levels,
        report_dir=tmp_path,
    )

    assert report["risk_assessment"]["risk_level"] == "CRITICAL"


def test_generate_report_creates_missing_directory(tmp_path):
    nested_dir = tmp_path / "nested" / "reports"

    generate_report(
        [],
        [],
        [],
        report_dir=nested_dir,
    )

    assert (nested_dir / REPORT_FILENAME).exists()


def test_generate_report_overwrites_previous_report(tmp_path):
    generate_report(
        [1],
        [],
        [],
        report_dir=tmp_path,
    )

    second_report = generate_report(
        [1, 2, 3],
        [],
        [],
        report_dir=tmp_path,
    )

    on_disk = json.loads(
        (tmp_path / REPORT_FILENAME).read_text(
            encoding="utf-8"
        )
    )

    assert on_disk["summary"]["events_processed"] == 3
    assert on_disk == second_report


def test_generate_report_includes_tool_and_version_fields(tmp_path):
    report = generate_report(
        [],
        [],
        [],
        report_dir=tmp_path,
    )

    assert report["tool"] == "CyberNova SIEM Detection Lab"
    assert "version" in report


def test_generate_report_metrics_empty_inputs(tmp_path):
    report = generate_report([], [], [], report_dir=tmp_path)

    assert report["metrics"] == {
        "alerts_by_type": {},
        "alerts_by_severity": {},
    }


def test_generate_report_metrics_group_alerts_by_type_and_severity(tmp_path):
    alerts = [
        {
            "details": {
                "type": "BRUTE_FORCE",
                "severity": "HIGH",
            }
        },
        {
            "details": {
                "type": "BRUTE_FORCE",
                "severity": "HIGH",
            }
        },
        {
            "details": {
                "type": "SUCCESS_AFTER_FAILURES",
                "severity": "CRITICAL",
            }
        },
        {
            "details": {
                "type": "DISTRIBUTED_PASSWORD_SPRAY",
                "severity": "HIGH",
            }
        },
    ]

    report = generate_report(
        [],
        alerts,
        [],
        report_dir=tmp_path,
    )

    assert report["metrics"] == {
        "alerts_by_type": {
            "BRUTE_FORCE": 2,
            "DISTRIBUTED_PASSWORD_SPRAY": 1,
            "SUCCESS_AFTER_FAILURES": 1,
        },
        "alerts_by_severity": {
            "CRITICAL": 1,
            "HIGH": 3,
        },
    }


def test_generate_report_metrics_handle_missing_alert_details(tmp_path):
    alerts = [
        {},
        {"details": {}},
    ]

    report = generate_report(
        [],
        alerts,
        [],
        report_dir=tmp_path,
    )

    assert report["metrics"] == {
        "alerts_by_type": {
            "UNKNOWN": 2,
        },
        "alerts_by_severity": {
            "UNKNOWN": 2,
        },
    }
