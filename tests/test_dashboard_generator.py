import json

import pytest

from dashboards.dashboard_generator import (
    DashboardGenerationError,
    generate_dashboard,
)


def write_report(path, **overrides):
    report = {
        "summary": {
            "events_processed": 10,
            "alerts_generated": 2,
            "incidents_created": 2,
        },
        "risk_assessment": {
            "risk_score": 180,
            "risk_level": "CRITICAL",
        },
        "metrics": {
            "alerts_by_type": {
                "BRUTE_FORCE": 1,
            },
            "alerts_by_severity": {
                "HIGH": 1,
            },
        },
        "alerts": [
            {
                "details": {
                    "type": "BRUTE_FORCE",
                    "severity": "HIGH",
                    "ip": "45.33.32.156",
                    "mitre": "T1110 - Brute Force",
                }
            }
        ],
        "incidents": [
            {
                "incident_id": "INC-001",
                "status": "OPEN",
            }
        ],
    }

    report.update(overrides)
    path.write_text(
        json.dumps(report),
        encoding="utf-8",
    )

    return report


def test_generate_dashboard_missing_report_raises(tmp_path):
    missing_report = tmp_path / "final_siem_report.json"
    output = tmp_path / "index.html"

    with pytest.raises(
        DashboardGenerationError,
        match="not found",
    ):
        generate_dashboard(missing_report, output)


def test_generate_dashboard_malformed_json_raises(tmp_path):
    report_file = tmp_path / "final_siem_report.json"
    report_file.write_text(
        "{not valid json",
        encoding="utf-8",
    )

    output = tmp_path / "index.html"

    with pytest.raises(
        DashboardGenerationError,
        match="malformed report",
    ):
        generate_dashboard(report_file, output)


def test_generate_dashboard_creates_output_file(tmp_path):
    report_file = tmp_path / "final_siem_report.json"
    write_report(report_file)

    output = tmp_path / "index.html"

    result_path = generate_dashboard(
        report_file,
        output,
    )

    assert result_path == output
    assert output.exists()

    html_content = output.read_text(
        encoding="utf-8"
    )

    assert "BRUTE_FORCE" in html_content
    assert "45.33.32.156" in html_content
    assert "CRITICAL" in html_content
    assert "INC-001" in html_content


def test_generate_dashboard_renders_alert_metrics(tmp_path):
    report_file = tmp_path / "final_siem_report.json"

    write_report(
        report_file,
        metrics={
            "alerts_by_type": {
                "BRUTE_FORCE": 3,
                "DISTRIBUTED_PASSWORD_SPRAY": 2,
            },
            "alerts_by_severity": {
                "CRITICAL": 1,
                "HIGH": 4,
            },
        },
    )

    output = tmp_path / "index.html"

    generate_dashboard(report_file, output)

    html_content = output.read_text(encoding="utf-8")

    assert "Alert Distribution by Detection Type" in html_content
    assert "DISTRIBUTED_PASSWORD_SPRAY" in html_content
    assert ">2<" in html_content

    assert "Alert Distribution by Severity" in html_content
    assert "CRITICAL" in html_content
    assert ">4<" in html_content


def test_generate_dashboard_renders_alert_metrics(tmp_path):
    report_file = tmp_path / "final_siem_report.json"

    write_report(
        report_file,
        metrics={
            "alerts_by_type": {
                "BRUTE_FORCE": 3,
                "DISTRIBUTED_PASSWORD_SPRAY": 2,
            },
            "alerts_by_severity": {
                "CRITICAL": 1,
                "HIGH": 4,
            },
        },
    )

    output = tmp_path / "index.html"

    generate_dashboard(report_file, output)

    html_content = output.read_text(encoding="utf-8")

    assert "Alert Distribution by Detection Type" in html_content
    assert "DISTRIBUTED_PASSWORD_SPRAY" in html_content
    assert "<td>2</td>" in html_content

    assert "Alert Distribution by Severity" in html_content
    assert "CRITICAL" in html_content
    assert "<td>4</td>" in html_content


def test_generate_dashboard_escapes_html_injection_in_ip_field(
    tmp_path,
):
    report_file = tmp_path / "final_siem_report.json"

    write_report(
        report_file,
        alerts=[
            {
                "details": {
                    "type": "BRUTE_FORCE",
                    "severity": "HIGH",
                    "ip": "<script>alert(1)</script>",
                    "mitre": "T1110 - Brute Force",
                }
            }
        ],
    )

    output = tmp_path / "index.html"

    generate_dashboard(
        report_file,
        output,
    )

    html_content = output.read_text(
        encoding="utf-8"
    )

    assert "<script>alert(1)</script>" not in html_content
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html_content


def test_generate_dashboard_handles_missing_optional_fields_gracefully(
    tmp_path,
):
    report_file = tmp_path / "final_siem_report.json"

    report_file.write_text(
        json.dumps({}),
        encoding="utf-8",
    )

    output = tmp_path / "index.html"

    generate_dashboard(
        report_file,
        output,
    )

    html_content = output.read_text(
        encoding="utf-8"
    )

    assert "UNKNOWN" in html_content


def test_generate_dashboard_empty_alerts_and_incidents(
    tmp_path,
):
    report_file = tmp_path / "final_siem_report.json"

    write_report(
        report_file,
        alerts=[],
        incidents=[],
    )

    output = tmp_path / "index.html"

    generate_dashboard(
        report_file,
        output,
    )

    html_content = output.read_text(
        encoding="utf-8"
    )

    assert "<table>" in html_content


def test_generate_dashboard_creates_missing_output_directory(
    tmp_path,
):
    report_file = tmp_path / "final_siem_report.json"
    write_report(report_file)

    output = (
        tmp_path
        / "nested"
        / "dashboard"
        / "index.html"
    )

    generate_dashboard(
        report_file,
        output,
    )

    assert output.exists()


def test_generate_dashboard_accepts_string_paths(
    tmp_path,
):
    report_file = tmp_path / "final_siem_report.json"
    write_report(report_file)

    output = tmp_path / "index.html"

    generate_dashboard(
        str(report_file),
        str(output),
    )

    assert output.exists()


def test_generate_dashboard_handles_many_alerts(
    tmp_path,
):
    report_file = tmp_path / "final_siem_report.json"

    alerts = [
        {
            "details": {
                "type": "BRUTE_FORCE",
                "severity": "HIGH",
                "ip": f"10.0.0.{i % 250 + 1}",
                "mitre": "T1110 - Brute Force",
            }
        }
        for i in range(200)
    ]

    write_report(
        report_file,
        alerts=alerts,
        incidents=[],
    )

    output = tmp_path / "index.html"

    generate_dashboard(
        report_file,
        output,
    )

    html_content = output.read_text(
        encoding="utf-8"
    )

    assert html_content.count("<tr>") == 206
    assert html_content.count("<td>BRUTE_FORCE</td>") == 201
    assert "<td>HIGH</td>" in html_content
