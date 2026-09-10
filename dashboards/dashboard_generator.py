"""Static HTML dashboard generation from the final SIEM report."""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

REPORT_FILE = Path("reports/final_siem_report.json")
OUTPUT_FILE = Path("dashboards/index.html")


class DashboardGenerationError(Exception):
    """Raised when the SIEM report cannot be loaded or is malformed."""


def _load_report(report_file: Path) -> dict[str, Any]:
    if not report_file.exists():
        raise DashboardGenerationError(
            f"report file not found: {report_file}. Run the SIEM pipeline first."
        )

    try:
        with report_file.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except json.JSONDecodeError as exc:
        raise DashboardGenerationError(
            f"malformed report file {report_file}: {exc}"
        ) from exc


def _escape(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _render_findings_rows(alerts: list[dict[str, Any]]) -> str:
    rows = []

    for alert in alerts:
        details = alert.get("details", {})
        rows.append(
            "<tr>"
            f"<td>{_escape(details.get('type', ''))}</td>"
            f"<td>{_escape(details.get('severity', ''))}</td>"
            f"<td>{_escape(details.get('ip', ''))}</td>"
            f"<td>{_escape(details.get('mitre', ''))}</td>"
            "</tr>"
        )

    return "\n".join(rows)


def _render_incident_rows(incidents: list[dict[str, Any]]) -> str:
    rows = []

    for incident in incidents:
        rows.append(
            "<tr>"
            f"<td>{_escape(incident.get('incident_id', ''))}</td>"
            f"<td>{_escape(incident.get('status', ''))}</td>"
            "</tr>"
        )

    return "\n".join(rows)


def _render_metric_rows(metrics: dict[str, int]) -> str:
    return "\n".join(
        "<tr>"
        f"<td>{_escape(name)}</td>"
        f"<td>{_escape(count)}</td>"
        "</tr>"
        for name, count in metrics.items()
    )


def generate_dashboard(
    report_file: str | Path = REPORT_FILE,
    output_file: str | Path = OUTPUT_FILE,
) -> Path:
    report = _load_report(Path(report_file))

    summary = report.get("summary", {})
    metrics = report.get("metrics", {})
    risk = report.get("risk_assessment", {})

    alerts_by_type = metrics.get("alerts_by_type", {})
    alerts_by_severity = metrics.get("alerts_by_severity", {})

    threats = _render_findings_rows(report.get("alerts", []))
    incident_rows = _render_incident_rows(report.get("incidents", []))

    html_content = f"""<!DOCTYPE html>
<html>
<head>
<title>CyberNova SOC Dashboard</title>
<link rel="stylesheet" href="style.css">
</head>
<body>

<h1>CyberNova SOC Dashboard</h1>

<div class="cards">
<div class="card">
<h2>{_escape(summary.get('events_processed', 0))}</h2>
<p>Events Analyzed</p>
</div>
<div class="card">
<h2>{_escape(summary.get('alerts_generated', 0))}</h2>
<p>Alerts Generated</p>
</div>
<div class="card">
<h2>{_escape(risk.get('risk_level', 'UNKNOWN'))}</h2>
<p>Risk Level</p>
</div>
<div class="card">
<h2>{_escape(risk.get('risk_score', 0))}</h2>
<p>Risk Score</p>
</div>
</div>

<h2>Security Findings</h2>
<table>
<tr><th>Threat</th><th>Severity</th><th>Source IP</th><th>MITRE ATT&amp;CK</th></tr>
{threats}
</table>

<h2>Alert Distribution by Detection Type</h2>
<table>
<tr><th>Detection Type</th><th>Count</th></tr>
{_render_metric_rows(alerts_by_type)}
</table>

<h2>Alert Distribution by Severity</h2>
<table>
<tr><th>Severity</th><th>Count</th></tr>
{_render_metric_rows(alerts_by_severity)}
</table>

<h2>Incidents</h2>
<table>
<tr><th>ID</th><th>Status</th></tr>
{incident_rows}
</table>

</body>
</html>
"""

    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as handle:
        handle.write(html_content)

    return output_path


if __name__ == "__main__":
    try:
        generated_path = generate_dashboard()
    except DashboardGenerationError as exc:
        print(f"Dashboard generation failed: {exc}")
    else:
        print("Dashboard created:")
        print(generated_path)
