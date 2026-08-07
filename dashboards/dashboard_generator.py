import json
import os


REPORT_FILE = "reports/final_siem_report.json"
OUTPUT_FILE = "dashboards/index.html"


def generate_dashboard():

    with open(REPORT_FILE, "r") as file:
        report = json.load(file)


    alerts = report["alerts"]
    incidents = report["incidents"]
    risk = report["risk_assessment"]


    threats = ""

    mitre = set()

    for alert in alerts:
        details = alert["details"]

        threats += f"""
        <tr>
            <td>{details.get('type')}</td>
            <td>{details.get('severity')}</td>
            <td>{details.get('ip')}</td>
            <td>{details.get('mitre')}</td>
        </tr>
        """

        mitre.add(details.get("mitre"))


    incident_rows = ""

    for incident in incidents:
        incident_rows += f"""
        <tr>
            <td>{incident['incident_id']}</td>
            <td>{incident['status']}</td>
        </tr>
        """


    html = f"""
<!DOCTYPE html>

<html>

<head>

<title>CyberNova SOC Dashboard</title>

<link rel="stylesheet" href="style.css">

</head>


<body>


<h1>🛡 CyberNova SOC Dashboard v3.0</h1>


<div class="cards">


<div class="card">
<h2>{report['summary']['events_processed']}</h2>
<p>Events Analyzed</p>
</div>


<div class="card">
<h2>{report['summary']['alerts_generated']}</h2>
<p>Alerts Generated</p>
</div>


<div class="card">
<h2>{risk['risk_level']}</h2>
<p>Risk Level</p>
</div>


<div class="card">
<h2>{risk['risk_score']}</h2>
<p>Risk Score</p>
</div>


</div>



<h2>Security Findings</h2>

<table>

<tr>
<th>Threat</th>
<th>Severity</th>
<th>Source IP</th>
<th>MITRE ATT&CK</th>
</tr>

{threats}

</table>



<h2>Incidents</h2>

<table>

<tr>
<th>ID</th>
<th>Status</th>
</tr>

{incident_rows}

</table>



</body>

</html>
"""


    with open(OUTPUT_FILE, "w") as file:
        file.write(html)


    print("Dashboard created:")
    print(OUTPUT_FILE)



if __name__ == "__main__":
    generate_dashboard()
