def calculate_risk(alerts):

    risk_score = 0

    for alert in alerts:

        severity = alert.get("details", {}).get("severity", "LOW")

        if severity == "CRITICAL":
            risk_score += 100

        elif severity == "HIGH":
            risk_score += 80

        elif severity == "MEDIUM":
            risk_score += 50

        elif severity == "LOW":
            risk_score += 20


    if risk_score >= 100:
        risk_level = "CRITICAL"

    elif risk_score >= 80:
        risk_level = "HIGH"

    elif risk_score >= 50:
        risk_level = "MEDIUM"

    else:
        risk_level = "LOW"


    return {
        "risk_score": risk_score,
        "risk_level": risk_level
    }
