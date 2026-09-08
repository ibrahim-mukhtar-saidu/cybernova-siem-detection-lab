import logging

from engine.risk_engine import DEFAULT_RISK_LEVELS, calculate_risk


def alert(severity):
    return {"details": {"severity": severity}}


def test_default_risk_levels_matches_documented_thresholds():
    assert DEFAULT_RISK_LEVELS == {
        "LOW": 20,
        "MEDIUM": 50,
        "HIGH": 80,
        "CRITICAL": 100,
    }


def test_calculate_risk_no_alerts():
    assert calculate_risk([]) == {
        "risk_score": 0,
        "risk_level": "LOW",
    }


def test_calculate_risk_single_low():
    assert calculate_risk([alert("LOW")]) == {
        "risk_score": 20,
        "risk_level": "LOW",
    }


def test_calculate_risk_single_medium_boundary():
    assert calculate_risk([alert("MEDIUM")]) == {
        "risk_score": 50,
        "risk_level": "MEDIUM",
    }


def test_calculate_risk_single_high_boundary():
    assert calculate_risk([alert("HIGH")]) == {
        "risk_score": 80,
        "risk_level": "HIGH",
    }


def test_calculate_risk_single_critical_boundary():
    assert calculate_risk([alert("CRITICAL")]) == {
        "risk_score": 100,
        "risk_level": "CRITICAL",
    }


def test_calculate_risk_combination_crosses_critical_boundary():
    result = calculate_risk(
        [alert("HIGH"), alert("LOW")]
    )

    assert result == {
        "risk_score": 100,
        "risk_level": "CRITICAL",
    }


def test_calculate_risk_combination_stays_medium():
    result = calculate_risk(
        [alert("MEDIUM"), alert("LOW")]
    )

    assert result == {
        "risk_score": 70,
        "risk_level": "MEDIUM",
    }


def test_calculate_risk_missing_details_key_defaults_to_low():
    assert calculate_risk([{}]) == {
        "risk_score": 20,
        "risk_level": "LOW",
    }


def test_calculate_risk_missing_severity_key_defaults_to_low():
    assert calculate_risk([{"details": {}}]) == {
        "risk_score": 20,
        "risk_level": "LOW",
    }


def test_calculate_risk_unknown_severity_treated_as_low_and_logged(
    caplog,
):
    with caplog.at_level(
        logging.WARNING,
        logger="engine.risk_engine",
    ):
        result = calculate_risk(
            [alert("SEV_TYPO")]
        )

    assert result == {
        "risk_score": 20,
        "risk_level": "LOW",
    }

    assert any(
        "unrecognized alert severity" in r.message
        for r in caplog.records
    )


def test_calculate_risk_custom_risk_levels():
    custom = {
        "LOW": 100,
        "MEDIUM": 200,
        "HIGH": 300,
        "CRITICAL": 400,
    }

    result = calculate_risk(
        [alert("CRITICAL")],
        risk_levels=custom,
    )

    assert result == {
        "risk_score": 100,
        "risk_level": "LOW",
    }


def test_calculate_risk_partial_custom_risk_levels_falls_back_to_defaults():
    custom = {"HIGH": 10}

    result = calculate_risk(
        [alert("LOW"), alert("LOW"), alert("LOW")],
        risk_levels=custom,
    )

    assert result["risk_score"] == 60
    assert result["risk_level"] == "HIGH"


def test_calculate_risk_empty_dict_risk_levels_falls_back_to_defaults():
    result = calculate_risk(
        [alert("CRITICAL")],
        risk_levels={},
    )

    assert result["risk_level"] == "CRITICAL"


def test_calculate_risk_large_number_of_alerts():
    alerts = [
        alert("CRITICAL")
        for _ in range(1000)
    ]

    result = calculate_risk(alerts)

    assert result == {
        "risk_score": 100000,
        "risk_level": "CRITICAL",
    }
