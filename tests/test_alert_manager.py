from datetime import datetime

from engine.alert_manager import create_alert, process_alerts


def test_create_alert_wraps_details():
    details = {"type": "BRUTE_FORCE", "ip": "1.2.3.4"}

    alert = create_alert(details)

    assert alert["details"] == details
    assert alert["alert_id"].startswith("ALERT-")
    datetime.fromisoformat(alert["created"])


def test_create_alert_ids_are_unique():
    ids = {create_alert({"type": "X"})["alert_id"] for _ in range(1000)}

    assert len(ids) == 1000


def test_create_alert_does_not_mutate_input():
    details = {"type": "BRUTE_FORCE"}

    create_alert(details)

    assert details == {"type": "BRUTE_FORCE"}


def test_process_alerts_empty_list():
    assert process_alerts([]) == []


def test_process_alerts_preserves_order_and_count():
    raw_alerts = [{"type": f"ALERT_{i}"} for i in range(5)]

    processed = process_alerts(raw_alerts)

    assert len(processed) == 5
    assert [a["details"]["type"] for a in processed] == [
        f"ALERT_{i}" for i in range(5)
    ]


def test_process_alerts_assigns_distinct_ids():
    raw_alerts = [{"type": "BRUTE_FORCE"} for _ in range(50)]

    processed = process_alerts(raw_alerts)

    ids = {a["alert_id"] for a in processed}
    assert len(ids) == 50
