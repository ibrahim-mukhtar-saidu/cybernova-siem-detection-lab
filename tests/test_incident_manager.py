import json
import logging
from pathlib import Path

import pytest

from engine.incident_manager import _next_sequence_numbers, create_incident


def test_next_sequence_numbers_zero_count_no_directory(tmp_path):
    incident_dir = tmp_path / "incidents"

    result = _next_sequence_numbers(incident_dir, 0)

    assert list(result) == []
    assert not incident_dir.exists()


def test_next_sequence_numbers_starts_at_one(tmp_path):
    incident_dir = tmp_path / "incidents"

    result = _next_sequence_numbers(incident_dir, 3)

    assert list(result) == [1, 2, 3]
    assert (incident_dir / ".sequence").read_text(encoding="utf-8") == "3"


def test_next_sequence_numbers_continues_across_calls(tmp_path):
    incident_dir = tmp_path / "incidents"

    first = list(_next_sequence_numbers(incident_dir, 2))
    second = list(_next_sequence_numbers(incident_dir, 2))

    assert first == [1, 2]
    assert second == [3, 4]


def test_next_sequence_numbers_resets_on_corrupted_sequence_file(
    tmp_path, caplog
):
    incident_dir = tmp_path / "incidents"
    incident_dir.mkdir()
    (incident_dir / ".sequence").write_text("not-a-number", encoding="utf-8")

    with caplog.at_level(logging.WARNING, logger="engine.incident_manager"):
        result = list(_next_sequence_numbers(incident_dir, 2))

    assert result == [1, 2]
    assert any("corrupted" in r.message for r in caplog.records)


def test_create_incident_empty_alerts_returns_empty_list_and_no_directory(
    tmp_path,
):
    incident_dir = tmp_path / "incidents"

    assert create_incident([], incident_dir) == []
    assert not incident_dir.exists()


def test_create_incident_writes_expected_files(tmp_path):
    incident_dir = tmp_path / "incidents"

    alerts = [
        {
            "alert_id": "ALERT-1",
            "details": {"type": "BRUTE_FORCE", "ip": "1.2.3.4"},
        },
        {
            "alert_id": "ALERT-2",
            "details": {
                "type": "SUCCESS_AFTER_FAILURES",
                "ip": "5.6.7.8",
            },
        },
    ]

    incidents = create_incident(alerts, incident_dir)

    assert [i["incident_id"] for i in incidents] == [
        "INC-001",
        "INC-002",
    ]
    assert all(i["status"] == "OPEN" for i in incidents)

    for number, alert in zip((1, 2), alerts):
        path = incident_dir / f"incident_{number:03}.json"
        assert path.exists()

        saved = json.loads(path.read_text(encoding="utf-8"))

        assert saved["alert"] == alert
        assert saved["incident_id"] == f"INC-{number:03}"


def test_create_incident_does_not_overwrite_previous_run(tmp_path):
    incident_dir = tmp_path / "incidents"

    first_alerts = [
        {
            "alert_id": "A1",
            "details": {"type": "BRUTE_FORCE"},
        }
    ]

    second_alerts = [
        {
            "alert_id": "A2",
            "details": {"type": "SUCCESS_AFTER_FAILURES"},
        }
    ]

    first_incidents = create_incident(first_alerts, incident_dir)
    second_incidents = create_incident(second_alerts, incident_dir)

    assert [i["incident_id"] for i in first_incidents] == ["INC-001"]
    assert [i["incident_id"] for i in second_incidents] == ["INC-002"]

    first_saved = json.loads(
        (incident_dir / "incident_001.json").read_text(encoding="utf-8")
    )
    assert first_saved["alert"] == first_alerts[0]

    second_saved = json.loads(
        (incident_dir / "incident_002.json").read_text(encoding="utf-8")
    )
    assert second_saved["alert"] == second_alerts[0]


def test_create_incident_propagates_permission_error(tmp_path, monkeypatch):
    incident_dir = tmp_path / "incidents"
    alerts = [
        {
            "alert_id": "A1",
            "details": {"type": "BRUTE_FORCE"},
        }
    ]

    original_open = Path.open

    def raising_open(self, *args, **kwargs):
        if self.suffix == ".json" and self.name.startswith("incident_"):
            raise PermissionError("denied")
        return original_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", raising_open)

    with pytest.raises(PermissionError):
        create_incident(alerts, incident_dir)


def test_create_incident_handles_large_incident_numbers(tmp_path):
    incident_dir = tmp_path / "incidents"
    incident_dir.mkdir()

    (incident_dir / ".sequence").write_text(
        "999",
        encoding="utf-8",
    )

    alerts = [
        {
            "alert_id": "A1",
            "details": {"type": "BRUTE_FORCE"},
        }
    ]

    incidents = create_incident(alerts, incident_dir)

    assert incidents[0]["incident_id"] == "INC-1000"
    assert (incident_dir / "incident_1000.json").exists()


def test_create_incident_default_directory_argument_is_a_path(
    tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)

    alerts = [
        {
            "alert_id": "A1",
            "details": {"type": "BRUTE_FORCE"},
        }
    ]

    incidents = create_incident(alerts)

    assert incidents[0]["incident_id"] == "INC-001"
    assert (
        tmp_path / "incidents" / "incident_001.json"
    ).exists()
