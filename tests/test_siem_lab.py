import runpy
from pathlib import Path

import pytest

import siem_lab_v2

REPO_ROOT = Path(__file__).resolve().parents[1]
SIEM_LAB_PATH = REPO_ROOT / "siem_lab.py"


def test_deprecated_wrapper_delegates_and_prints_notice(
    monkeypatch,
    capsys,
):
    monkeypatch.setattr(
        siem_lab_v2,
        "main",
        lambda: 0,
    )

    with pytest.raises(SystemExit) as exc_info:
        runpy.run_path(
            str(SIEM_LAB_PATH),
            run_name="__main__",
        )

    assert exc_info.value.code == 0

    output = capsys.readouterr().out

    assert "deprecated" in output.lower()


def test_deprecated_wrapper_propagates_nonzero_exit_code(
    monkeypatch,
):
    monkeypatch.setattr(
        siem_lab_v2,
        "main",
        lambda: 1,
    )

    with pytest.raises(SystemExit) as exc_info:
        runpy.run_path(
            str(SIEM_LAB_PATH),
            run_name="__main__",
        )

    assert exc_info.value.code == 1
