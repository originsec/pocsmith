import json
from pathlib import Path
import pytest
from pocsmith.driver_tools.report_outcome import report_outcome, ReportOutcomeError


def test_crash_repro_requires_signal_and_attempt(tmp_path: Path):
    with pytest.raises(ReportOutcomeError):
        report_outcome(tmp_path, status="crash_repro_success", attempt_id=None,
                       signal=None, notes="found it")


def test_crash_repro_returns_replay_directive(tmp_path: Path):
    res = report_outcome(tmp_path, status="crash_repro_success", attempt_id=3,
                         signal={"kind": "bugcheck", "code": "0x3B", "module": "ntoskrnl.exe"},
                         notes="kernel UAF reachable")
    assert res["action"] == "replay_verify"
    assert res["attempt_id"] == 3
    assert res["signal"]["kind"] == "bugcheck"


def test_give_up_short_circuits(tmp_path: Path):
    res = report_outcome(tmp_path, status="give_up", attempt_id=None,
                         signal=None, notes="no path found")
    assert res["action"] == "terminate"
    assert res["status"] == "give_up"


def test_persists_outcome(tmp_path: Path):
    report_outcome(tmp_path, status="give_up", attempt_id=None,
                   signal=None, notes="x")
    assert (tmp_path / "outcome.json").exists()
    saved = json.loads((tmp_path / "outcome.json").read_text())
    assert saved["status"] == "give_up"
