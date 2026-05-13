import json
from pathlib import Path
from pocsmith.report import write_artifacts


def test_writes_summary_and_verification(tmp_path: Path):
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "notes.md").write_text("# notes\n")
    write_artifacts(
        workspace=ws,
        outcome={"status": "crash_repro_success", "attempt_id": 3,
                 "signal": {"kind": "bugcheck", "code": "0x3B", "module": "ntoskrnl.exe"},
                 "notes": "kernel UAF reachable"},
        verify={"matched": True, "observation": {"reason": "bugcheck"}},
        phases_run=4, exhausted=None,
    )
    summary = (ws / "artifacts" / "summary.md").read_text()
    assert "crash_repro_success" in summary
    assert "bugcheck" in summary
    ver = json.loads((ws / "artifacts" / "verification.json").read_text())
    assert ver["matched"] is True
    assert ver["status"] == "crash_repro_success"


def test_unverified_claim_writes_with_warning(tmp_path: Path):
    ws = tmp_path / "ws"
    ws.mkdir()
    write_artifacts(
        workspace=ws,
        outcome={"status": "crash_repro_success", "attempt_id": 3,
                 "signal": {"kind": "bugcheck", "code": "0x3B", "module": "ntoskrnl.exe"},
                 "notes": "x"},
        verify={"matched": False, "observation": {}},
        phases_run=4, exhausted=None,
    )
    summary = (ws / "artifacts" / "summary.md").read_text()
    assert "unverified_claim" in summary.lower() or "did not match" in summary.lower()


def test_terminal_no_verify_writes_summary_only(tmp_path: Path):
    ws = tmp_path / "ws"
    ws.mkdir()
    write_artifacts(
        workspace=ws,
        outcome={"status": "give_up", "attempt_id": None, "signal": None,
                 "notes": "no path"},
        verify=None,
        phases_run=2, exhausted=None,
    )
    assert (ws / "artifacts" / "summary.md").exists()
    assert not (ws / "artifacts" / "verification.json").exists()
