from pathlib import Path
from pocsmith.driver_tools.end_phase import end_phase


def test_writes_notes_and_summary(tmp_path: Path):
    ws = tmp_path / "ws"
    (ws / "transcripts").mkdir(parents=True)
    res = end_phase(ws, summary="ruled out heap spray", updated_notes="# Notes\n- tried x")
    assert res["closed"] is True
    assert (ws / "notes.md").read_text() == "# Notes\n- tried x"
    summary_file = ws / "transcripts" / "phase-summary.jsonl"
    assert summary_file.exists()
    line = summary_file.read_text().splitlines()[-1]
    assert "ruled out heap spray" in line
