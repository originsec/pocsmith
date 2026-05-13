"""Driver tool: end the current phase, persist updated notes.md."""
from pathlib import Path
import json
import time


def end_phase(workspace: Path, *, summary: str, updated_notes: str) -> dict:
    ws = Path(workspace)
    (ws / "notes.md").write_text(updated_notes, encoding="utf-8")
    (ws / "transcripts").mkdir(exist_ok=True)
    line = json.dumps({"ts": int(time.time()), "summary": summary})
    with (ws / "transcripts" / "phase-summary.jsonl").open("a", encoding="utf-8") as f:
        f.write(line + "\n")
    return {"closed": True}
