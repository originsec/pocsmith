from pathlib import Path
import json
from pocsmith.resume import resume_workspace
from pocsmith.workspace import prepare_workspace, release_lock


def _seed(tmp_path: Path) -> Path:
    src = tmp_path / "export" / "CVE-1"
    src.mkdir(parents=True)
    (src / "cve.md").write_text("# r")
    (src / "context.json").write_text(json.dumps({
        "cve_id": "CVE-1", "cvss": 1.0, "kb": "KB1", "title": "t", "description": "d",
        "primary_binaries": ["x.dll"], "deep_analysis": [],
        "prepatch_paths": {}, "postpatch_paths": {}, "ghidriff_dir": "ghidriff/",
    }))
    return src.parent


def test_resume_re_locks_existing_workspace(tmp_path: Path):
    export = _seed(tmp_path)
    work = tmp_path / "work"
    ws = prepare_workspace(export / "CVE-1", work)
    release_lock(ws)
    ws2 = resume_workspace(work, "CVE-1")
    assert ws2.path == work / "CVE-1"
    assert (ws2.path / "pocsmith-run.lock").exists()
