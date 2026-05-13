from pathlib import Path
import json
import pytest
from pocsmith.workspace import prepare_workspace, WorkspaceLockError, symbol_path_for, release_lock


def _make_export(tmp_path: Path, cve: str = "CVE-1") -> Path:
    src = tmp_path / "export" / cve
    src.mkdir(parents=True)
    (src / "cve.md").write_text("# r")
    (src / "context.json").write_text(json.dumps({
        "cve_id": cve, "cvss": 1.0, "kb": "KB1", "title": "t", "description": "d",
        "primary_binaries": ["x.dll"], "deep_analysis": [],
        "prepatch_paths": {"x.dll": "pre-patch/aa/x.dll"},
        "postpatch_paths": {"x.dll": "post-patch/bb/x.dll"},
        "ghidriff_dir": "ghidriff/",
    }))
    (src / "pre-patch/aa").mkdir(parents=True)
    (src / "pre-patch/aa/x.dll").write_bytes(b"PE")
    (src / "post-patch/bb").mkdir(parents=True)
    (src / "post-patch/bb/x.dll").write_bytes(b"PE2")
    (src / "ghidriff").mkdir()
    (src / "ghidriff/x.md").write_text("diff")
    return src


def test_prepares_layout(tmp_path: Path):
    src = _make_export(tmp_path)
    ws_root = tmp_path / "work"
    ws = prepare_workspace(src, ws_root)
    assert ws.path == ws_root / "CVE-1"
    for f in ("cve.md", "context.json", "pre-patch/aa/x.dll",
              "ghidriff/x.md", "notes.md", "pocsmith-run.lock"):
        assert (ws.path / f).exists(), f
    for d in ("attempts", "transcripts", "poc", "symbols"):
        assert (ws.path / d).is_dir(), d


def test_lock_prevents_concurrent(tmp_path: Path):
    src = _make_export(tmp_path)
    ws_root = tmp_path / "work"
    prepare_workspace(src, ws_root)
    with pytest.raises(WorkspaceLockError):
        prepare_workspace(src, ws_root)


def test_release_lock_allows_resume(tmp_path: Path):
    src = _make_export(tmp_path)
    ws_root = tmp_path / "work"
    ws = prepare_workspace(src, ws_root)
    release_lock(ws)
    ws2 = prepare_workspace(src, ws_root)
    assert ws2.path == ws.path


def test_symbol_path_for(tmp_path: Path):
    sp = symbol_path_for(tmp_path / "ws")
    assert sp.startswith("srv*") and "msdl.microsoft.com" in sp
    assert str(tmp_path / "ws" / "symbols") in sp
