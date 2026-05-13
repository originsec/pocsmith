from pathlib import Path
import json
from pocsmith.driver_tools.cve_context import cve_context


def test_returns_structured_view(tmp_path: Path):
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "context.json").write_text(json.dumps({
        "cve_id": "CVE-1", "cvss": 8.8, "kb": "KB1", "title": "t",
        "description": "d", "primary_binaries": ["a.dll"], "deep_analysis": [],
        "prepatch_paths": {"a.dll": "pre-patch/x/a.dll"},
        "postpatch_paths": {"a.dll": "post-patch/y/a.dll"},
        "ghidriff_dir": "ghidriff/",
    }))
    res = cve_context(ws)
    assert res["cve_id"] == "CVE-1"
    assert res["primary_binaries"] == ["a.dll"]
    assert res["prepatch_paths"]["a.dll"].endswith("a.dll")
