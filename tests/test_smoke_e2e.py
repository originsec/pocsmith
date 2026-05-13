import json
from pathlib import Path
from typer.testing import CliRunner
from pocsmith.cli import app


def test_e2e_run_writes_outcome(tmp_path: Path):
    ws_root = tmp_path / "work"
    cve_dir = ws_root / "CVE-E"
    cve_dir.mkdir(parents=True)
    (cve_dir / "cve.md").write_text("# r")
    (cve_dir / "context.json").write_text(json.dumps({
        "cve_id": "CVE-E", "cvss": 1.0, "kb": "KB1", "title": "t",
        "description": "d", "primary_binaries": [], "deep_analysis": [],
        "prepatch_paths": {}, "postpatch_paths": {}, "ghidriff_dir": "ghidriff/",
    }))
    runner = CliRunner()
    res = runner.invoke(app, [
        "run", "--cve", "CVE-E", "--level", "A",
        "--workspace-root", str(ws_root),
    ], env={"POCSMITH_FAKE_RUNNER": "1"})
    assert res.exit_code == 0, res.stdout
    assert cve_dir.exists()
