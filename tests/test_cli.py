from pathlib import Path
import json
from typer.testing import CliRunner
from pocsmith.cli import app


def _seed_workspace(ws_root: Path, cve_id: str = "CVE-1") -> Path:
    src = ws_root / cve_id
    src.mkdir(parents=True)
    (src / "cve.md").write_text("# r")
    (src / "context.json").write_text(json.dumps({
        "cve_id": cve_id, "cvss": 1.0, "kb": "KB1", "title": "t", "description": "d",
        "primary_binaries": ["x.dll"], "deep_analysis": [],
        "prepatch_paths": {}, "postpatch_paths": {}, "ghidriff_dir": "ghidriff/",
    }))
    return ws_root


def test_run_smoke(tmp_path: Path, monkeypatch):
    ws_root = _seed_workspace(tmp_path / "work")
    monkeypatch.setenv("POCSMITH_FAKE_RUNNER", "1")
    runner = CliRunner()
    result = runner.invoke(app, [
        "run",
        "--cve", "CVE-1",
        "--level", "A",
        "--workspace-root", str(ws_root),
    ])
    assert result.exit_code == 0, result.stdout
    assert (ws_root / "CVE-1" / "context.json").exists()


def test_run_skip_build_check_bypasses_preflight(tmp_path: Path, monkeypatch):
    ws_root = _seed_workspace(tmp_path / "work")
    monkeypatch.setenv("POCSMITH_FAKE_RUNNER", "1")

    def _boom(*a, **kw):
        raise AssertionError("check_vm_build must not be called when --skip-build-check is set")

    monkeypatch.setattr("pocsmith.cli.check_vm_build", _boom)

    runner = CliRunner()
    result = runner.invoke(app, [
        "run",
        "--cve", "CVE-1",
        "--level", "A",
        "--workspace-root", str(ws_root),
        "--vm-name", "some-vm",
        "--skip-build-check",
    ])
    assert result.exit_code == 0, result.stdout
    assert "--skip-build-check set" in result.stdout or "--skip-build-check set" in (result.stderr or "")


def test_inspect_lists(tmp_path: Path):
    ws_root = _seed_workspace(tmp_path / "work")
    runner = CliRunner()
    runner.invoke(app, [
        "run", "--cve", "CVE-1", "--level", "A",
        "--workspace-root", str(ws_root),
    ], env={"POCSMITH_FAKE_RUNNER": "1"})
    result = runner.invoke(app, [
        "inspect", "--workspace-root", str(ws_root),
    ])
    assert result.exit_code == 0
    assert "CVE-1" in result.stdout
