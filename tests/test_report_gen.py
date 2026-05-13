"""Unit tests for pocsmith.report_gen."""
from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

import pocsmith.report_gen as rg


# ---------------------------------------------------------------------------
# collect_workspace_data
# ---------------------------------------------------------------------------


def test_collect_workspace_data_happy_path(tmp_path: Path):
    """Text file is read, binary file is silently skipped."""
    context = {"cve_id": "CVE-2025-0001", "title": "Test Vuln"}
    outcome = {
        "status": "crash_repro_success",
        "notes": (
            "Full reproduction artifacts in poc/:\n"
            "- evil.c / evil.dll - payload DLL\n"
        ),
    }

    (tmp_path / "context.json").write_text(json.dumps(context), encoding="utf-8")
    (tmp_path / "outcome.json").write_text(json.dumps(outcome), encoding="utf-8")
    (tmp_path / "notes.md").write_text("## researcher notes\n", encoding="utf-8")
    (tmp_path / "cve.md").write_text("# CVE details\n", encoding="utf-8")

    poc_dir = tmp_path / "poc"
    poc_dir.mkdir()
    (poc_dir / "evil.c").write_text("int main() { return 0; }", encoding="utf-8")
    (poc_dir / "evil.dll").write_bytes(b"\x4d\x5a\x90\x00")

    data = rg.collect_workspace_data(tmp_path)

    assert isinstance(data["context"], dict)
    assert isinstance(data["outcome"], dict)
    assert isinstance(data["notes"], str)

    assert "evil.c" in data["poc_files"], "text file should be collected"
    assert "evil.dll" not in data["poc_files"], "binary file should be skipped"


def test_collect_workspace_data_missing_poc_file(tmp_path: Path):
    """A referenced file that doesn't exist lands in missing_poc_files."""
    outcome = {
        "status": "ok",
        "notes": "poc/deploy.ps1 - deployment script\n- deploy.ps1 - script\n",
    }
    (tmp_path / "outcome.json").write_text(json.dumps(outcome), encoding="utf-8")

    poc_dir = tmp_path / "poc"
    poc_dir.mkdir()
    # deploy.ps1 intentionally NOT created

    data = rg.collect_workspace_data(tmp_path)

    assert "deploy.ps1" in data["missing_poc_files"]
    # FIX 3: also assert the file was not accidentally included in poc_files
    assert "deploy.ps1" not in data["poc_files"]


def test_collect_workspace_data_empty_workspace(tmp_path: Path):
    """No workspace files at all -- should return an all-keys dict without raising."""
    data = rg.collect_workspace_data(tmp_path)

    for key in ("context", "outcome", "notes", "cve_md", "poc_files", "missing_poc_files"):
        assert key in data, f"expected key '{key}' missing from result"

    assert data["context"] == {}
    assert data["outcome"] == {}
    assert data["notes"] == ""
    assert data["poc_files"] == {}
    assert data["missing_poc_files"] == []


def test_collect_workspace_data_windows_backslash_in_notes(tmp_path: Path):
    """poc\\exploit.c (Windows-style path) should resolve to exploit.c."""
    outcome = {
        "status": "ok",
        "notes": "Artifacts: poc\\exploit.c\n",
    }
    (tmp_path / "outcome.json").write_text(json.dumps(outcome), encoding="utf-8")

    poc_dir = tmp_path / "poc"
    poc_dir.mkdir()
    (poc_dir / "exploit.c").write_text("// exploit\n", encoding="utf-8")

    data = rg.collect_workspace_data(tmp_path)

    assert "exploit.c" in data["poc_files"], (
        "Windows-style backslash path should be resolved to the base filename"
    )


def test_collect_workspace_data_bad_context_json(tmp_path: Path):
    """Malformed context.json raises ValueError mentioning context.json."""
    (tmp_path / "context.json").write_text("{bad json!!!", encoding="utf-8")

    with pytest.raises(ValueError, match="context.json"):
        rg.collect_workspace_data(tmp_path)


# ---------------------------------------------------------------------------
# call_claude_for_report
# ---------------------------------------------------------------------------


def test_call_claude_no_api_key(monkeypatch):
    """Missing ANTHROPIC_API_KEY raises RuntimeError."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    with pytest.raises(RuntimeError, match="ANTHROPIC_API_KEY not set"):
        rg.call_claude_for_report({"context": {}, "outcome": {}}, model="claude-test")


def test_call_claude_mocked_success(monkeypatch):
    """Mocked client returns expected text and receives the correct model argument."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-fake")

    fake_block = SimpleNamespace(type="text", text="# Report\nHello")
    fake_response = SimpleNamespace(content=[fake_block], stop_reason="end_turn")

    # FIX 4: capture kwargs passed to create() to assert model and messages are forwarded
    captured: dict = {}

    class FakeMessages:
        def create(self, **kwargs):
            captured.update(kwargs)
            return fake_response

    class FakeClient:
        messages = FakeMessages()

    import anthropic
    monkeypatch.setattr(anthropic, "Anthropic", lambda: FakeClient())

    data = {
        "context": {"cve_id": "CVE-2025-1234", "title": "Test"},
        "outcome": {"status": "ok"},
        "notes": "",
        "cve_md": "",
        "poc_files": {},
        "missing_poc_files": [],
    }

    result = rg.call_claude_for_report(data, model="claude-test")
    assert result == "# Report\nHello"

    # Verify the model and messages were forwarded to the API
    assert captured.get("model") == "claude-test"
    assert "messages" in captured


def test_call_claude_empty_content_raises(monkeypatch):
    """Empty content list raises RuntimeError containing both 'no text content' and the stop_reason."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-fake")

    fake_response = SimpleNamespace(content=[], stop_reason="max_tokens")

    class FakeMessages:
        def create(self, **kwargs):
            return fake_response

    class FakeClient:
        messages = FakeMessages()

    import anthropic
    monkeypatch.setattr(anthropic, "Anthropic", lambda: FakeClient())

    data = {
        "context": {},
        "outcome": {},
        "notes": "",
        "cve_md": "",
        "poc_files": {},
        "missing_poc_files": [],
    }

    # FIX 1: use exc_info pattern so both the generic message and the stop_reason
    # value are asserted -- confirming stop_reason is included in the error text.
    with pytest.raises(RuntimeError) as exc_info:
        rg.call_claude_for_report(data, model="claude-test")
    assert "no text content" in str(exc_info.value)
    assert "max_tokens" in str(exc_info.value)


def test_call_claude_braces_in_title_no_keyerror(monkeypatch):
    """Curly braces in title should NOT trigger KeyError via .format()."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-fake")

    fake_block = SimpleNamespace(type="text", text="# Report\nOK")
    fake_response = SimpleNamespace(content=[fake_block], stop_reason="end_turn")

    class FakeMessages:
        def create(self, **kwargs):
            return fake_response

    class FakeClient:
        messages = FakeMessages()

    import anthropic
    monkeypatch.setattr(anthropic, "Anthropic", lambda: FakeClient())

    data = {
        "context": {"cve_id": "CVE-2025-9999", "title": "Use-After-Free {UAF}"},
        "outcome": {"status": "ok"},
        "notes": "",
        "cve_md": "",
        "poc_files": {},
        "missing_poc_files": [],
    }

    # Should not raise KeyError
    result = rg.call_claude_for_report(data, model="claude-test")
    assert result == "# Report\nOK"


# ---------------------------------------------------------------------------
# write_report_artifacts
# ---------------------------------------------------------------------------


def test_write_report_artifacts_writes_report_md(tmp_path: Path):
    """report.md is written inside artifacts/."""
    rg.write_report_artifacts(tmp_path, "# Hello", {"poc_files": {}, "missing_poc_files": []})

    report_path = tmp_path / "artifacts" / "report.md"
    assert report_path.exists()
    assert "# Hello" in report_path.read_text(encoding="utf-8")


def test_write_report_artifacts_copies_poc_files(tmp_path: Path):
    """POC source file is copied into artifacts/poc/."""
    poc_dir = tmp_path / "poc"
    poc_dir.mkdir()
    (poc_dir / "evil.c").write_text("int main() {}", encoding="utf-8")

    data = {
        "poc_files": {"evil.c": "int main() {}"},
        "missing_poc_files": [],
    }

    rg.write_report_artifacts(tmp_path, "# Report", data)

    copied = tmp_path / "artifacts" / "poc" / "evil.c"
    assert copied.exists(), "evil.c should be copied to artifacts/poc/"


def test_write_report_artifacts_skips_missing_files(tmp_path: Path):
    """Files in missing_poc_files are not copied; no error is raised."""
    # poc/gone.c does NOT exist on disk
    data = {
        "poc_files": {"gone.c": "..."},
        "missing_poc_files": ["gone.c"],
    }

    # Should complete without raising
    rg.write_report_artifacts(tmp_path, "# Report", data)

    # FIX 2: unconditional assertion -- the file must not exist regardless of
    # whether the directory was created.
    artifacts_poc = tmp_path / "artifacts" / "poc"
    assert not (artifacts_poc / "gone.c").exists()


# ---------------------------------------------------------------------------
# generate_report
# ---------------------------------------------------------------------------


def test_generate_report_skips_on_no_api_key(tmp_path: Path, monkeypatch):
    """No API key causes generate_report to skip silently -- no report.md written."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    # Provide minimal valid workspace so collect_workspace_data won't error
    (tmp_path / "context.json").write_text(json.dumps({}), encoding="utf-8")
    (tmp_path / "outcome.json").write_text(json.dumps({}), encoding="utf-8")

    rg.generate_report(tmp_path)

    assert not (tmp_path / "artifacts" / "report.md").exists()


def test_generate_report_writes_error_stub_on_api_failure(tmp_path: Path, monkeypatch):
    """Non-RuntimeError from call_claude writes a 'Report generation failed' stub."""
    monkeypatch.setattr(
        rg,
        "call_claude_for_report",
        lambda data, model: (_ for _ in ()).throw(Exception("network error")),
    )

    rg.generate_report(tmp_path)

    report_path = tmp_path / "artifacts" / "report.md"
    assert report_path.exists()
    assert "Report generation failed" in report_path.read_text(encoding="utf-8")


def test_generate_report_full_success(tmp_path: Path, monkeypatch):
    """Successful call writes the returned markdown to artifacts/report.md."""
    (tmp_path / "context.json").write_text(json.dumps({"cve_id": "CVE-2025-0001"}), encoding="utf-8")
    (tmp_path / "outcome.json").write_text(json.dumps({"status": "ok", "notes": ""}), encoding="utf-8")

    monkeypatch.setattr(
        rg,
        "call_claude_for_report",
        lambda data, model: "# Full Report",
    )

    rg.generate_report(tmp_path)

    report_path = tmp_path / "artifacts" / "report.md"
    assert report_path.exists()
    assert "# Full Report" in report_path.read_text(encoding="utf-8")
