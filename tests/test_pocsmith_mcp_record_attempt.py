"""Tests for the record_attempt MCP wrapper, including recovery from
JSON/XML tool-call format drift the agent occasionally emits."""
import json
from pathlib import Path

import pytest

from pocsmith.pocsmith_mcp import _strip_xml_drift, record_attempt


# ---------------------------------------------------------------------------
# _strip_xml_drift unit tests
# ---------------------------------------------------------------------------


def test_strip_xml_drift_clean_string():
    cleaned, recovered = _strip_xml_drift("just a normal hypothesis sentence.")
    assert cleaned == "just a normal hypothesis sentence."
    assert recovered == {}


def test_strip_xml_drift_recovers_single_embedded_arg():
    val = (
        "XSL injection in StringTable would auto-fire JScript.</hypothesis>\n"
        '<parameter name="poc_path">poc/grimresource.msc'
    )
    cleaned, recovered = _strip_xml_drift(val)
    assert cleaned == "XSL injection in StringTable would auto-fire JScript."
    assert recovered == {"poc_path": "poc/grimresource.msc"}


def test_strip_xml_drift_recovers_chained_args():
    val = (
        "kd output summary.</kd_observations>\n"
        '<parameter name="outcome">no_trigger</parameter>\n'
        '<parameter name="ruled_out">["x"]</parameter>'
    )
    cleaned, recovered = _strip_xml_drift(val)
    assert cleaned == "kd output summary."
    assert recovered == {"outcome": "no_trigger", "ruled_out": '["x"]'}


def test_strip_xml_drift_handles_no_close_tag():
    val = 'some text <parameter name="outcome">triggered'
    cleaned, recovered = _strip_xml_drift(val)
    assert cleaned == "some text"
    assert recovered == {"outcome": "triggered"}


# ---------------------------------------------------------------------------
# record_attempt wrapper tests (full path with recovery)
# ---------------------------------------------------------------------------


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    ws = tmp_path / "ws"
    (ws / "attempts").mkdir(parents=True)
    monkeypatch.setenv("POCSMITH_WORKSPACE", str(ws))
    return ws


def test_clean_call_succeeds(workspace: Path):
    aid = record_attempt(
        outcome="no_trigger",
        poc_path="poc/a.msc",
        deploy_to="C:/Users/x/Downloads/a.msc",
        invocation={"command": "mmc.exe", "args": ["a.msc"], "cwd": "C:/"},
        ruled_out=["claim x"],
        hypothesis="hypothesis text",
        kd_observations="kd output",
    )
    assert aid == 1
    s = json.loads((workspace / "attempts/001/status.json").read_text())
    assert s["outcome"] == "no_trigger"
    assert s["hypothesis"] == "hypothesis text"


def test_recovers_from_xml_drift_in_hypothesis(workspace: Path):
    """Reproduces the exact failure mode from CVE-2026-27914 session log
    line 77: poc_path and outcome embedded as XML inside hypothesis and
    kd_observations respectively."""
    aid = record_attempt(
        hypothesis=(
            "XSL injection would auto-fire JScript on document open."
            '</hypothesis>\n<parameter name="poc_path">poc/grimresource.msc'
        ),
        deploy_to="C:/Users/x/Downloads/grimresource.msc",
        invocation={"command": "mmc.exe", "args": [], "cwd": "C:/"},
        kd_observations=(
            "mmc.exe loaded file, no child processes spawned."
            '</kd_observations>\n<parameter name="outcome">no_trigger'
        ),
        ruled_out=["msxsl:script auto-fires on .msc open"],
    )
    assert aid == 1
    s = json.loads((workspace / "attempts/001/status.json").read_text())
    assert s["poc_path"] == "poc/grimresource.msc"
    assert s["outcome"] == "no_trigger"
    assert s["hypothesis"] == "XSL injection would auto-fire JScript on document open."
    assert s["kd_observations"] == "mmc.exe loaded file, no child processes spawned."


def test_missing_required_field_raises_clear_error(workspace: Path):
    with pytest.raises(ValueError, match="missing required fields"):
        record_attempt(
            outcome="no_trigger",
            poc_path="poc/a.msc",
            deploy_to="C:/x/a.msc",
            invocation={"command": "mmc.exe", "args": [], "cwd": "C:/"},
            ruled_out=[],
            hypothesis="h",
        )


def test_recovery_does_not_overwrite_existing_arg(workspace: Path):
    """If outcome is already provided, an XML-embedded outcome in another
    string field must not clobber it."""
    aid = record_attempt(
        outcome="triggered",
        poc_path="poc/a.msc",
        deploy_to="C:/x/a.msc",
        invocation={"command": "mmc.exe", "args": [], "cwd": "C:/"},
        ruled_out=[],
        hypothesis="h",
        kd_observations='kd</kd_observations>\n<parameter name="outcome">no_trigger',
    )
    s = json.loads((workspace / "attempts/001/status.json").read_text())
    assert s["outcome"] == "triggered"
    assert aid == 1
