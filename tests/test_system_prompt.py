from pathlib import Path
import json
from pocsmith.context import CveContext, FunctionFinding
from pocsmith.prompts.system_prompt import build_system_prompt, build_phase_kickoff


def _ctx() -> CveContext:
    return CveContext(
        cve_id="CVE-1", cvss=8.8, kb="KB1", title="t", description="d",
        primary_binaries=["x.dll"], deep_analysis=[
            FunctionFinding(binary="x.dll", function="F", relevance=0.9, summary="s"),
        ],
        prepatch_paths={"x.dll": "pre-patch/aa/x.dll"},
        postpatch_paths={"x.dll": "post-patch/bb/x.dll"},
        ghidriff_dir="ghidriff/",
    )


def test_includes_level_and_signal_contract():
    p = build_system_prompt(level="A", ceilings={
        "wall_min": 60, "iterations": 40, "dollars": 10, "phases": 8,
    })
    assert "Level A" in p
    assert "report_outcome" in p
    assert "kd_breakpoint_hit" in p


def test_kickoff_injects_context_and_notes(tmp_path: Path):
    ws = tmp_path / "ws"
    (ws / "attempts").mkdir(parents=True)
    (ws / "notes.md").write_text("# Notes\n- nothing yet")
    a1 = ws / "attempts" / "001"
    a1.mkdir()
    (a1 / "status.json").write_text(json.dumps({
        "attempt_id": 1, "hypothesis": "h", "outcome": "no_signal",
        "ruled_out": ["heap spray"],
    }))
    msg = build_phase_kickoff(workspace=ws, ctx=_ctx(), phase_n=2)
    assert "CVE-1" in msg
    assert "F" in msg  # deep_analysis function name
    assert "nothing yet" in msg
    assert "phase 2" in msg.lower()
    assert "heap spray" in msg


def test_kickoff_hint_included_when_provided(tmp_path: Path):
    ws = tmp_path / "ws"
    ws.mkdir()
    msg = build_phase_kickoff(workspace=ws, ctx=_ctx(), phase_n=1,
                              user_hint="Try the pool spray approach first.")
    assert "User Guidance" in msg
    assert "pool spray approach" in msg


def test_kickoff_hint_absent_when_empty(tmp_path: Path):
    ws = tmp_path / "ws"
    ws.mkdir()
    msg = build_phase_kickoff(workspace=ws, ctx=_ctx(), phase_n=1)
    assert "User Guidance" not in msg
