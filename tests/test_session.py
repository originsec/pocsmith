from pathlib import Path
import json
import pytest
from pocsmith.session import run_session, SessionResult, RunnerProtocol


class ScriptedRunner(RunnerProtocol):
    def __init__(self, script: list[dict]):
        self.script = list(script)
        self.calls: list[tuple] = []

    async def run_phase(self, *, workspace, system_prompt, kickoff,
                        tools, hooks, model, phase_n: int = 0):
        if not self.script:
            return {"event": "end_phase", "tokens_in": 0, "tokens_out": 0,
                    "attempts": 0, "elapsed_s": 0}
        return self.script.pop(0)


@pytest.mark.asyncio
async def test_terminal_report_outcome_short_circuits(tmp_path: Path):
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "context.json").write_text(json.dumps({
        "cve_id": "CVE-1", "cvss": 1.0, "kb": "KB1", "title": "t", "description": "d",
        "primary_binaries": ["x.dll"], "deep_analysis": [],
        "prepatch_paths": {}, "postpatch_paths": {}, "ghidriff_dir": "ghidriff/",
    }))
    runner = ScriptedRunner([
        {"event": "report_outcome", "outcome": {"action": "terminate", "status": "give_up"},
         "tokens_in": 100, "tokens_out": 50, "attempts": 1, "elapsed_s": 5},
    ])
    res = await run_session(workspace=ws, level="A", runner=runner,
                            ceilings={"wall_min": 60, "iterations": 40,
                                      "dollars": 10, "phases": 8},
                            model="claude-opus-4-7")
    assert isinstance(res, SessionResult)
    assert res.terminal["status"] == "give_up"
    assert res.phases_run == 1


@pytest.mark.asyncio
async def test_phase_loop_advances_until_terminal(tmp_path: Path):
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "context.json").write_text(json.dumps({
        "cve_id": "CVE-1", "cvss": 1.0, "kb": "KB1", "title": "t", "description": "d",
        "primary_binaries": ["x.dll"], "deep_analysis": [],
        "prepatch_paths": {}, "postpatch_paths": {}, "ghidriff_dir": "ghidriff/",
    }))
    runner = ScriptedRunner([
        {"event": "end_phase", "tokens_in": 1000, "tokens_out": 500,
         "attempts": 5, "elapsed_s": 60},
        {"event": "end_phase", "tokens_in": 1000, "tokens_out": 500,
         "attempts": 5, "elapsed_s": 60},
        {"event": "report_outcome",
         "outcome": {"action": "terminate", "status": "give_up"},
         "tokens_in": 500, "tokens_out": 200, "attempts": 0, "elapsed_s": 30},
    ])
    res = await run_session(workspace=ws, level="A", runner=runner,
                            ceilings={"wall_min": 60, "iterations": 40,
                                      "dollars": 10, "phases": 8},
                            model="claude-opus-4-7")
    assert res.phases_run == 3


@pytest.mark.asyncio
async def test_budget_exhaustion_stops(tmp_path: Path):
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "context.json").write_text(json.dumps({
        "cve_id": "CVE-1", "cvss": 1.0, "kb": "KB1", "title": "t", "description": "d",
        "primary_binaries": ["x.dll"], "deep_analysis": [],
        "prepatch_paths": {}, "postpatch_paths": {}, "ghidriff_dir": "ghidriff/",
    }))
    runner = ScriptedRunner([
        {"event": "end_phase", "tokens_in": 0, "tokens_out": 0,
         "attempts": 40, "elapsed_s": 0},  # exhausts iterations
        {"event": "end_phase", "tokens_in": 0, "tokens_out": 0,
         "attempts": 0, "elapsed_s": 0},  # should NOT be reached
    ])
    res = await run_session(workspace=ws, level="A", runner=runner,
                            ceilings={"wall_min": 60, "iterations": 40,
                                      "dollars": 10, "phases": 8},
                            model="claude-opus-4-7")
    assert res.exhausted == "iterations"
    assert res.phases_run == 1
