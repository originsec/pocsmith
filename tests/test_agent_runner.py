from pathlib import Path
from unittest.mock import patch

import pytest
from claude_agent_sdk import AssistantMessage, ResultMessage, ToolUseBlock


def _tool_block(name: str, input: dict) -> ToolUseBlock:
    return ToolUseBlock(id=f"tu_{name}", name=name, input=input)


def _assistant(*blocks: ToolUseBlock) -> AssistantMessage:
    return AssistantMessage(content=list(blocks), model="claude-opus-4-7")


def _result(input_tokens: int, output_tokens: int) -> ResultMessage:
    return ResultMessage(
        subtype="success",
        duration_ms=0,
        duration_api_ms=0,
        is_error=False,
        num_turns=1,
        session_id="test",
        usage={"input_tokens": input_tokens, "output_tokens": output_tokens},
    )


@pytest.mark.asyncio
async def test_runner_detects_report_outcome(tmp_path: Path):
    from pocsmith.agent_runner import AgentRunner

    messages = [
        _assistant(_tool_block("record_attempt", {"attempt_id": 1})),
        _assistant(_tool_block("report_outcome", {
            "action": "terminate", "status": "give_up",
            "attempt_id": None, "signal": None, "notes": "x",
        })),
        _result(input_tokens=100, output_tokens=50),
    ]

    async def fake_query(prompt, options):
        for m in messages:
            yield m

    with patch("pocsmith.agent_runner.query", fake_query):
        runner = AgentRunner()
        out = await runner.run_phase(
            workspace=tmp_path, system_prompt="sys", kickoff="kick",
            tools=[], hooks={}, model="claude-opus-4-7",
        )

    assert out["event"] == "report_outcome"
    assert out["outcome"]["status"] == "give_up"
    assert out["attempts"] == 1
    assert out["tokens_in"] == 100 and out["tokens_out"] == 50


@pytest.mark.asyncio
async def test_runner_sets_max_buffer_size(tmp_path: Path):
    from pocsmith.agent_runner import _MAX_BUFFER_SIZE, AgentRunner

    captured: dict = {}

    async def fake_query(prompt, options):
        captured["options"] = options
        return
        yield  # pragma: no cover - generator marker

    with patch("pocsmith.agent_runner.query", fake_query):
        runner = AgentRunner()
        await runner.run_phase(
            workspace=tmp_path, system_prompt="sys", kickoff="kick",
            tools=[], hooks={}, model="claude-opus-4-7",
        )

    assert captured["options"].max_buffer_size == _MAX_BUFFER_SIZE
    assert _MAX_BUFFER_SIZE > 1024 * 1024
