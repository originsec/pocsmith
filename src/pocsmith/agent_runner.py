"""Concrete Agent SDK runner implementing pocsmith.session.RunnerProtocol."""
import dataclasses
import json
import logging
import time
from pathlib import Path

from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    ResultMessage,
    SystemMessage,
    ToolUseBlock,
    query,
)

log = logging.getLogger("pocsmith.runner")


def _serialize(obj):
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {k: _serialize(v) for k, v in dataclasses.asdict(obj).items()}
    if isinstance(obj, list):
        return [_serialize(i) for i in obj]
    if isinstance(obj, dict):
        return {k: _serialize(v) for k, v in obj.items()}
    return obj


class AgentRunner:
    async def run_phase(self, *, workspace: Path, system_prompt: str,
                        kickoff: str, tools: list, hooks: dict,
                        model: str, phase_n: int = 0) -> dict:
        _start = time.monotonic()
        opts = ClaudeAgentOptions(
            system_prompt=system_prompt,
            model=model,
            cwd=str(workspace),
            mcp_servers=str(workspace / ".mcp.json"),
            allowed_tools=tools,
            hooks=hooks or None,
            permission_mode="bypassPermissions",
            setting_sources=[],  # no user/project/local settings, CLAUDE.md, or memory
            skills=None,         # no skill auto-config
        )
        attempts = 0
        tokens_in = 0
        tokens_out = 0
        terminal: dict | None = None
        phase_summary: str = ""
        done = False

        jsonl_path = workspace / "session.jsonl"
        with jsonl_path.open("a", encoding="utf-8") as jf:
            def _write(msg_type: str, data):
                record = {
                    "ts": time.time(),
                    "phase": phase_n,
                    "type": msg_type,
                    "data": _serialize(data),
                }
                jf.write(json.dumps(record, default=str) + "\n")
                jf.flush()

            sdk_error: str | None = None
            try:
                async for message in query(prompt=kickoff, options=opts):
                    if done:
                        break

                    msg_type = type(message).__name__
                    _write(msg_type, message)

                    if isinstance(message, SystemMessage) and message.subtype == "init":
                        sid = message.data.get("session_id", "")[:8]
                        mod = message.data.get("model", "?")
                        log.info("SDK session %s  phase=%d model=%s", sid, phase_n, mod)
                        log.debug("SDK session init: %s", message.data)
                    elif isinstance(message, AssistantMessage):
                        for block in message.content:
                            if not isinstance(block, ToolUseBlock):
                                continue
                            name = block.name
                            log.debug("tool_call: %s", name)
                            if name in ("record_attempt", "mcp__pocsmith__record_attempt"):
                                attempts += 1
                                log.debug("record_attempt input: %s", block.input)
                            elif name in ("report_outcome", "mcp__pocsmith__report_outcome"):
                                terminal = dict(block.input)
                                log.debug("report_outcome input: %s", block.input)
                            elif name in ("end_phase", "mcp__pocsmith__end_phase"):
                                phase_summary = block.input.get("summary", "")
                                log.info("Phase %d summary: %s", phase_n, phase_summary)
                                done = True
                                break
                    elif isinstance(message, ResultMessage):
                        usage = message.usage or {}
                        tokens_in += int(usage.get("input_tokens", 0))
                        tokens_out += int(usage.get("output_tokens", 0))
                        log.debug("ResultMessage usage: %s", usage)
            except Exception as exc:  # noqa: BLE001
                sdk_error = str(exc)
                log.error("Phase %d SDK error: %s", phase_n, sdk_error)
                _write("sdk_error", {"error": sdk_error})

        result: dict = {
            "event": "report_outcome" if terminal else "end_phase",
            "outcome": terminal,
            "phase_summary": phase_summary,
            "tokens_in": tokens_in,
            "tokens_out": tokens_out,
            "attempts": attempts,
            "elapsed_s": time.monotonic() - _start,
        }
        if sdk_error is not None:
            result["sdk_error"] = sdk_error
        return result
