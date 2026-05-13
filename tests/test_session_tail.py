"""Tests for pocsmith.session_tail.

Renders records using the same shape that agent_runner.AgentRunner.run_phase
writes to session.jsonl, then asserts that the textual output names tool calls,
results, assistant text, and SDK errors correctly.
"""
from __future__ import annotations

import io
import json
import re

from pocsmith.session_tail import (
    SessionTailer,
    fmt_tool_input,
    truncate_text,
)


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _strip_ansi(s: str) -> str:
    return _ANSI_RE.sub("", s)


def _record(ts: float, rtype: str, data: dict, phase: int = 1) -> str:
    return json.dumps({"ts": ts, "phase": phase, "type": rtype, "data": data}) + "\n"


def test_truncate_text_chars():
    out = truncate_text("a" * 100, max_chars=10, max_lines=10)
    assert out.startswith("aaaaaaaaaa")
    assert "[+90 chars]" in out


def test_truncate_text_lines():
    out = truncate_text("\n".join(str(i) for i in range(20)), max_chars=1000, max_lines=5)
    assert "0\n1\n2\n3\n4" in out
    assert "[+15 more lines]" in out


def test_fmt_tool_input_compact():
    s = fmt_tool_input({"cmd": "ls -la", "n": 3, "opts": {"a": 1}})
    assert "cmd='ls -la'" in s
    assert "n=3" in s
    assert 'opts={"a":1}' in s


def test_fmt_tool_input_truncates_long_string():
    s = fmt_tool_input({"x": "a" * 200})
    assert s.endswith("...'") or s.endswith("...")
    assert len(s) <= 220


def test_tail_renders_assistant_tool_and_result():
    buf = io.StringIO()
    tailer = SessionTailer(path="unused", out=buf)

    # SDK init banner
    tailer.process_line(_record(
        ts=1700000000.0, rtype="SystemMessage",
        data={"subtype": "init",
              "data": {"cwd": "C:/ws", "model": "claude-opus-4-7",
                       "session_id": "abcdef1234"}},
    ))

    # Assistant tool_use + text
    tailer.process_line(_record(
        ts=1700000001.0, rtype="AssistantMessage",
        data={"content": [
            {"text": "I'll compile the POC now."},
            {"name": "Bash", "id": "tu_1", "input": {"command": "cl /nologo poc.c"}},
        ]},
    ))

    # Matching tool result
    tailer.process_line(_record(
        ts=1700000002.0, rtype="UserMessage",
        data={"content": [
            {"tool_use_id": "tu_1", "content": "poc.c\npoc.exe built", "is_error": False},
        ]},
    ))

    out = _strip_ansi(buf.getvalue())
    assert "SESSION STARTED" in out
    assert "model=claude-opus-4-7" in out
    assert "cwd: C:/ws" in out
    assert "[ASSISTANT]" in out
    assert "I'll compile the POC now." in out
    assert "[TOOL] Bash" in out
    assert "command=" in out
    assert "[RESULT] Bash" in out
    assert "poc.exe built" in out


def test_tail_marks_error_results():
    buf = io.StringIO()
    tailer = SessionTailer(path="unused", out=buf)

    tailer.process_line(_record(
        ts=1700000003.0, rtype="AssistantMessage",
        data={"content": [
            {"name": "Read", "id": "tu_2", "input": {"file_path": "missing.txt"}},
        ]},
    ))
    tailer.process_line(_record(
        ts=1700000004.0, rtype="UserMessage",
        data={"content": [
            {"tool_use_id": "tu_2", "content": "File not found", "is_error": True},
        ]},
    ))

    out = _strip_ansi(buf.getvalue())
    assert "[RESULT] Read [ERROR]" in out
    assert "File not found" in out


def test_tail_renders_sdk_error_record():
    buf = io.StringIO()
    tailer = SessionTailer(path="unused", out=buf)
    tailer.process_line(_record(
        ts=1700000005.0, rtype="sdk_error",
        data={"error": "connection reset"},
    ))
    out = _strip_ansi(buf.getvalue())
    assert "[SDK ERROR] connection reset" in out


def test_tail_hides_thinking_by_default_and_shows_when_enabled():
    buf_hidden = io.StringIO()
    SessionTailer(path="unused", out=buf_hidden).process_line(_record(
        ts=1700000006.0, rtype="AssistantMessage",
        data={"content": [{"thinking": "secret internal reasoning"}]},
    ))
    assert "secret internal reasoning" not in buf_hidden.getvalue()

    buf_shown = io.StringIO()
    SessionTailer(path="unused", show_thinking=True, out=buf_shown).process_line(_record(
        ts=1700000007.0, rtype="AssistantMessage",
        data={"content": [{"thinking": "secret internal reasoning"}]},
    ))
    out = _strip_ansi(buf_shown.getvalue())
    assert "[THINKING]" in out
    assert "secret internal reasoning" in out


def test_tail_skips_malformed_json_with_parse_error():
    buf = io.StringIO()
    SessionTailer(path="unused", out=buf).process_line("{not json")
    out = _strip_ansi(buf.getvalue())
    assert "[PARSE ERROR]" in out
