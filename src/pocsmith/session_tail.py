"""Live-tail a pocsmith session.jsonl in a human-readable turn format.

The format consumed here is the per-record schema written by
``pocsmith.agent_runner.AgentRunner.run_phase`` to ``<workspace>/session.jsonl``:

    {"ts": <float>, "phase": <int>, "type": <str>, "data": <serialized SDK message>}

Run as a module:

    python -m pocsmith.session_tail <workspace>/session.jsonl
    python -m pocsmith.session_tail --tail --thinking <workspace>/session.jsonl

Or via the CLI subcommand:

    pocsmith tail --cve CVE-XXXX --config pocsmith.yaml
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import TextIO


# ANSI color codes
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
WHITE = "\033[97m"

C_SESSION = DIM + WHITE
C_USER = BOLD + CYAN
C_ASST = BOLD + GREEN
C_TOOL = BOLD + YELLOW
C_RESULT = MAGENTA
C_ERROR = BOLD + RED
C_THINKING = DIM

DEFAULT_MAX_RESULT = 600
DEFAULT_MAX_RESULT_LINES = 25


def _enable_ansi_on_windows() -> None:
    if sys.platform != "win32":
        return
    try:
        import ctypes  # noqa: PLC0415
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except OSError:
        pass


def fmt_time(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%H:%M:%S")


def truncate_text(text: str, max_chars: int, max_lines: int) -> str:
    lines = text.split("\n")
    truncated_lines = False
    if len(lines) > max_lines:
        lines = lines[:max_lines]
        truncated_lines = True

    joined = "\n".join(lines)
    truncated_chars = False
    if len(joined) > max_chars:
        joined = joined[:max_chars]
        truncated_chars = True

    suffix = ""
    if truncated_lines:
        suffix = f"\n  ... [+{len(text.split(chr(10))) - max_lines} more lines]"
    elif truncated_chars:
        suffix = f" ... [+{len(text) - max_chars} chars]"
    return joined + suffix


def fmt_tool_input(inp: dict, max_len: int = 200) -> str:
    """Compact single-line summary of tool input kwargs."""
    parts = []
    for k, v in inp.items():
        if isinstance(v, str):
            s = v.replace("\n", "\\n")
            if len(s) > 80:
                s = s[:80] + "..."
            parts.append(f"{k}={s!r}")
        elif isinstance(v, (dict, list)):
            s = json.dumps(v, separators=(",", ":"))
            if len(s) > 80:
                s = s[:80] + "..."
            parts.append(f"{k}={s}")
        else:
            parts.append(f"{k}={v!r}")
    result = ", ".join(parts)
    if len(result) > max_len:
        result = result[:max_len] + "..."
    return result


def extract_result_text(item: dict, data: dict) -> str:
    """Pull readable text from a tool-result UserMessage item."""
    raw = item.get("content", "")
    if isinstance(raw, str) and raw:
        return raw

    if isinstance(raw, list):
        parts = []
        for block in raw:
            if isinstance(block, dict):
                parts.append(block.get("text", json.dumps(block)))
            else:
                parts.append(str(block))
        if parts:
            return "\n".join(parts)

    tresult = data.get("tool_use_result", {})
    if isinstance(tresult, dict):
        stdout = tresult.get("stdout", "")
        if stdout:
            return stdout
        content = tresult.get("content", "")
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            parts = []
            for block in content:
                if isinstance(block, dict):
                    parts.append(block.get("text", ""))
                else:
                    parts.append(str(block))
            return "\n".join(parts)

    return ""


def _print_indented(text: str, out: TextIO, indent: str = "  ") -> None:
    for line in text.split("\n"):
        out.write(f"{indent}{line}\n")


class SessionTailer:
    def __init__(
        self,
        path: Path | str,
        *,
        skip_existing: bool = False,
        show_thinking: bool = False,
        show_hooks: bool = False,
        max_result: int = DEFAULT_MAX_RESULT,
        max_result_lines: int = DEFAULT_MAX_RESULT_LINES,
        out: TextIO | None = None,
    ) -> None:
        self.path = Path(path)
        self.skip_existing = skip_existing
        self.show_thinking = show_thinking
        self.show_hooks = show_hooks
        self.max_result = max_result
        self.max_result_lines = max_result_lines
        self.out = out or sys.stdout
        self.tool_names: dict[str, str] = {}

    def _write(self, line: str) -> None:
        self.out.write(line + "\n")

    def process_line(self, raw: str) -> None:
        raw = raw.strip()
        if not raw:
            return
        try:
            record = json.loads(raw)
        except json.JSONDecodeError as exc:
            self._write(f"{C_ERROR}[PARSE ERROR] {exc}: {raw[:80]}{RESET}")
            return

        ts = record.get("ts", 0)
        rtype = record.get("type", "")
        data = record.get("data", {})

        if rtype == "HookEventMessage":
            if self.show_hooks:
                subtype = data.get("subtype", "")
                hook_name = data.get("data", {}).get("hook_name", "")
                self._write(f"{C_SESSION}[{fmt_time(ts)}] HOOK {subtype}: {hook_name}{RESET}")
            return

        if rtype == "SystemMessage":
            subtype = data.get("subtype", "")
            if subtype == "init":
                inner = data.get("data", {})
                cwd = inner.get("cwd", "")
                model = inner.get("model", "")
                sid = inner.get("session_id", "")[:8]
                self._write(f"\n{C_SESSION}{'=' * 70}{RESET}")
                self._write(
                    f"{C_SESSION}[{fmt_time(ts)}] SESSION STARTED  "
                    f"model={model}  id={sid}...{RESET}"
                )
                self._write(f"{C_SESSION}  cwd: {cwd}{RESET}")
                self._write(f"{C_SESSION}{'=' * 70}{RESET}\n")
            return

        if rtype == "AssistantMessage":
            for item in data.get("content", []):
                if not isinstance(item, dict):
                    continue

                if "thinking" in item:
                    if self.show_thinking:
                        thinking = item.get("thinking", "").strip()
                        if thinking:
                            self._write(f"{C_THINKING}[{fmt_time(ts)}] [THINKING]{RESET}")
                            _print_indented(
                                truncate_text(thinking, 600, 30),
                                self.out, "  " + DIM,
                            )
                            self.out.write(RESET)
                    continue

                if "text" in item:
                    text = item["text"].strip()
                    if text:
                        self._write(f"{C_ASST}[{fmt_time(ts)}] [ASSISTANT]{RESET}")
                        _print_indented(text, self.out)
                    continue

                if "name" in item and "id" in item:
                    tool_name = item["name"]
                    tool_id = item["id"]
                    self.tool_names[tool_id] = tool_name
                    inp_str = fmt_tool_input(item.get("input", {}))
                    self._write(f"{C_TOOL}[{fmt_time(ts)}] [TOOL] {tool_name}({inp_str}){RESET}")
            return

        if rtype == "UserMessage":
            for item in data.get("content", []):
                if isinstance(item, str):
                    if item.strip():
                        self._write(f"{C_USER}[{fmt_time(ts)}] [USER] {item.strip()}{RESET}")
                    continue
                if not isinstance(item, dict):
                    continue

                if "tool_use_id" in item:
                    tool_id = item["tool_use_id"]
                    tool_name = self.tool_names.get(tool_id, "?")
                    is_error = bool(item.get("is_error"))
                    result_text = extract_result_text(item, data).strip()

                    color = C_ERROR if is_error else C_RESULT
                    flag = " [ERROR]" if is_error else ""
                    self._write(f"{color}[{fmt_time(ts)}] [RESULT] {tool_name}{flag}{RESET}")
                    if result_text:
                        display = truncate_text(result_text, self.max_result, self.max_result_lines)
                        _print_indented(display, self.out)
                    continue

                if "text" in item:
                    text = item["text"].strip()
                    if text:
                        self._write(f"{C_USER}[{fmt_time(ts)}] [USER]{RESET}")
                        _print_indented(text, self.out)
            return

        if rtype == "sdk_error":
            err = data.get("error", "") if isinstance(data, dict) else str(data)
            self._write(f"{C_ERROR}[{fmt_time(ts)}] [SDK ERROR] {err}{RESET}")
            return

    def run(self, *, poll_interval: float = 0.15) -> None:
        if not self.path.exists():
            self._write(f"Waiting for {self.path} ...")
            while not self.path.exists():
                time.sleep(0.5)

        self._write(f"{DIM}Tailing: {self.path}{RESET}")

        with self.path.open("r", encoding="utf-8", errors="replace") as f:
            if self.skip_existing:
                f.seek(0, os.SEEK_END)
            while True:
                line = f.readline()
                if line:
                    self.process_line(line)
                    self.out.flush()
                else:
                    time.sleep(poll_interval)


def tail(
    path: Path | str,
    *,
    skip_existing: bool = False,
    show_thinking: bool = False,
    show_hooks: bool = False,
    max_result: int = DEFAULT_MAX_RESULT,
    max_result_lines: int = DEFAULT_MAX_RESULT_LINES,
) -> None:
    """Tail a session.jsonl file. Blocks until interrupted."""
    _enable_ansi_on_windows()
    tailer = SessionTailer(
        path,
        skip_existing=skip_existing,
        show_thinking=show_thinking,
        show_hooks=show_hooks,
        max_result=max_result,
        max_result_lines=max_result_lines,
    )
    try:
        tailer.run()
    except KeyboardInterrupt:
        sys.stdout.write(f"\n{DIM}Stopped.{RESET}\n")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Live-tail a pocsmith session.jsonl in human-readable turn format.",
    )
    parser.add_argument("file", help="Path to session.jsonl")
    parser.add_argument("--tail", action="store_true",
                        help="Skip existing content, watch for new lines only")
    parser.add_argument("--thinking", action="store_true",
                        help="Show extended thinking blocks")
    parser.add_argument("--hooks", action="store_true",
                        help="Show hook events (noisy)")
    parser.add_argument("--max-result", type=int, default=DEFAULT_MAX_RESULT,
                        help=f"Max chars per tool result (default: {DEFAULT_MAX_RESULT})")
    parser.add_argument("--max-result-lines", type=int, default=DEFAULT_MAX_RESULT_LINES,
                        help=f"Max lines per tool result (default: {DEFAULT_MAX_RESULT_LINES})")
    args = parser.parse_args(argv)

    tail(
        args.file,
        skip_existing=args.tail,
        show_thinking=args.thinking,
        show_hooks=args.hooks,
        max_result=args.max_result,
        max_result_lines=args.max_result_lines,
    )


if __name__ == "__main__":
    main()
