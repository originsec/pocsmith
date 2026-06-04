"""Generate a full findings report via Claude SDK from workspace artifacts."""
from __future__ import annotations

import asyncio
import json
import logging
import re
import shutil
import sys
from pathlib import Path

log = logging.getLogger("pocsmith.report")

TEXT_EXTENSIONS = {".c", ".py", ".ps1", ".txt", ".md", ".msc", ".bat", ".def"}
BINARY_EXTENSIONS = {".exe", ".dll", ".obj", ".pdb", ".lib", ".ilk", ".exp", ".gzf"}

_REPORT_STRUCTURE = """\
Write the report with exactly these sections:
# {cve_id} -- {title}
CVSS: {cvss} | KB: {kb} | Level: {status}

## Executive Summary
## Vulnerability Analysis
### Affected Component
### Root Cause
### Patch Analysis
## Exploit Chain
## Proof of Concept
### Requirements
### Reproduction Steps
### Expected Signals
## Detection & Mitigation
## Caveats & Limitations
---
## Appendix A: Binary Hashes
## Appendix B: Key Patch Diff
## Appendix C: Debugger Output
## Appendix D: POC File Manifest"""

_SYSTEM_PROMPT = (
    "You are a Windows security researcher writing a formal vulnerability research report. "
    "Write in Markdown following the exact structure in the user message. "
    "Use only the provided data. "
    "ASCII only -- no Unicode bullets or special characters."
)


def _safe(v: object) -> str:
    """Escape braces in a value so it is safe to interpolate into a .format() string."""
    return str(v).replace("{", "{{").replace("}", "}}")


def _extract_poc_filenames(notes: str) -> list[str]:
    """Parse outcome notes text for POC filenames using two-pass strategy."""
    names: list[str] = []
    seen: set[str] = set()

    for line in notes.splitlines():
        stripped = line.strip()
        if re.match(r"^[-*]\s+", stripped) and ("." in stripped or "/" in stripped):
            # Remove the bullet marker then split on " / " and " - "
            body = re.sub(r"^[-*]\s+", "", stripped)
            parts = re.split(r" / | - ", body)
            for part in parts:
                candidate = part.strip()
                if candidate and ("." in candidate or "/" in candidate):
                    fname = Path(candidate).name
                    if fname and fname not in seen:
                        seen.add(fname)
                        names.append(fname)

    # Fallback: bare poc/filename or poc\filename patterns (FIX 4 -- Windows backslash support)
    for match in re.finditer(r"poc[/\\]([^\s,;\"'\\]+)", notes):
        fname = Path(match.group(1)).name
        if fname and fname not in seen:
            seen.add(fname)
            names.append(fname)

    return names


def collect_workspace_data(workspace: Path) -> dict:
    """Read workspace files and return a unified data dict for report generation."""
    context: dict = {}
    outcome: dict = {}
    notes: str = ""
    cve_md: str = ""

    context_path = workspace / "context.json"
    if context_path.exists():
        try:
            context = json.loads(context_path.read_text(encoding="utf-8"))
            log.debug("Loaded context.json: cve_id=%s", context.get("cve_id", "?"))
        except (json.JSONDecodeError, ValueError) as exc:
            raise ValueError(f"Failed to parse context.json: {exc}") from exc
    else:
        log.warning("context.json not found in workspace")

    outcome_path = workspace / "outcome.json"
    if outcome_path.exists():
        try:
            outcome = json.loads(outcome_path.read_text(encoding="utf-8"))
            log.debug("Loaded outcome.json: status=%s", outcome.get("status", "?"))
        except (json.JSONDecodeError, ValueError) as exc:
            raise ValueError(f"Failed to parse outcome.json: {exc}") from exc
    else:
        log.warning("outcome.json not found in workspace")

    notes_path = workspace / "notes.md"
    if notes_path.exists():
        notes = notes_path.read_text(encoding="utf-8")
        log.debug("Loaded notes.md (%d bytes)", len(notes))

    cve_md_path = workspace / "cve.md"
    if cve_md_path.exists():
        cve_md = cve_md_path.read_text(encoding="utf-8")
        log.debug("Loaded cve.md (%d bytes)", len(cve_md))

    poc_files: dict[str, str] = {}
    missing_poc_files: list[str] = []

    outcome_notes = outcome.get("notes", "")
    if outcome_notes:
        filenames = _extract_poc_filenames(outcome_notes)
        log.debug("Extracted POC filenames from outcome notes: %s", filenames)
        poc_dir = workspace / "poc"
        for fname in filenames:
            fpath = poc_dir / fname
            suffix = Path(fname).suffix.lower()
            if suffix in BINARY_EXTENSIONS:
                log.debug("Skipping binary POC file: %s", fname)
                continue
            if not fpath.exists():
                log.warning("POC file referenced but not on disk: %s", fname)
                missing_poc_files.append(fname)
                continue
            if suffix in TEXT_EXTENSIONS or suffix == "":
                try:
                    poc_files[fname] = fpath.read_text(encoding="utf-8", errors="replace")
                    log.debug("Loaded POC file: %s (%d bytes)", fname, len(poc_files[fname]))
                except OSError:
                    log.warning("Failed to read POC file: %s", fname)
                    missing_poc_files.append(fname)

    log.info(
        "Workspace data collected: %d POC file(s), %d missing",
        len(poc_files), len(missing_poc_files),
    )
    return {
        "context": context,
        "outcome": outcome,
        "notes": notes,
        "cve_md": cve_md,
        "poc_files": poc_files,
        "missing_poc_files": missing_poc_files,
    }


def _build_prompt(data: dict) -> tuple[str, str]:
    """Build (system_prompt, user_prompt) strings from workspace data."""
    ctx = data.get("context", {})
    outcome = data.get("outcome", {})

    cve_id = ctx.get("cve_id", "CVE-UNKNOWN")
    title = ctx.get("title", "")
    cvss = ctx.get("cvss", "N/A")
    kb = ctx.get("kb", "")
    status = outcome.get("status", "unknown")

    deep_analysis = ctx.get("deep_analysis", [])
    deep_analysis_text = json.dumps(deep_analysis, indent=2) if deep_analysis else "(none)"
    signal_text = json.dumps(outcome.get("signal"), indent=2) if outcome.get("signal") else "(none)"

    report_instruction = _REPORT_STRUCTURE.format(
        cve_id=_safe(cve_id),
        title=_safe(title),
        cvss=_safe(cvss),
        kb=_safe(kb),
        status=_safe(status),
    )

    parts: list[str] = []

    meta = (
        f"CVE ID: {cve_id}\n"
        f"Title: {title}\n"
        f"CVSS: {cvss}\n"
        f"KB: {kb}\n"
        f"Description: {ctx.get('description', '')}\n"
        f"Primary Binaries: {', '.join(ctx.get('primary_binaries', []))}\n"
    )
    if data.get("cve_md"):
        meta += f"\nCVE Reference:\n{data['cve_md']}\n"
    parts.append(meta)

    parts.append(f"Deep Analysis (patch diff function findings):\n{deep_analysis_text}\n")

    parts.append(
        f"Outcome Status: {status}\n"
        f"Signal:\n{signal_text}\n"
        f"Outcome Notes:\n{outcome.get('notes', '')}\n"
    )

    if data.get("notes"):
        parts.append(f"Researcher Notes (notes.md):\n{data['notes']}\n")

    for fname, content in data.get("poc_files", {}).items():
        parts.append(f"POC File [{fname}]:\n```\n{content}\n```\n")

    if data.get("missing_poc_files"):
        parts.append(f"POC files referenced but not on disk: {', '.join(data['missing_poc_files'])}\n")

    parts.append(report_instruction)

    return _SYSTEM_PROMPT, "\n".join(parts)


async def _query_claude(
    system_prompt: str,
    user_prompt: str,
    model: str,
    llm_env: dict[str, str] | None = None,
) -> str:
    """Run a single-turn query via claude_agent_sdk and return the text response."""
    from claude_agent_sdk import AssistantMessage, ClaudeAgentOptions, ResultMessage, ToolUseBlock, query

    opts = ClaudeAgentOptions(
        system_prompt=system_prompt,
        model=model,
        allowed_tools=[],
        mcp_servers=None,
        env=llm_env or {},
        permission_mode="bypassPermissions",
        setting_sources=[],
        skills=None,
    )

    text_parts: list[str] = []
    async for message in query(prompt=user_prompt, options=opts):
        if isinstance(message, AssistantMessage):
            for block in message.content:
                if not isinstance(block, ToolUseBlock) and hasattr(block, "text"):
                    text_parts.append(block.text)
        elif isinstance(message, ResultMessage):
            usage = message.usage or {}
            log.debug(
                "SDK result: input_tokens=%s output_tokens=%s",
                usage.get("input_tokens", "?"),
                usage.get("output_tokens", "?"),
            )

    if not text_parts:
        raise RuntimeError("Claude returned no text content")
    return "".join(text_parts)


def call_claude_for_report(
    data: dict,
    *,
    model: str,
    llm_env: dict[str, str] | None = None,
) -> str:
    """Call Claude via SDK to generate the findings report. Returns Markdown text."""
    log.info("Querying Claude for report (model=%s)", model)
    system_prompt, user_prompt = _build_prompt(data)
    result = asyncio.run(_query_claude(system_prompt, user_prompt, model, llm_env))
    log.info("Report generated (%d chars)", len(result))
    return result


def write_report_artifacts(workspace: Path, report_md: str, data: dict) -> None:
    """Write report.md and copy identified POC files into artifacts/."""
    artifacts = workspace / "artifacts"
    artifacts.mkdir(exist_ok=True)

    report_path = artifacts / "report.md"
    report_path.write_text(report_md, encoding="utf-8")
    log.info("Wrote report to %s", report_path)

    poc_files = data.get("poc_files", {})
    missing = set(data.get("missing_poc_files", []))

    if poc_files:
        artifacts_poc = artifacts / "poc"
        artifacts_poc.mkdir(exist_ok=True)
        poc_src = workspace / "poc"
        copied = 0
        for fname in poc_files:
            if fname in missing:
                continue
            src = poc_src / fname
            if src.exists():
                shutil.copy2(src, artifacts_poc / fname)
                copied += 1
        log.debug("Copied %d POC file(s) to artifacts/poc/", copied)


def generate_report(
    workspace: Path,
    *,
    model: str = "claude-opus-4-7",
    llm_env: dict[str, str] | None = None,
) -> None:
    """Collect workspace data, call Claude, and write report artifacts."""
    log.info("Starting report generation for workspace: %s", workspace)
    data = collect_workspace_data(workspace)

    try:
        report_kwargs = {"model": model}
        if llm_env is not None:
            report_kwargs["llm_env"] = llm_env
        report_md = call_claude_for_report(data, **report_kwargs)
    except RuntimeError as exc:
        log.warning("Report generation skipped: %s", exc)
        return
    except Exception as exc:
        log.error("Report generation failed: %s", exc, exc_info=True)
        artifacts = workspace / "artifacts"
        artifacts.mkdir(exist_ok=True)
        (artifacts / "report.md").write_text(
            f"# Report generation failed\nError: {exc}\n",
            encoding="utf-8",
        )
        return

    write_report_artifacts(workspace, report_md, data)
