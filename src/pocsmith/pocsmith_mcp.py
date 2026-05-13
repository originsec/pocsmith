#!/usr/bin/env python3
"""pocsmith driver-tool MCP server.

Wraps compile_c, attacker_py, cve_context, record_attempt, end_phase, and
report_outcome as MCP tools so the agent can call them directly.

Launched per-workspace by the session driver via .mcp.json. Configuration is
passed through environment variables set in that file:

    POCSMITH_WORKSPACE      Absolute path to the active workspace directory
    POCSMITH_VCVARSALL      Path to vcvarsall.bat (for compile_c)
    POCSMITH_ARCH           Target arch passed to vcvarsall, e.g. "x64"
    POCSMITH_ATTACKER_VENV  Path to the attacker Python venv (for attacker_py)
"""
import os
import re
import sys
from pathlib import Path

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:
    print("ERROR: mcp package not found. pip install mcp", file=sys.stderr)
    sys.exit(1)

mcp = FastMCP(
    "pocsmith",
    instructions=(
        "pocsmith driver tools. Use compile_c / attacker_py to build and run "
        "attack code. Use record_attempt after every iteration (required). "
        "Use end_phase to persist notes between phases. Use report_outcome as "
        "the terminal call when success or giving up."
    ),
)


def _ws() -> Path:
    ws = os.environ.get("POCSMITH_WORKSPACE", "")
    if not ws:
        raise RuntimeError("POCSMITH_WORKSPACE env var not set")
    return Path(ws)


# ---------------------------------------------------------------------------
# compile_c
# ---------------------------------------------------------------------------

@mcp.tool()
def compile_c(
    sources: list[str],
    out: str,
    extra_flags: list[str] | None = None,
) -> dict:
    """
    Compile one or more C/C++ sources with cl.exe under a VS environment.

    Paths may be absolute or relative to the workspace root.

    Args:
        sources:     Source file paths (e.g. ["poc/poc.c"])
        out:         Output PE path (e.g. "poc/poc.exe")
        extra_flags: Additional cl.exe flags. Default: ["/W4", "/MT", "/Zi", "/nologo"]

    Returns: {exit, stdout, stderr, pe_path}
              pe_path is None on compile failure.
    """
    from pocsmith.driver_tools.compile_c import compile_c as _compile_c
    vcvarsall = Path(os.environ.get("POCSMITH_VCVARSALL", ""))
    arch = os.environ.get("POCSMITH_ARCH", "x64")
    ws = _ws()
    src_paths = [Path(s) if Path(s).is_absolute() else ws / s for s in sources]
    out_path = Path(out) if Path(out).is_absolute() else ws / out
    out_path.parent.mkdir(parents=True, exist_ok=True)
    return _compile_c(sources=src_paths, out=out_path,
                      vcvarsall=vcvarsall, arch=arch, extra_flags=extra_flags)


# ---------------------------------------------------------------------------
# attacker_py
# ---------------------------------------------------------------------------

@mcp.tool()
def attacker_py(
    script: str,
    args: list[str] | None = None,
    timeout_ms: int = 60000,
) -> dict:
    """
    Run a Python script in the attacker-side venv (impacket etc.).

    Path may be absolute or relative to the workspace root.

    Args:
        script:     Path to the Python script (e.g. "poc/relay.py")
        args:       Command-line arguments for the script
        timeout_ms: Timeout in milliseconds (default 60 s)

    Returns: {exit, stdout, stderr}
    """
    from pocsmith.driver_tools.attacker_py import attacker_py as _attacker_py
    venv = Path(os.environ.get("POCSMITH_ATTACKER_VENV", ""))
    ws = _ws()
    script_path = Path(script) if Path(script).is_absolute() else ws / script
    return _attacker_py(script=script_path, args=args or [], venv=venv,
                        timeout_ms=timeout_ms)


# ---------------------------------------------------------------------------
# cve_context
# ---------------------------------------------------------------------------

@mcp.tool()
def cve_context() -> dict:
    """
    Return the structured CVE context for this workspace.

    Returns: {cve_id, cvss, kb, title, description, primary_binaries,
              deep_analysis, prepatch_paths, postpatch_paths,
              ghidriff_dir, patched_build}
    """
    from pocsmith.driver_tools.cve_context import cve_context as _cve_context
    return _cve_context(_ws())


# ---------------------------------------------------------------------------
# record_attempt
# ---------------------------------------------------------------------------

# Detects an XML <parameter name="X">VALUE</parameter> tag (closing tag optional).
# Used to recover args the model leaked into a neighboring string field.
_PARAM_TAG_RE = re.compile(
    r'<parameter\s+name=["\']([^"\']+)["\']>([^<]*)(?:</parameter>)?',
    re.DOTALL,
)


def _strip_xml_drift(s: str) -> tuple[str, dict[str, str]]:
    """Recover args the model embedded as XML inside a JSON string value.

    When Opus 4.7 mixes JSON tool-call format with the older XML format, a
    string value may end with `</fieldname>\\n<parameter name="X">VALUE` — the
    args after the bad break get swallowed into the preceding string. This
    strips the XML drift and returns (cleaned_value, {recovered_arg: value}).
    """
    if not isinstance(s, str) or "<parameter" not in s:
        return s, {}
    cut = s.find("<parameter")
    head = s[:cut].rstrip()
    head = re.sub(r"</\w+>\s*$", "", head).rstrip()
    extracted = {m.group(1): m.group(2) for m in _PARAM_TAG_RE.finditer(s[cut:])}
    return head, extracted


@mcp.tool()
def record_attempt(
    outcome: str | None = None,
    poc_path: str | None = None,
    deploy_to: str | None = None,
    invocation: dict | None = None,
    ruled_out: list[str] | None = None,
    hypothesis: str | None = None,
    kd_observations: str | None = None,
) -> int:
    """
    Record an attempt iteration. REQUIRED before moving to the next hypothesis.

    ALL FIELDS BELOW ARE REQUIRED. The signature uses Optional only so the
    server can recover from JSON/XML format mixing — see "FORMAT" below.

    FORMAT — read carefully:
        Pass every argument as a JSON key in the tool call. Do NOT emit
        `<parameter name="X">VALUE</parameter>` XML tags inside JSON string
        values. If you do, this server will attempt to recover the orphaned
        args, but you'll waste a round trip.

    Args:
        outcome:         REQUIRED. Exactly one of:
                         triggered, no_trigger, crash, timeout, error
        poc_path:        REQUIRED. Workspace-relative path to the POC artifact
                         (source, compiled binary, .msc, .docx, .xml, etc.).
                         For file-as-POC cases, this may equal deploy_to's name.
        deploy_to:       REQUIRED. Path on the target VM where the POC was placed.
        invocation:      REQUIRED. Dict with keys: command (str), args (list[str]),
                         cwd (str). Example:
                         {"command": "cdb.exe", "args": ["-cf", "s.txt", "mmc.exe"],
                          "cwd": "C:\\poc"}
                         Must be a JSON object — NOT a string.
        ruled_out:       REQUIRED. List of hypotheses or primitives definitively
                         eliminated this iteration. Empty list [] is valid.
        hypothesis:      REQUIRED. What you expected to happen and why.
        kd_observations: REQUIRED. Summary of KD output (BPs hit, registers, stack).

    Returns: monotonic attempt_id (integer) — pass to report_outcome on success
    """
    from pocsmith.driver_tools.record_attempt import record_attempt as _record_attempt

    args: dict = {
        "outcome": outcome,
        "poc_path": poc_path,
        "deploy_to": deploy_to,
        "invocation": invocation,
        "ruled_out": ruled_out,
        "hypothesis": hypothesis,
        "kd_observations": kd_observations,
    }
    for field, val in list(args.items()):
        if isinstance(val, str) and "<parameter" in val:
            cleaned, recovered = _strip_xml_drift(val)
            args[field] = cleaned
            for k, v in recovered.items():
                if k in args and args[k] in (None, ""):
                    args[k] = v

    missing = [k for k, v in args.items() if v is None]
    if missing:
        raise ValueError(
            f"record_attempt: missing required fields: {sorted(missing)}. "
            "All seven fields are required. Pass each as a JSON key — do not "
            "embed <parameter name=...> XML tags inside string values."
        )

    return _record_attempt(_ws(), **args)


# ---------------------------------------------------------------------------
# end_phase
# ---------------------------------------------------------------------------

@mcp.tool()
def end_phase(summary: str, updated_notes: str) -> dict:
    """
    End the current phase and persist updated notes.md.

    Call when changing hypothesis direction or hitting a wall.
    notes.md is the agent's exobrain — write everything useful for the next phase.
    Anything not in notes.md or attempts/*/status.json does not survive the phase.

    Args:
        summary:       Short description of what this phase accomplished/tried
        updated_notes: Full replacement content for notes.md

    Returns: {closed: true}
    """
    from pocsmith.driver_tools.end_phase import end_phase as _end_phase
    return _end_phase(_ws(), summary=summary, updated_notes=updated_notes)


# ---------------------------------------------------------------------------
# report_outcome
# ---------------------------------------------------------------------------

@mcp.tool()
def report_outcome(
    status: str,
    notes: str,
    attempt_id: int | None = None,
    signal: dict | None = None,
) -> dict:
    """
    Terminal call — report the final outcome for this POC session.

    status must be one of:
      crash_repro_success   bug triggered; KD captured a verifiable signal
      partial_primitive     partial control demonstrated
      full_exploit          full code execution achieved
      unverified_claim      believed to work but signal not cleanly captured
      give_up               approach or budget exhausted
      error                 tool or infrastructure failure

    For crash_repro_success / partial_primitive / full_exploit:
      attempt_id is REQUIRED — the attempt_id returned by record_attempt
      signal is REQUIRED: {kind, ...kind-specific fields}
        kind="bugcheck"           -> code (str), module (str)
        kind="usermode_exception" -> module (str), rva_range ([int,int]), exception_code (str)
        kind="kd_breakpoint_hit"  -> symbol (str), register_predicate (str)
        kind="service_crash"      -> service_name (str), module (str), rva_range ([int,int])
        kind="assertion"          -> module (str), assert_text_substring (str)
      Extra fields in signal are ignored — only the listed fields are stored.

    After this call the driver will replay the specified attempt on a fresh
    VM revert and promote artifacts only if the signal matches.

    Args:
        status:     Outcome status (see above)
        notes:      Human-readable notes on what was achieved or why giving up
        attempt_id: attempt_id to replay (required for success statuses)
        signal:     Signal dict (required for success statuses)

    Returns: {action, status, attempt_id, signal, notes}
    """
    from pocsmith.driver_tools.report_outcome import report_outcome as _report_outcome
    return _report_outcome(_ws(), status=status, attempt_id=attempt_id,
                           signal=signal, notes=notes)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("pocsmith MCP server starting (stdio transport)...", file=sys.stderr)
    mcp.run()
