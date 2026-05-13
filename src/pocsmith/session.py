"""Phase-scoped session loop."""
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from pocsmith.budget import Budget
from pocsmith.context import load_context
from pocsmith.prompts.system_prompt import build_system_prompt, build_phase_kickoff
import pocsmith.log as _log_mod

# Explicit tool allowlist passed to every agent phase.
# Built-in Claude Code tools + all MCP servers wired by _write_mcp_json.
# kd and ghidra use prefix wildcards since their tool lists are external.
ALLOWED_TOOLS: list[str] = [
    # Claude Code built-ins
    "Bash", "Read", "Write", "Edit", "Glob", "Grep", "Task",
    # Hyper-V VM lifecycle, checkpoints, KD setup, guest exec
    "mcp__hyperv__hyperv_list_vms",
    "mcp__hyperv__hyperv_get_vm_info",
    "mcp__hyperv__hyperv_start_vm",
    "mcp__hyperv__hyperv_stop_vm",
    "mcp__hyperv__hyperv_reset_vm",
    "mcp__hyperv__hyperv_checkpoint_create",
    "mcp__hyperv__hyperv_checkpoint_list",
    "mcp__hyperv__hyperv_checkpoint_restore",
    "mcp__hyperv__hyperv_checkpoint_remove",
    "mcp__hyperv__hyperv_configure_kdnet",
    "mcp__hyperv__hyperv_configure_kdcom",
    "mcp__hyperv__hyperv_guest_run",
    "mcp__hyperv__hyperv_guest_run_ps",
    "mcp__hyperv__hyperv_victim_run",
    "mcp__hyperv__hyperv_victim_run_ps",
    "mcp__hyperv__hyperv_guest_put",
    "mcp__hyperv__hyperv_guest_get",
    "mcp__hyperv__hyperv_guest_read_file",
    "mcp__hyperv__hyperv_guest_list_dir",
    # pocsmith driver tools
    "mcp__pocsmith__compile_c",
    "mcp__pocsmith__attacker_py",
    "mcp__pocsmith__cve_context",
    "mcp__pocsmith__record_attempt",
    "mcp__pocsmith__end_phase",
    "mcp__pocsmith__report_outcome",
    # External MCP servers — wildcard since tool names depend on server version
    "mcp__kd__*",
    "mcp__ghidra__*",
]


class RunnerProtocol(Protocol):
    async def run_phase(
        self, *, workspace: Path, system_prompt: str, kickoff: str,
        tools: list, hooks: dict, model: str, phase_n: int = 0,
    ) -> dict: ...


@dataclass
class SessionResult:
    phases_run: int
    terminal: dict | None
    exhausted: str | None


async def run_session(*, workspace: Path, level: str, runner: RunnerProtocol,
                      ceilings: dict, model: str,
                      vm_name: str = "",
                      user_hint: str = "",
                      tools: list | None = None,
                      hooks: dict | None = None) -> SessionResult:
    if ceilings.get("phases", 1) < 1:
        raise ValueError("ceilings['phases'] must be >= 1")
    _log_mod.init(workspace)
    log = _log_mod.log
    ctx = load_context(workspace / "context.json")
    budget = Budget(
        wall_min=ceilings["wall_min"], iterations=ceilings["iterations"],
        dollars=ceilings["dollars"], phases=ceilings["phases"],
    )
    system = build_system_prompt(level=level, ceilings=ceilings)
    terminal: dict | None = None
    phase_n = 0

    log.info("Session start  cve=%s level=%s model=%s", ctx.cve_id, level, model)
    log.debug("Ceilings: %s", ceilings)

    while terminal is None:
        if budget.exhausted():
            log.info("Budget exhausted: %s", budget.exhausted())
            break
        phase_n += 1
        kickoff = build_phase_kickoff(workspace=workspace, ctx=ctx, phase_n=phase_n,
                                      vm_name=vm_name,
                                      user_hint=user_hint if phase_n == 1 else "")
        reminder = budget.reminder()
        if reminder is not None:
            kickoff = reminder.text + "\n\n" + kickoff

        log.info("Phase %d starting", phase_n)
        log.debug("Phase %d kickoff:\n%s", phase_n, kickoff[:500])

        result = await runner.run_phase(
            workspace=workspace, system_prompt=system, kickoff=kickoff,
            tools=tools if tools is not None else ALLOWED_TOOLS,
            hooks=hooks or {}, model=model, phase_n=phase_n,
        )
        budget.tick(
            seconds=result.get("elapsed_s", 0),
            tokens_input=result.get("tokens_in", 0),
            tokens_output=result.get("tokens_out", 0),
            attempts=result.get("attempts", 0),
            phases=1,
        )
        elapsed = result.get("elapsed_s", 0)
        tok_in = result.get("tokens_in", 0)
        tok_out = result.get("tokens_out", 0)
        attempts = result.get("attempts", 0)
        event = result.get("event", "?")
        log.info(
            "Phase %d done  event=%s attempts=%d elapsed=%.1fs tok_in=%d tok_out=%d",
            phase_n, event, attempts, elapsed, tok_in, tok_out,
        )
        if result.get("sdk_error"):
            log.error("Phase %d aborted by SDK error: %s", phase_n, result["sdk_error"])
            break
        if result.get("event") == "report_outcome":
            terminal = result.get("outcome", {})
            status = terminal.get("status", "?")
            action = terminal.get("action", "?")
            notes = (terminal.get("notes") or "")[:120]
            log.info("Terminal outcome  status=%s action=%s notes=%s", status, action, notes)
            log.debug("Terminal outcome full: %s", terminal)

    exhausted = budget.exhausted()
    log.info("Session end  cve=%s phases=%d status=%s exhausted=%s",
             ctx.cve_id, phase_n, terminal.get("status", "none") if terminal else "none", exhausted)
    log.debug("Session end full: terminal=%s exhausted=%s", terminal, exhausted)
    return SessionResult(
        phases_run=phase_n, terminal=terminal, exhausted=exhausted,
    )
