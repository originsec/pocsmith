"""pocsmith CLI: run, resume, inspect, report."""
from pathlib import Path
import asyncio
import json
import os
import typer
from dotenv import load_dotenv

from pocsmith.workspace import (
    prepare_workspace, release_lock,
    start_ghidra_container, stop_ghidra_container, wait_for_ghidra_container,
)
from pocsmith.session import run_session, RunnerProtocol
from pocsmith.report import write_artifacts
from pocsmith.context import load_context
from pocsmith.config import load_config
from pocsmith.llm import effective_model, effective_sdk_env
from pocsmith.preflight import check_vm_build


load_dotenv()

app = typer.Typer(help="Agentic POC development from patchwatch reports.")


_CEILINGS_BY_LEVEL = {
    "A": {"wall_min": 60, "iterations": 40, "dollars": 10.0, "phases": 8},
    "B": {"wall_min": 240, "iterations": 80, "dollars": 50.0, "phases": 16},
    "C": {"wall_min": 240, "iterations": 80, "dollars": 50.0, "phases": 16},
}

_SUCCESS_STATUSES = {"crash_repro_success", "partial_primitive", "full_exploit"}


class _FakeRunner(RunnerProtocol):
    """Used by tests; env-gated."""
    async def run_phase(self, *, workspace, system_prompt, kickoff,
                        tools, hooks, model, phase_n: int = 0,
                        llm_env: dict[str, str] | None = None):
        return {"event": "report_outcome",
                "outcome": {"action": "terminate", "status": "give_up",
                            "attempt_id": None, "signal": None, "notes": "fake"},
                "tokens_in": 1, "tokens_out": 1, "attempts": 0, "elapsed_s": 1}


def _make_runner() -> RunnerProtocol:
    if os.environ.get("POCSMITH_FAKE_RUNNER") == "1":
        return _FakeRunner()
    from pocsmith.agent_runner import AgentRunner
    return AgentRunner()


@app.command()
def run(
    cve: str = typer.Option(..., "--cve"),
    level: str = typer.Option("A", "--level"),
    workspace_root: Path = typer.Option(None, "--workspace-root"),
    model: str | None = typer.Option(None, "--model"),
    config_path: Path = typer.Option(None, "--config",
                                     help="Path to pocsmith.yaml"),
    vm_name: str = typer.Option("", "--vm-name",
                                help="Hyper-V VM name (overrides vm.default_profile from --config)"),
    hint: str = typer.Option("", "--hint",
                             help="Hints, suggestions, or questions injected into the first phase kickoff."),
    skip_build_check: bool = typer.Option(
        False, "--skip-build-check",
        help="Skip the VM build-number check against context.json's patched_build.",
    ),
):
    if level not in _CEILINGS_BY_LEVEL:
        raise typer.BadParameter(f"level must be one of A, B, C; got {level!r}")

    cfg = load_config(config_path) if config_path else None
    model = effective_model(cfg, model)
    llm_env = effective_sdk_env(cfg, model=model) or None
    effective_ws = workspace_root or (cfg.paths.workspace_root if cfg else None)
    if not effective_ws:
        raise typer.BadParameter(
            "provide --workspace-root or set paths.workspace_root in --config",
            param_hint="--workspace-root",
        )

    src = effective_ws / cve
    if not src.exists():
        raise typer.BadParameter(f"CVE export not found: {src}")

    effective_vm = vm_name or (cfg.vm.default_profile if cfg else "")

    if effective_vm and skip_build_check:
        typer.echo("[!] --skip-build-check set; not verifying VM build matches context.json", err=True)
    elif effective_vm:
        ctx = load_context(src / "context.json")
        if ctx.patched_build is None:
            typer.echo(
                "[!] VM name set but context.json has no patched_build; "
                "skipping VM build check.",
                err=True,
            )
        else:
            try:
                hv = cfg.hyperv_guest if cfg else None
                check_vm_build(
                    effective_vm, ctx.patched_build,
                    user=os.environ.get(hv.username_env, "") if hv else "",
                    password=os.environ.get(hv.password_env, "") if hv else "",
                )
            except RuntimeError as exc:
                raise typer.BadParameter(str(exc), param_hint="--vm-name/--config") from exc

    from pocsmith.config import GhidraDockerConfig
    ws = None
    ghidra_container = None
    try:
        ws = prepare_workspace(src, effective_ws, cfg=cfg)
        if cfg is not None and isinstance(cfg.ghidra, GhidraDockerConfig):
            ghidra_container = start_ghidra_container(ws, cfg)
            wait_for_ghidra_container(cfg.ghidra.port)
        res = asyncio.run(run_session(
            workspace=ws.path, level=level, runner=_make_runner(),
            ceilings=_CEILINGS_BY_LEVEL[level], model=model,
            vm_name=effective_vm, user_hint=hint,
            llm_env=llm_env,
        ))
        outcome = res.terminal or {
            "status": res.exhausted or "error",
            "attempt_id": None, "signal": None, "notes": "",
        }
        write_artifacts(
            workspace=ws.path,
            outcome=outcome,
            verify=None,
            phases_run=res.phases_run,
            exhausted=res.exhausted,
        )
        if outcome.get("status") in _SUCCESS_STATUSES:
            from pocsmith.report_gen import generate_report
            generate_report(workspace=ws.path, model=model, llm_env=llm_env)
            if (ws.path / "artifacts" / "report.md").exists():
                typer.echo("[+] Report written to artifacts/report.md")
            else:
                typer.echo("[!] Report generation failed -- see stderr", err=True)
        typer.echo(f"phases_run={res.phases_run} terminal={res.terminal} exhausted={res.exhausted}")
    finally:
        if ghidra_container is not None:
            stop_ghidra_container(ghidra_container)
        if ws is not None:
            release_lock(ws)


@app.command()
def resume(
    cve: str = typer.Option(..., "--cve"),
    workspace_root: Path = typer.Option(None, "--workspace-root"),
    level: str = typer.Option("A", "--level"),
    model: str | None = typer.Option(None, "--model"),
    force: bool = typer.Option(False, "--force"),
    config_path: Path = typer.Option(None, "--config",
                                     help="Path to pocsmith.yaml"),
    vm_name: str = typer.Option("", "--vm-name",
                                help="Hyper-V VM name (overrides vm.default_profile from --config)"),
    hint: str = typer.Option("", "--hint",
                             help="Hints, suggestions, or questions injected into the first phase kickoff."),
    skip_build_check: bool = typer.Option(
        False, "--skip-build-check",
        help="Skip the VM build-number check against context.json's patched_build.",
    ),
):
    from pocsmith.resume import resume_workspace
    if level not in _CEILINGS_BY_LEVEL:
        raise typer.BadParameter(f"level must be one of A, B, C; got {level!r}")

    cfg = load_config(config_path) if config_path else None
    model = effective_model(cfg, model)
    llm_env = effective_sdk_env(cfg, model=model) or None
    effective_ws = workspace_root or (cfg.paths.workspace_root if cfg else None)
    if not effective_ws:
        raise typer.BadParameter(
            "provide --workspace-root or set paths.workspace_root in --config",
            param_hint="--workspace-root",
        )

    effective_vm = vm_name or (cfg.vm.default_profile if cfg else "")

    if effective_vm and skip_build_check:
        typer.echo("[!] --skip-build-check set; not verifying VM build matches context.json", err=True)
    elif effective_vm:
        ctx_path = effective_ws / cve / "context.json"
        if ctx_path.exists():
            ctx = load_context(ctx_path)
            if ctx.patched_build is None:
                typer.echo(
                    "[!] VM name set but context.json has no patched_build; "
                    "skipping VM build check.",
                    err=True,
                )
            else:
                try:
                    hv = cfg.hyperv_guest if cfg else None
                    check_vm_build(
                        effective_vm, ctx.patched_build,
                        user=os.environ.get(hv.username_env, "") if hv else "",
                        password=os.environ.get(hv.password_env, "") if hv else "",
                    )
                except RuntimeError as exc:
                    raise typer.BadParameter(str(exc), param_hint="--vm-name/--config") from exc

    from pocsmith.config import GhidraDockerConfig
    target = effective_ws / cve
    lock = target / "pocsmith-run.lock"
    if lock.exists() and force:
        lock.unlink()
    ws = None
    ghidra_container = None
    try:
        ws = resume_workspace(effective_ws, cve, cfg=cfg)
        if cfg is not None and isinstance(cfg.ghidra, GhidraDockerConfig):
            ghidra_container = start_ghidra_container(ws, cfg)
            wait_for_ghidra_container(cfg.ghidra.port)
        res = asyncio.run(run_session(
            workspace=ws.path, level=level, runner=_make_runner(),
            ceilings=_CEILINGS_BY_LEVEL[level], model=model,
            vm_name=effective_vm, user_hint=hint,
            llm_env=llm_env,
        ))
        outcome = res.terminal or {
            "status": res.exhausted or "error",
            "attempt_id": None, "signal": None, "notes": "",
        }
        write_artifacts(
            workspace=ws.path,
            outcome=outcome,
            verify=None,
            phases_run=res.phases_run,
            exhausted=res.exhausted,
        )
        if outcome.get("status") in _SUCCESS_STATUSES:
            from pocsmith.report_gen import generate_report
            generate_report(workspace=ws.path, model=model, llm_env=llm_env)
            if (ws.path / "artifacts" / "report.md").exists():
                typer.echo("[+] Report written to artifacts/report.md")
            else:
                typer.echo("[!] Report generation failed -- see stderr", err=True)
        typer.echo(f"phases_run={res.phases_run} terminal={res.terminal} exhausted={res.exhausted}")
    finally:
        if ghidra_container is not None:
            stop_ghidra_container(ghidra_container)
        if ws is not None:
            release_lock(ws)


@app.command()
def inspect(
    workspace_root: Path = typer.Option(..., "--workspace-root"),
):
    if not workspace_root.exists():
        raise typer.BadParameter(f"{workspace_root} not found")
    for entry in sorted(workspace_root.iterdir()):
        if entry.is_dir() and (entry / "context.json").exists():
            outcome = entry / "outcome.json"
            status = "running"
            if outcome.exists():
                status = json.loads(outcome.read_text(encoding="utf-8")).get("status", "?")
            typer.echo(f"{entry.name}\t{status}")


@app.command()
def tail(
    cve: str = typer.Option("", "--cve",
                            help="CVE workspace name; resolves <workspace_root>/<cve>/session.jsonl"),
    workspace_root: Path = typer.Option(None, "--workspace-root"),
    config_path: Path = typer.Option(None, "--config", help="Path to pocsmith.yaml"),
    file: Path = typer.Option(None, "--file",
                              help="Direct path to a session.jsonl (overrides --cve)"),
    skip_existing: bool = typer.Option(False, "--tail/--no-tail",
                                       help="Skip existing content, only follow new lines"),
    thinking: bool = typer.Option(False, "--thinking",
                                  help="Show extended thinking blocks"),
    hooks: bool = typer.Option(False, "--hooks", help="Show hook events (noisy)"),
    max_result: int = typer.Option(600, "--max-result",
                                   help="Max chars per tool result"),
    max_result_lines: int = typer.Option(25, "--max-result-lines",
                                         help="Max lines per tool result"),
):
    """Live-tail a session.jsonl in human-readable turn format."""
    from pocsmith.session_tail import tail as _tail

    if file is not None:
        target = file
    else:
        if not cve:
            raise typer.BadParameter("provide --file or --cve")
        cfg = load_config(config_path) if config_path else None
        effective_ws = workspace_root or (cfg.paths.workspace_root if cfg else None)
        if not effective_ws:
            raise typer.BadParameter(
                "provide --workspace-root or set paths.workspace_root in --config",
                param_hint="--workspace-root",
            )
        target = effective_ws / cve / "session.jsonl"

    _tail(
        target,
        skip_existing=skip_existing,
        show_thinking=thinking,
        show_hooks=hooks,
        max_result=max_result,
        max_result_lines=max_result_lines,
    )


@app.command()
def report(
    cve: str = typer.Option(..., "--cve"),
    workspace_root: Path = typer.Option(None, "--workspace-root"),
    model: str | None = typer.Option(None, "--model"),
    config_path: Path = typer.Option(None, "--config", help="Path to pocsmith.yaml"),
):
    cfg = load_config(config_path) if config_path else None
    model = effective_model(cfg, model)
    llm_env = effective_sdk_env(cfg, model=model) or None
    effective_ws = workspace_root or (cfg.paths.workspace_root if cfg else None)
    if not effective_ws:
        raise typer.BadParameter(
            "provide --workspace-root or set paths.workspace_root in --config",
            param_hint="--workspace-root",
        )

    cve_dir = effective_ws / cve
    if not cve_dir.is_dir():
        typer.echo(f"[!] CVE workspace not found: {cve_dir}", err=True)
        raise typer.Exit(code=1)

    import pocsmith.log as _log_mod
    _log_mod.init(cve_dir)

    outcome_path = cve_dir / "outcome.json"
    if not outcome_path.exists():
        typer.echo("[!] No outcome.json found -- run pocsmith run first")
        raise typer.Exit(code=1)

    try:
        outcome = json.loads(outcome_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, ValueError) as exc:
        typer.echo(f"[!] Failed to parse outcome.json: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    status = outcome.get("status", "")
    if status not in _SUCCESS_STATUSES:
        typer.echo(f"[!] outcome status is '{status}' -- report generation only runs on success statuses")
        raise typer.Exit(code=1)

    from pocsmith.report_gen import generate_report
    generate_report(workspace=cve_dir, model=model, llm_env=llm_env)
    typer.echo("[+] Report written to artifacts/report.md")
