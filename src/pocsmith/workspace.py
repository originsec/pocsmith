"""Workspace prep: materialize per-CVE dir, lock, symbol path env."""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING
import errno
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from pocsmith.context import CveContext, load_context

_POCSMITH_MCP = Path(__file__).parent / "pocsmith_mcp.py"

if TYPE_CHECKING:
    from pocsmith.config import PocsmithConfig


class WorkspaceLockError(RuntimeError):
    pass


@dataclass
class Workspace:
    path: Path
    context: CveContext


_SUBDIRS = ("poc", "attempts", "transcripts", "symbols", "ghidra-project", "artifacts")


def _write_mcp_json(target: Path, cfg: PocsmithConfig) -> None:
    servers: dict = {}

    servers["kd"] = {
        "command": sys.executable,
        "args": ["-m", cfg.kd.module],
    }

    from pocsmith.config import GhidraDockerConfig
    if isinstance(cfg.ghidra, GhidraDockerConfig):
        servers["ghidra"] = {
            "type": "http",
            "url": f"http://127.0.0.1:{cfg.ghidra.port}/mcp",
        }
    else:
        parts = cfg.ghidra.pyghidra_mcp_cmd.split()
        servers["ghidra"] = {
            "command": parts[0],
            "args": parts[1:],
            "env": {"GHIDRA_INSTALL_DIR": str(cfg.ghidra.ghidra_install_dir)},
        }

    if cfg.vm.mcp_module:
        hv_env: dict = {}
        for env_name in (
            cfg.hyperv_guest.username_env,
            cfg.hyperv_guest.password_env,
            cfg.hyperv_guest.victim_username_env,
            cfg.hyperv_guest.victim_password_env,
        ):
            val = os.environ.get(env_name, "")
            if val:
                hv_env[env_name] = val
        entry: dict = {"command": sys.executable, "args": ["-m", cfg.vm.mcp_module]}
        if hv_env:
            entry["env"] = hv_env
        servers["hyperv"] = entry

    pocsmith_env = {
        "POCSMITH_WORKSPACE": str(target),
        "POCSMITH_VCVARSALL": str(cfg.compile.vcvarsall),
        "POCSMITH_ARCH": cfg.compile.arch,
        "POCSMITH_ATTACKER_VENV": str(cfg.attacker_py.venv),
    }
    if cfg.attacker_py.sysinternals_dir is not None:
        pocsmith_env["POCSMITH_SYSINTERNALS"] = str(cfg.attacker_py.sysinternals_dir)
    servers["pocsmith"] = {
        "command": sys.executable,
        "args": [str(_POCSMITH_MCP)],
        "env": pocsmith_env,
    }

    (target / ".mcp.json").write_text(
        json.dumps({"mcpServers": servers}, indent=2),
        encoding="utf-8",
    )


def ghidra_container_name(cve_id: str) -> str:
    return f"pyghidra-mcp-{cve_id}"


def start_ghidra_container(workspace: "Workspace", cfg: "PocsmithConfig") -> str:
    from pocsmith.config import GhidraDockerConfig
    if not isinstance(cfg.ghidra, GhidraDockerConfig):
        raise TypeError("start_ghidra_container requires docker ghidra config")

    cve_id = workspace.context.cve_id
    name = ghidra_container_name(cve_id)
    ghidra_project = workspace.path / "ghidra-project"

    subprocess.run(["docker", "rm", "-f", name], check=False, capture_output=True)

    cmd = [
        "docker", "run", "-d", "--rm",
        "-p", f"127.0.0.1:{cfg.ghidra.port}:8000",
        "-v", f"{ghidra_project}:/ghidra_projects",
    ]
    for subdir in ("pre-patch", "post-patch"):
        src = workspace.path / subdir
        if src.exists():
            cmd += ["-v", f"{src}:/{subdir}:ro"]
    cmd += list(cfg.ghidra.extra_args)
    cmd += [
        "--name", name,
        cfg.ghidra.image,
        "--transport", "streamable-http",
        "--host", "0.0.0.0",
        "--project-path", "/ghidra_projects",
        "--project-name", cve_id,
    ]
    result = subprocess.run(cmd, check=True, capture_output=True, text=True)
    container_id = result.stdout.strip()[:12]
    print(f"[*] ghidra container started  name={name}  id={container_id}  port={cfg.ghidra.port}")
    return name


def stop_ghidra_container(container_name: str) -> None:
    subprocess.run(["docker", "stop", container_name], check=False, capture_output=True)


def wait_for_ghidra_container(port: int, timeout: int = 120) -> None:
    """Block until the pyghidra-mcp HTTP server accepts TCP connections."""
    deadline = time.monotonic() + timeout
    interval = 2
    while True:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=2):
                return
        except OSError:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(
                    f"pyghidra-mcp did not become ready on port {port} within {timeout}s"
                )
            time.sleep(min(interval, remaining))


def prepare_workspace(export_dir: Path, ws_root: Path,
                      cfg: PocsmithConfig | None = None) -> Workspace:
    ctx = load_context(export_dir / "context.json")
    target = ws_root / ctx.cve_id
    target.mkdir(parents=True, exist_ok=True)

    if (target / "attempts").exists():
        raise WorkspaceLockError(
            f"workspace {target} was already initialized by a prior run; "
            "use 'pocsmith resume' to continue it"
        )

    lock = target / "pocsmith-run.lock"
    try:
        fd = os.open(str(lock), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.write(fd, str(os.getpid()).encode())
        os.close(fd)
    except OSError as e:
        if e.errno == errno.EEXIST:
            raise WorkspaceLockError(f"workspace {target} already locked")
        raise

    for entry in ("cve.md", "context.json"):
        dst = target / entry
        if not dst.exists():
            shutil.copy2(export_dir / entry, dst)

    for sub in ("pre-patch", "post-patch", "ghidriff"):
        src_sub = export_dir / sub
        if src_sub.exists():
            _copy_tree(src_sub, target / sub)

    for d in _SUBDIRS:
        (target / d).mkdir(exist_ok=True)
    notes = target / "notes.md"
    if not notes.exists():
        notes.write_text("# Agent notes\n\n_No notes yet._\n")
    if cfg is not None:
        _write_mcp_json(target, cfg)
    return Workspace(path=target, context=ctx)


def _copy_tree(src: Path, dst: Path) -> None:
    dst.mkdir(parents=True, exist_ok=True)
    for entry in src.iterdir():
        target = dst / entry.name
        if target.exists():
            continue
        if entry.is_dir():
            _copy_tree(entry, target)
        else:
            try:
                os.link(entry, target)
            except OSError:
                shutil.copy2(entry, target)


def release_lock(ws: Workspace) -> None:
    (ws.path / "pocsmith-run.lock").unlink(missing_ok=True)


def symbol_path_for(workspace_path: Path) -> str:
    sym = workspace_path / "symbols"
    return f"srv*{sym}*https://msdl.microsoft.com/download/symbols"
