"""Resume helper: re-acquire lock on an already-materialized workspace."""
from __future__ import annotations
from pathlib import Path
from typing import TYPE_CHECKING
import errno
import os
from pocsmith.context import load_context
from pocsmith.workspace import Workspace, WorkspaceLockError, _write_mcp_json

if TYPE_CHECKING:
    from pocsmith.config import PocsmithConfig


def resume_workspace(workspace_root: Path, cve_id: str,
                     cfg: PocsmithConfig | None = None) -> Workspace:
    target = workspace_root / cve_id
    if not target.exists() or not (target / "context.json").exists():
        raise FileNotFoundError(f"no materialized workspace at {target}")
    lock = target / "pocsmith-run.lock"
    try:
        fd = os.open(str(lock), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        try:
            os.write(fd, str(os.getpid()).encode())
        finally:
            os.close(fd)
    except OSError as e:
        if e.errno == errno.EEXIST:
            raise WorkspaceLockError(f"{target} still locked; clear with --force")
        raise
    if cfg is not None:
        _write_mcp_json(target, cfg)
    return Workspace(path=target, context=load_context(target / "context.json"))
