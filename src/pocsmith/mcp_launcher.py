"""Generate .mcp.json and supervise MCP subprocesses."""
from dataclasses import dataclass, field
from pathlib import Path
import json
import os
import subprocess
import time


@dataclass
class McpSpec:
    name: str
    command: str
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    restart_on_exit: bool = False


def write_mcp_json(path: Path, specs: list[McpSpec]) -> None:
    obj = {"mcpServers": {
        s.name: {"command": s.command, "args": s.args, "env": s.env}
        for s in specs
    }}
    path.write_text(json.dumps(obj, indent=2))


@dataclass
class Supervisor:
    specs: list[McpSpec]
    _procs: dict[str, subprocess.Popen] = field(default_factory=dict)

    def start_all(self) -> None:
        for s in self.specs:
            self._spawn(s)

    def _spawn(self, s: McpSpec) -> None:
        env = {**os.environ, **s.env} if s.env else None
        self._procs[s.name] = subprocess.Popen(
            [s.command, *s.args],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=env,
        )

    def health_check(self) -> dict[str, bool]:
        return {name: (p.poll() is None) for name, p in self._procs.items()}

    def restart_dead(self) -> list[str]:
        restarted = []
        for s in self.specs:
            p = self._procs.get(s.name)
            if p is None or p.poll() is not None:
                if s.restart_on_exit:
                    self._spawn(s)
                    restarted.append(s.name)
        return restarted

    def stop_all(self, timeout: float = 5.0) -> None:
        for p in self._procs.values():
            if p.poll() is None:
                p.terminate()
        deadline = time.time() + timeout
        for p in self._procs.values():
            remaining = max(0.0, deadline - time.time())
            try:
                p.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                p.kill()
        self._procs.clear()
