"""In-process fakes for vm/kd/target/ghidra MCPs."""
from collections import deque
from pathlib import Path
from typing import Any


class FakeVm:
    def __init__(self) -> None:
        self.history: list[tuple] = []
        self.profiles: dict[str, dict[str, Any]] = {}
        self._snap_id = 0

    def boot(self, profile: str) -> dict[str, Any]:
        self.history.append(("boot", profile))
        self.profiles.setdefault(profile, {"running": True, "snapshots": []})
        return {"hostname": f"{profile}.test", "ip": "192.0.2.1"}

    def snapshot(self, profile: str, name: str) -> str:
        if profile not in self.profiles:
            raise RuntimeError(f"profile '{profile}' not booted")
        self._snap_id += 1
        sid = f"snap{self._snap_id}"
        self.profiles[profile]["snapshots"].append((sid, name))
        self.history.append(("snapshot", profile, sid))
        return sid

    def revert(self, profile: str, snapshot_id: str) -> None:
        self.history.append(("revert", profile, snapshot_id))

    def shutdown(self, profile: str, mode: str = "graceful") -> None:
        self.history.append(("shutdown", profile, mode))
        self.profiles[profile]["running"] = False

    def get_kd_endpoint(self, profile: str) -> str:
        return f"pipe://./pipe/{profile}-kd"


class FakeKd:
    """Fake matching the kd-mcp tool surface."""

    def __init__(self) -> None:
        self.attached = False
        self.history: list[tuple] = []
        self._bps: dict[str, str] = {}
        self._next_bp = 0
        self._go_queue: deque[dict[str, str]] = deque()

    # --- session ---
    def kernel_attach(self, connection_string: str) -> str:
        self.attached = True
        self.history.append(("kernel_attach", connection_string))
        return "kd-session-1"

    def detach(self) -> None:
        self.attached = False
        self.history.append(("detach",))

    # --- execution ---
    def queue_break(self, *, reason: str, output: str) -> None:
        """Test helper: enqueue a result that go() will return."""
        self._go_queue.append({"status": reason, "output": output})

    def go(self) -> dict[str, Any]:
        self.history.append(("go",))
        if self._go_queue:
            return dict(self._go_queue.popleft())
        return {"status": "break", "output": ""}

    def break_in(self) -> dict[str, Any]:
        self.history.append(("break_in",))
        return {"status": "break", "output": ""}

    def raw(self, command: str) -> dict[str, Any]:
        self.history.append(("raw", command))
        return {"output": ""}

    # --- breakpoints ---
    def bp(self, expression: str) -> dict[str, Any]:
        self._next_bp += 1
        bp_id = f"bp{self._next_bp}"
        self._bps[bp_id] = expression
        return {"output": f"(breakpoint {bp_id} set)"}

    def remove_bp(self, bp_id: str = "*") -> dict[str, Any]:
        if bp_id == "*":
            self._bps.clear()
        else:
            self._bps.pop(bp_id, None)
        return {"output": "(done)"}

    def list_bps(self) -> dict[str, Any]:
        return {"output": "\n".join(f"{k} {v}" for k, v in self._bps.items())}

    # --- registers / stack ---
    def get_regs(self) -> dict[str, Any]:
        return {"output": ""}

    def stack_trace(self, frames: int = 20) -> dict[str, Any]:
        return {"output": ""}


class FakeTarget:
    def __init__(self) -> None:
        self.put_history: list[tuple[Path, str]] = []
        self._run_results: deque[dict[str, Any]] = deque()
        self.run_history: list[tuple[str, list[str]]] = []

    def put(self, local: Path, remote: str) -> None:
        self.put_history.append((Path(local), remote))

    def queue_run_result(self, *, exit: int, stdout: str, stderr: str) -> None:
        self._run_results.append({"exit": exit, "stdout": stdout, "stderr": stderr})

    def run(self, command: str, args: list[str], timeout_ms: int = 60_000) -> dict[str, Any]:
        self.run_history.append((command, args))
        if self._run_results:
            return self._run_results.popleft()
        return {"exit": 0, "stdout": "", "stderr": ""}


class FakeGhidra:
    def __init__(self) -> None:
        self._decomps: dict[str, str] = {}

    def set_decomp(self, function: str, code: str) -> None:
        self._decomps[function] = code

    def decompile_function(self, function: str) -> str:
        return self._decomps.get(function, "")
