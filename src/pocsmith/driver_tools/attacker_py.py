"""Driver tool: run an attacker-side Python script in the configured venv."""
from pathlib import Path
import subprocess


class AttackerVenvMissing(RuntimeError):
    pass


def attacker_py(*, script: Path, args: list[str], venv: Path,
                timeout_ms: int = 60_000) -> dict:
    py = Path(venv) / "Scripts" / "python.exe"
    if not py.exists():
        raise AttackerVenvMissing(f"venv python not found at {py}")
    cmd = [str(py), str(script), *args]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              stdin=subprocess.DEVNULL,
                              timeout=timeout_ms / 1000.0, check=False)
    except subprocess.TimeoutExpired as e:
        return {"exit": -1, "stdout": e.stdout or "", "stderr": "TIMEOUT"}
    return {"exit": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}
