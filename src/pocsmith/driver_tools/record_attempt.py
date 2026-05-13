"""Driver tool: append iteration log entry, return monotonic attempt_id."""
from pathlib import Path
import json

_VALID_OUTCOMES = {"triggered", "no_trigger", "crash", "timeout", "error"}


def record_attempt(workspace: Path, *, outcome: str, poc_path: str,
                   deploy_to: str, invocation: dict, ruled_out: list[str],
                   hypothesis: str, kd_observations: str) -> int:
    if outcome not in _VALID_OUTCOMES:
        raise ValueError(
            f"outcome must be one of {sorted(_VALID_OUTCOMES)}, got {outcome!r}"
        )
    if not isinstance(invocation, dict):
        raise ValueError(
            f"invocation must be a dict, e.g. "
            f'{{"command": "cdb.exe", "args": ["-cf", "script.txt", "target.exe"], "cwd": "C:\\\\poc"}}, '
            f"got {type(invocation).__name__}"
        )
    attempts_dir = Path(workspace) / "attempts"
    attempts_dir.mkdir(parents=True, exist_ok=True)
    next_id = max(
        (int(p.name) for p in attempts_dir.iterdir()
         if p.is_dir() and p.name.isdigit()),
        default=0,
    ) + 1
    a_dir = attempts_dir / f"{next_id:03d}"
    a_dir.mkdir(exist_ok=True)
    payload = {
        "attempt_id": next_id,
        "hypothesis": hypothesis,
        "poc_path": poc_path,
        "deploy_to": deploy_to,
        "invocation": invocation,
        "kd_observations": kd_observations,
        "outcome": outcome,
        "ruled_out": ruled_out,
    }
    (a_dir / "status.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return next_id
