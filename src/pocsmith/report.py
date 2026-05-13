"""Final artifact writer: artifacts/summary.md + verification.json."""
from pathlib import Path
import json


def write_artifacts(*, workspace: Path, outcome: dict, verify: dict | None,
                    phases_run: int, exhausted: str | None) -> None:
    artifacts = Path(workspace) / "artifacts"
    artifacts.mkdir(exist_ok=True)
    effective_status = _effective_status(outcome, verify)

    md_lines = [
        f"# pocsmith run summary",
        f"",
        f"- **Reported status:** {outcome.get('status')}",
        f"- **Effective status:** {effective_status}",
        f"- **Attempt ID:** {outcome.get('attempt_id')}",
        f"- **Phases run:** {phases_run}",
    ]
    if exhausted:
        md_lines.append(f"- **Exhausted:** {exhausted}")
    md_lines.extend([
        f"",
        f"## Signal",
        f"```",
        json.dumps(outcome.get("signal"), indent=2) if outcome.get("signal") else "(none)",
        f"```",
        f"",
        f"## Notes",
        outcome.get("notes", ""),
    ])
    if verify is not None:
        md_lines.extend([
            f"",
            f"## Replay verification",
            f"- **Matched:** {verify.get('matched')}",
            f"```",
            json.dumps(verify.get("observation", {}), indent=2),
            f"```",
        ])
        if verify.get("matched") is False:
            md_lines.append("\n_Result was downgraded to **unverified_claim**: replay did not match._")
    (artifacts / "summary.md").write_text("\n".join(md_lines), encoding="utf-8")

    if verify is not None:
        (artifacts / "verification.json").write_text(json.dumps({
            **verify, "status": outcome.get("status"),
            "effective_status": effective_status,
        }, indent=2), encoding="utf-8")


def _effective_status(outcome: dict, verify: dict | None) -> str:
    s = outcome.get("status", "error")
    if verify is None:
        return s
    return s if verify.get("matched") else "unverified_claim"
