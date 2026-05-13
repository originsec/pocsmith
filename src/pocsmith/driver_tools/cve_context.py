"""Driver tool: structured view of context.json for the agent."""
from pathlib import Path
from pocsmith.context import load_context


def cve_context(workspace: Path) -> dict:
    ctx = load_context(Path(workspace) / "context.json")
    return ctx.model_dump()
