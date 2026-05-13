"""context.json schema. Stable contract with patchwatch (design.md §3.1)."""
from pathlib import Path
import json
from pydantic import BaseModel, Field


class FunctionFinding(BaseModel):
    binary: str
    function: str
    relevance: float
    summary: str
    before_code: str | None = None
    after_code: str | None = None


class CveContext(BaseModel):
    cve_id: str
    cvss: float | None = None
    kb: str
    title: str
    description: str
    primary_binaries: list[str]
    deep_analysis: list[FunctionFinding] = Field(default_factory=list)
    prepatch_paths: dict[str, str] = Field(default_factory=dict)
    postpatch_paths: dict[str, str] = Field(default_factory=dict)
    ghidriff_dir: str
    # Build where CVE was fixed, e.g. "19041.3086" or "10.0.19041.3086".
    # Set by patchwatch export-poc-context; used for pre-flight VM build check.
    patched_build: str | None = None


def load_context(path: Path) -> CveContext:
    raw = json.loads(Path(path).read_text())
    return CveContext.model_validate(raw)
