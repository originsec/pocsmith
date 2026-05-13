"""YAML config loader."""
from pathlib import Path
from typing import Annotated, Literal, Optional, Union
import yaml
from pydantic import BaseModel, Field


class IsoEntry(BaseModel):
    path: Path
    os_build: str
    profile_name: str


class VmConfig(BaseModel):
    backend: Literal["hyperv"] = "hyperv"
    vm_root: Path
    default_profile: str
    # Python module name to invoke as `python -m <mcp_module>`. The package
    # must be installed in the pocsmith venv (setup.ps1 installs it editable
    # from the hyperv-mcp checkout). Set to None to omit the hyperv MCP entry.
    mcp_module: Optional[str] = "hyperv_mcp"
    isos: list[IsoEntry] = Field(default_factory=list)


class KdMcpConfig(BaseModel):
    # Python module name to invoke as `python -m <module>`. The package must
    # be installed in the pocsmith venv (setup.ps1 installs it editable from
    # the kd-mcp checkout).
    module: str = "kd_mcp"


class HypervGuestConfig(BaseModel):
    username_env: str = "HYPERV_GUEST_USERNAME"
    password_env: str = "HYPERV_GUEST_PASSWORD"
    # Optional unprivileged account for EoP victim-side execution (Medium IL).
    # When set, the agent should use these credentials for running the
    # vulnerable target process and admin credentials for setup tasks.
    victim_username_env: str = "HYPERV_GUEST_VICTIM_USERNAME"
    victim_password_env: str = "HYPERV_GUEST_VICTIM_PASSWORD"


class GhidraDockerConfig(BaseModel):
    mode: Literal["docker"] = "docker"
    image: str = "ghcr.io/clearbluejar/pyghidra-mcp"
    port: int = 8000
    extra_args: list[str] = Field(default_factory=list)


class GhidraLocalConfig(BaseModel):
    mode: Literal["local"] = "local"
    pyghidra_mcp_cmd: str = "pyghidra-mcp"
    ghidra_install_dir: Path


GhidraConfig = Annotated[
    Union[GhidraDockerConfig, GhidraLocalConfig],
    Field(discriminator="mode"),
]


class CompileConfig(BaseModel):
    vcvarsall: Path
    arch: Literal["x64", "x86", "arm64"] = "x64"


class AttackerPyConfig(BaseModel):
    venv: Path
    packages: list[str] = Field(default_factory=list)
    # Optional: host-side directory holding Sysinternals Suite binaries
    # (PsExec.exe, ProcMon.exe, etc.) that the agent can deploy into the guest.
    sysinternals_dir: Optional[Path] = None


class LlmConfig(BaseModel):
    model: str = "claude-opus-4-7"
    api_key_env: str = "ANTHROPIC_API_KEY"
    context_threshold_pct: int = 70


class LevelCeiling(BaseModel):
    wall_min: int
    iterations: int
    dollars: float
    phases: int


class CeilingsConfig(BaseModel):
    level_a: LevelCeiling
    level_b: LevelCeiling
    level_c: LevelCeiling


class PathsConfig(BaseModel):
    patchwatch_bin: Path
    workspace_root: Path


class PocsmithConfig(BaseModel):
    vm: VmConfig
    kd: KdMcpConfig
    hyperv_guest: HypervGuestConfig
    ghidra: GhidraConfig
    compile: CompileConfig
    attacker_py: AttackerPyConfig
    llm: LlmConfig
    ceilings: CeilingsConfig
    paths: PathsConfig


def load_config(path: Path) -> PocsmithConfig:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"pocsmith config not found: {path}")
    raw = yaml.safe_load(path.read_text(encoding="utf-8-sig"))
    return PocsmithConfig.model_validate(raw)
