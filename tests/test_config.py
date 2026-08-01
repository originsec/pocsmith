from pathlib import Path
from pocsmith.config import load_config, PocsmithConfig, GhidraDockerConfig
from pocsmith.llm import ABLITERATION_BASE_URL, effective_model, sdk_env


def test_loads_example(tmp_path: Path):
    cfg_path = tmp_path / "cfg.yaml"
    cfg_path.write_text("""
vm: { backend: hyperv, vm_root: C:/p/vms, default_profile: win11-24h2 }
kd: { module: kd_mcp }
hyperv_guest:
  username_env: HYPERV_GUEST_USERNAME
  password_env: HYPERV_GUEST_PASSWORD
ghidra: { mode: docker, image: "ghcr.io/clearbluejar/pyghidra-mcp" }
compile: { vcvarsall: C:/x.bat, arch: x64 }
attacker_py: { venv: C:/v, packages: [impacket] }
llm: { model: claude-opus-4-7, api_key_env: ANTHROPIC_API_KEY, context_threshold_pct: 70 }
ceilings:
  level_a: { wall_min: 60, iterations: 40, dollars: 10, phases: 8 }
  level_b: { wall_min: 240, iterations: 80, dollars: 50, phases: 16 }
  level_c: { wall_min: 240, iterations: 80, dollars: 50, phases: 16 }
paths: { patchwatch_bin: C:/x.exe, workspace_root: C:/w }
""")
    cfg = load_config(cfg_path)
    assert isinstance(cfg, PocsmithConfig)
    assert cfg.ceilings.level_a.iterations == 40
    assert cfg.llm.context_threshold_pct == 70
    assert cfg.hyperv_guest.username_env == "HYPERV_GUEST_USERNAME"
    assert isinstance(cfg.ghidra, GhidraDockerConfig)
    assert cfg.ghidra.image == "ghcr.io/clearbluejar/pyghidra-mcp"
    assert cfg.llm.provider == "anthropic"


def test_abliteration_llm_provider_maps_to_claude_sdk_env(tmp_path: Path, monkeypatch):
    cfg_path = tmp_path / "cfg.yaml"
    cfg_path.write_text("""
vm: { backend: hyperv, vm_root: C:/p/vms, default_profile: win11-24h2 }
kd: { module: kd_mcp }
hyperv_guest:
  username_env: HYPERV_GUEST_USERNAME
  password_env: HYPERV_GUEST_PASSWORD
ghidra: { mode: docker, image: "ghcr.io/clearbluejar/pyghidra-mcp" }
compile: { vcvarsall: C:/x.bat, arch: x64 }
attacker_py: { venv: C:/v, packages: [impacket] }
llm:
  provider: abliteration-ai
  model: abliterated-model
  api_key_env: ABLITERATION_API_KEY
  context_threshold_pct: 70
ceilings:
  level_a: { wall_min: 60, iterations: 40, dollars: 10, phases: 8 }
  level_b: { wall_min: 240, iterations: 80, dollars: 50, phases: 16 }
  level_c: { wall_min: 240, iterations: 80, dollars: 50, phases: 16 }
paths: { patchwatch_bin: C:/x.exe, workspace_root: C:/w }
""")
    monkeypatch.setenv("ABLITERATION_API_KEY", "ak-test")

    cfg = load_config(cfg_path)
    model = effective_model(cfg, override=None)
    env = sdk_env(cfg.llm, model=model)

    assert model == "abliterated-model"
    assert env["ANTHROPIC_BASE_URL"] == ABLITERATION_BASE_URL
    assert env["ANTHROPIC_API_KEY"] == "ak-test"
    assert env["ANTHROPIC_CUSTOM_MODEL_OPTION"] == "abliterated-model"
