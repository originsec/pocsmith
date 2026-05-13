"""Driver tool: compile C with cl.exe under a resolved VS env."""
from pathlib import Path
from functools import lru_cache
import subprocess
import os


class CompileError(RuntimeError):
    pass


def _dump_env_via_cmd(vcvarsall: Path, arch: str) -> dict[str, str]:
    # cmd /c with a quoted path requires wrapping the entire command in outer
    # quotes so cmd strips them and sees: "path with spaces\vcvarsall.bat" arch
    raw_cmd = f'cmd.exe /c ""{vcvarsall}" {arch} >nul && set"'
    proc = subprocess.run(
        raw_cmd,
        capture_output=True, text=True, check=False,
    )
    if proc.returncode != 0:
        raise CompileError(f"vcvarsall failed: {proc.stderr}")
    env = {}
    for line in proc.stdout.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            env[k] = v
    return env


@lru_cache(maxsize=8)
def resolve_vs_env(vcvarsall: Path, arch: str) -> dict[str, str]:
    if not Path(vcvarsall).exists():
        raise CompileError(f"vcvarsall.bat not found at {vcvarsall}")
    return _dump_env_via_cmd(Path(vcvarsall), arch)


def compile_c(*, sources: list[Path], out: Path, vcvarsall: Path,
              arch: str = "x64", extra_flags: list[str] | None = None) -> dict:
    env = {**os.environ, **resolve_vs_env(vcvarsall, arch)}
    flags = extra_flags or ["/W4", "/MT", "/Zi", "/nologo"]
    cmd = ["cl.exe", *flags, *[str(s) for s in sources],
           f"/Fe:{out}", f"/Fd:{out.with_suffix('.pdb')}"]
    proc = subprocess.run(cmd, capture_output=True, text=True, env=env, check=False)
    pe_path = str(out) if (proc.returncode == 0 and out.exists()) else None
    return {"exit": proc.returncode, "stdout": proc.stdout,
            "stderr": proc.stderr, "pe_path": pe_path}
