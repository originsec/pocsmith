from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest
from pocsmith.driver_tools.compile_c import compile_c, resolve_vs_env, CompileError


def test_resolve_vs_env_caches(tmp_path: Path):
    resolve_vs_env.cache_clear()  # ensure clean state
    fake_bat = tmp_path / "vcvarsall.bat"
    fake_bat.write_text("@echo off")
    with patch("pocsmith.driver_tools.compile_c._dump_env_via_cmd",
               return_value={"INCLUDE": "C:/i", "LIB": "C:/l", "PATH": "C:/p"}) as m:
        e1 = resolve_vs_env(fake_bat, "x64")
        e2 = resolve_vs_env(fake_bat, "x64")
        assert e1 == e2
        m.assert_called_once()


def test_compile_c_invokes_cl(tmp_path: Path):
    src = tmp_path / "p.c"
    src.write_text("int main(){return 0;}")
    out = tmp_path / "p.exe"
    with patch("pocsmith.driver_tools.compile_c.resolve_vs_env",
               return_value={"PATH": "C:/p", "INCLUDE": "", "LIB": ""}), \
         patch("subprocess.run") as run:
        run.return_value = MagicMock(returncode=0, stdout="ok", stderr="")
        out.write_bytes(b"PE\x00\x00")  # simulate output
        res = compile_c(sources=[src], out=out, vcvarsall=Path("C:/v.bat"),
                        arch="x64", extra_flags=["/W4"])
        assert res["exit"] == 0
        assert res["pe_path"] == str(out)
        cmd = run.call_args[0][0]
        assert any("cl" in str(c).lower() for c in cmd)


def test_compile_c_failure(tmp_path: Path):
    src = tmp_path / "bad.c"
    src.write_text("oops")
    out = tmp_path / "bad.exe"
    with patch("pocsmith.driver_tools.compile_c.resolve_vs_env",
               return_value={"PATH": "C:/p", "INCLUDE": "", "LIB": ""}), \
         patch("subprocess.run") as run:
        run.return_value = MagicMock(returncode=2, stdout="", stderr="error C2059")
        res = compile_c(sources=[src], out=out, vcvarsall=Path("C:/v.bat"),
                        arch="x64", extra_flags=[])
        assert res["exit"] == 2
        assert "C2059" in res["stderr"]
        assert res["pe_path"] is None
