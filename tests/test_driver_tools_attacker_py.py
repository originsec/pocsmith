from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest
from pocsmith.driver_tools.attacker_py import attacker_py, AttackerVenvMissing


def test_runs_in_venv_python(tmp_path: Path):
    venv = tmp_path / "venv"
    (venv / "Scripts").mkdir(parents=True)
    (venv / "Scripts" / "python.exe").write_text("")  # mock
    script = tmp_path / "x.py"
    script.write_text("print('hi')")
    with patch("subprocess.run") as run:
        run.return_value = MagicMock(returncode=0, stdout="hi\n", stderr="")
        res = attacker_py(script=script, args=["--target", "1.2.3.4"],
                          venv=venv, timeout_ms=5000)
        cmd = run.call_args[0][0]
        assert str(venv / "Scripts" / "python.exe") == cmd[0]
        assert "--target" in cmd
        assert res["exit"] == 0


def test_missing_venv_raises(tmp_path: Path):
    venv = tmp_path / "nonesuch"
    script = tmp_path / "x.py"
    script.write_text("print('x')")
    with pytest.raises(AttackerVenvMissing):
        attacker_py(script=script, args=[], venv=venv, timeout_ms=1000)
