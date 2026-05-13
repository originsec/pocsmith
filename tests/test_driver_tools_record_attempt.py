import json
from pathlib import Path
from pocsmith.driver_tools.record_attempt import record_attempt


def test_appends_monotonic(tmp_path: Path):
    ws = tmp_path / "ws"
    (ws / "attempts").mkdir(parents=True)
    a1 = record_attempt(ws, hypothesis="h1", poc_path="poc/a.c",
                        deploy_to="C:/p/a.exe", invocation={"args": ["x"]},
                        kd_observations="...", outcome="no_trigger", ruled_out=[])
    a2 = record_attempt(ws, hypothesis="h2", poc_path="poc/b.c",
                        deploy_to="C:/p/b.exe", invocation={"args": []},
                        kd_observations="...", outcome="triggered", ruled_out=["x"])
    assert a1 == 1 and a2 == 2
    s2 = json.loads((ws / "attempts/002/status.json").read_text())
    assert s2["hypothesis"] == "h2"
    assert s2["attempt_id"] == 2
