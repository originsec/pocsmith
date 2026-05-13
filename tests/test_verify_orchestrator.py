import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from fake_mcp.fakes import FakeVm, FakeKd, FakeTarget  # noqa: E402
from pocsmith.verify.orchestrator import replay_verify, VerifyResult  # noqa: E402
from pocsmith.verify.predicates import Bugcheck  # noqa: E402


def _seed_attempt(ws: Path, attempt_id: int, payload: dict) -> None:
    a = ws / "attempts" / f"{attempt_id:03d}"
    a.mkdir(parents=True)
    (a / "status.json").write_text(json.dumps(payload))
    (a / "poc.exe").write_bytes(b"PE")


def test_match_bugcheck(tmp_path: Path):
    ws = tmp_path / "ws"
    ws.mkdir()
    _seed_attempt(ws, 1, {
        "attempt_id": 1, "poc_path": "attempts/001/poc.exe",
        "invocation": {"args": []}, "deploy_to": "C:/poc/poc.exe",
    })
    vm = FakeVm()
    kd = FakeKd()
    kd.queue_break(reason="bugcheck",
                   output="*** Fatal System Error: 0x0000003b\nProbably caused by : ntoskrnl.exe")
    target = FakeTarget()
    target.queue_run_result(exit=0, stdout="", stderr="")

    sig = Bugcheck(code="0x3B", module="ntoskrnl.exe")
    res = replay_verify(ws=ws, attempt_id=1, signal=sig, vm=vm, kd=kd, target=target,
                        profile="p1", clean_snapshot="clean1")
    assert isinstance(res, VerifyResult)
    assert res.matched is True
    assert ("revert", "p1", "clean1") in vm.history


def test_mismatch_returns_unverified(tmp_path: Path):
    ws = tmp_path / "ws"
    ws.mkdir()
    _seed_attempt(ws, 2, {
        "attempt_id": 2, "poc_path": "attempts/002/poc.exe",
        "invocation": {"args": []}, "deploy_to": "C:/poc/poc.exe",
    })
    vm, kd, target = FakeVm(), FakeKd(), FakeTarget()
    kd.queue_break(reason="timeout", output="")
    target.queue_run_result(exit=0, stdout="", stderr="")
    sig = Bugcheck(code="0x3B", module="ntoskrnl.exe")
    res = replay_verify(ws=ws, attempt_id=2, signal=sig, vm=vm, kd=kd, target=target,
                        profile="p1", clean_snapshot="clean1")
    assert res.matched is False
