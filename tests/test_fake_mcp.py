from pathlib import Path

# Use relative import for test helpers
import sys
from pathlib import Path as PathlibPath
sys.path.insert(0, str(PathlibPath(__file__).parent))

from fake_mcp.fakes import FakeVm, FakeKd, FakeTarget, FakeGhidra


def test_vm_revert_lifecycle():
    vm = FakeVm()
    vm.boot("p1")
    sid = vm.snapshot("p1", "clean")
    vm.revert("p1", sid)
    assert vm.history[-1] == ("revert", "p1", sid)


def test_kd_session():
    kd = FakeKd()
    kd.kernel_attach("com:pipe,port=\\\\.\\pipe\\vm-kd,resets=0,reconnect")
    res = kd.bp("rpcrt4!FinishUsingContextHandle")
    assert "breakpoint" in res["output"]
    go_res = kd.go()
    assert go_res["status"] == "break"
    raw_res = kd.raw("k 20")
    assert "output" in raw_res
    kd.remove_bp("*")


def test_target_run(tmp_path: Path):
    t = FakeTarget()
    t.put(tmp_path / "x", r"C:\poc\x.exe")  # tmp_path/x doesn't need to exist for fake
    t.queue_run_result(exit=0, stdout="ok", stderr="")
    res = t.run(r"C:\poc\x.exe", [])
    assert res["exit"] == 0 and res["stdout"] == "ok"


def test_ghidra_decomp():
    g = FakeGhidra()
    g.set_decomp("FinishUsingContextHandle", "void f() { /* old */ }")
    assert "old" in g.decompile_function("FinishUsingContextHandle")
