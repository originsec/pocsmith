from pathlib import Path
from pocsmith.verify.evaluators import (
    eval_bugcheck, eval_usermode_exception, eval_kd_breakpoint_hit,
    eval_service_crash, eval_assertion, KdBreakObservation,
)
from pocsmith.verify.predicates import (
    Bugcheck, UsermodeException, KdBreakpointHit, ServiceCrash, Assertion,
)

FIX = Path(__file__).parent / "fixtures"


def test_bugcheck_match():
    out = (FIX / "kd_outputs/bugcheck_3b.txt").read_text()
    assert eval_bugcheck(Bugcheck(code="0x3B", module="ntoskrnl.exe"), out)
    assert not eval_bugcheck(Bugcheck(code="0x7E", module="ntoskrnl.exe"), out)


def test_kd_bp_hit_with_predicate():
    out = (FIX / "kd_outputs/bp_hit.txt").read_text()
    obs = KdBreakObservation(symbol_hit="rpcrt4!FinishUsingContextHandle",
                             register_dump=out, memory={})
    p = KdBreakpointHit(symbol="rpcrt4!FinishUsingContextHandle",
                        register_predicate="rcx==0")
    assert eval_kd_breakpoint_hit(p, obs)


def test_usermode_exception_in_range():
    xml = (FIX / "wer/usermode_av.xml").read_text()
    p = UsermodeException(module="rpcrt4.dll", rva_range=(0x1000, 0x2000),
                          exception_code="0xC0000005")
    assert eval_usermode_exception(p, xml)


def test_usermode_exception_out_of_range():
    xml = (FIX / "wer/usermode_av.xml").read_text()
    p = UsermodeException(module="rpcrt4.dll", rva_range=(0x4000, 0x5000),
                          exception_code="0xC0000005")
    assert not eval_usermode_exception(p, xml)


def test_service_crash_match():
    xml = (FIX / "eventlog/service_crash.xml").read_text()
    p = ServiceCrash(service_name="RpcSs", module="rpcrt4.dll",
                     rva_range=(0x1000, 0x2000))
    assert eval_service_crash(p, xml)


def test_assertion_match():
    out = "ASSERT! rpcrt4.dll: refcount underflow at line 42"
    assert eval_assertion(Assertion(module="rpcrt4.dll",
                                    assert_text_substring="refcount underflow"), out)
    assert not eval_assertion(Assertion(module="rpcrt4.dll",
                                        assert_text_substring="other thing"), out)
