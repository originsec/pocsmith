import pytest
from pydantic import ValidationError
from pocsmith.verify.predicates import (
    Bugcheck, UsermodeException, KdBreakpointHit, ServiceCrash, Assertion,
    parse_signal,
)

def test_parses_bugcheck():
    s = parse_signal({"kind": "bugcheck", "code": "0x3B", "module": "ntoskrnl.exe"})
    assert isinstance(s, Bugcheck)
    assert s.code == "0x3B"

def test_parses_usermode_exception():
    s = parse_signal({"kind": "usermode_exception", "module": "rpcrt4.dll",
                      "rva_range": [0x1000, 0x2000], "exception_code": "0xC0000005"})
    assert isinstance(s, UsermodeException)

def test_parses_kd_bp():
    s = parse_signal({"kind": "kd_breakpoint_hit",
                      "symbol": "rpcrt4!FinishUsingContextHandle",
                      "register_predicate": "rcx==0"})
    assert isinstance(s, KdBreakpointHit)

def test_parses_service_crash():
    s = parse_signal({"kind": "service_crash", "service_name": "RpcSs",
                      "module": "rpcrt4.dll", "rva_range": [0x1000, 0x2000]})
    assert isinstance(s, ServiceCrash)

def test_parses_assertion():
    s = parse_signal({"kind": "assertion", "module": "rpcrt4.dll",
                      "assert_text_substring": "refcount underflow"})
    assert isinstance(s, Assertion)

def test_rejects_unknown_kind():
    with pytest.raises(ValidationError):
        parse_signal({"kind": "vibes", "thing": "x"})

def test_rejects_missing_field():
    with pytest.raises(ValidationError):
        parse_signal({"kind": "bugcheck", "code": "0x3B"})  # missing module
