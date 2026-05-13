import pytest
from pocsmith.verify.dsl import evaluate

REGS = {"rcx": 0, "rdx": 0x2000, "rax": 0x1000}
MEM = {0x1000 + 0xb8: 0, 0x2000 + 0x10: 5}


def test_eq():
    assert evaluate("rcx==0", REGS, MEM) is True
    assert evaluate("rdx==0", REGS, MEM) is False


def test_lt():
    assert evaluate("rcx < 1", REGS, MEM) is True


def test_deref_qword():
    assert evaluate("qword ptr [rax+0xb8] < 1", REGS, MEM) is True
    assert evaluate("qword ptr [rdx+0x10] == 5", REGS, MEM) is True


def test_and_or():
    assert evaluate("(rcx==0) && (rdx > 0x1000)", REGS, MEM) is True
    assert evaluate("(rcx==1) || (rdx > 0x1000)", REGS, MEM) is True
    assert evaluate("(rcx==1) && (rdx > 0x1000)", REGS, MEM) is False


def test_unknown_register_raises():
    with pytest.raises(ValueError):
        evaluate("r99==0", REGS, MEM)


def test_missing_memory_raises():
    with pytest.raises(KeyError):
        evaluate("qword ptr [rax+0xff] == 0", REGS, MEM)


def test_deref_no_offset():
    # rsp=0, memory[0]=0x99
    assert evaluate("qword ptr [rsp] == 0x99", {"rsp": 0}, {0: 0x99})
