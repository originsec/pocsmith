"""Predicate evaluators against observation bundles."""
from dataclasses import dataclass
import re
from xml.etree import ElementTree as ET
from pocsmith.verify.predicates import (
    Bugcheck, UsermodeException, KdBreakpointHit, ServiceCrash, Assertion,
)
from pocsmith.verify.dsl import evaluate as eval_dsl, X64_REGS


@dataclass
class KdBreakObservation:
    symbol_hit: str
    register_dump: str
    memory: dict[int, int]


def _parse_register_dump(text: str) -> dict[str, int]:
    out: dict[str, int] = {}
    pat = re.compile(r"\b([a-z][a-z0-9]+)=([0-9a-fA-F`]+)", re.IGNORECASE)
    for m in pat.finditer(text):
        name = m.group(1).lower()
        if name not in X64_REGS:
            continue
        out[name] = int(m.group(2).replace("`", ""), 16)
    return out


def eval_bugcheck(p: Bugcheck, kd_output: str) -> bool:
    hex_str = p.code.lower().removeprefix("0x").lstrip("0") or "0"
    code_norm = hex_str.rjust(2, "0")
    txt = kd_output.lower()
    code_present = (
        re.search(rf"bugcheck\s+0?{code_norm}\b", txt) is not None
        or re.search(rf"\*\*\* fatal system error: 0x[0]*{code_norm}\b", txt) is not None
    )
    module_present = p.module.lower() in txt
    return code_present and module_present


def eval_usermode_exception(p: UsermodeException, wer_xml: str) -> bool:
    try:
        root = ET.fromstring(wer_xml)
    except ET.ParseError:
        return False

    def fmt(tag: str) -> str:
        el = root.find(f".//{tag}")
        return (el.text or "") if el is not None else ""

    if fmt("FaultingModuleName").lower() != p.module.lower():
        return False
    if fmt("ExceptionCode").lower() != p.exception_code.lower():
        return False
    off_text = fmt("FaultingOffset")
    off = int(off_text, 16) if off_text.lower().startswith("0x") else int(off_text or "0")
    return p.rva_range[0] <= off <= p.rva_range[1]


def eval_kd_breakpoint_hit(p: KdBreakpointHit, obs: KdBreakObservation) -> bool:
    if obs.symbol_hit != p.symbol:
        return False
    regs = _parse_register_dump(obs.register_dump)
    try:
        return eval_dsl(p.register_predicate, regs, obs.memory)
    except KeyError:
        return False


def eval_service_crash(p: ServiceCrash, eventlog_xml: str) -> bool:
    try:
        root = ET.fromstring(eventlog_xml)
    except ET.ParseError:
        return False
    stopped = any(
        (e.findtext("ServiceName") or "") == p.service_name
        and (e.findtext("ServiceState") or "").lower() == "stopped"
        for e in root.findall("Event")
    )
    if not stopped:
        return False
    for e in root.findall("Event"):
        if (e.findtext("FaultingModule") or "").lower() != p.module.lower():
            continue
        off_text = e.findtext("FaultOffset") or "0"
        off = int(off_text, 16) if off_text.lower().startswith("0x") else int(off_text)
        if p.rva_range[0] <= off <= p.rva_range[1]:
            return True
    return False


def eval_assertion(p: Assertion, kd_output: str) -> bool:
    return (
        "ASSERT" in kd_output.upper()
        and p.module.lower() in kd_output.lower()
        and p.assert_text_substring in kd_output
    )
