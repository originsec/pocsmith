"""Replay-verify driver: revert + redeploy + rerun + signal match."""
from dataclasses import dataclass
from pathlib import Path
import json
from pocsmith.verify.predicates import (
    SignalPredicate, Bugcheck, UsermodeException, KdBreakpointHit,
    ServiceCrash, Assertion,
)
from pocsmith.verify.evaluators import (
    eval_bugcheck, eval_usermode_exception, eval_kd_breakpoint_hit,
    eval_service_crash, eval_assertion, KdBreakObservation,
)


@dataclass
class VerifyResult:
    matched: bool
    observation: dict
    notes: str = ""


def replay_verify(*, ws: Path, attempt_id: int, signal: SignalPredicate,
                  vm, kd, target, profile: str, clean_snapshot: str,
                  wer_xml: str | None = None,
                  eventlog_xml: str | None = None) -> VerifyResult:
    status = json.loads((ws / "attempts" / f"{attempt_id:03d}" / "status.json").read_text())
    poc_local = ws / status["poc_path"]
    deploy_to = status["deploy_to"]
    args = list(status.get("invocation", {}).get("args", []))

    vm.revert(profile, clean_snapshot)
    kd.kernel_attach(vm.get_kd_endpoint(profile))
    if isinstance(signal, KdBreakpointHit):
        kd.bp(signal.symbol)
    go_res = kd.go()

    target.put(poc_local, deploy_to)
    run_res = target.run(deploy_to, args)
    # kd.go() blocks until a break event and returns {"status", "output"}.
    brk = {"reason": go_res.get("status", "timeout"), "output": go_res.get("output", "")}

    obs = {"run": run_res, "kd": brk}
    matched = _eval(signal, brk, run_res, wer_xml, eventlog_xml)
    return VerifyResult(matched=matched, observation=obs)


def _eval(signal, brk, run_res, wer_xml, eventlog_xml) -> bool:
    if isinstance(signal, Bugcheck):
        return eval_bugcheck(signal, brk.get("output", ""))
    if isinstance(signal, Assertion):
        return eval_assertion(signal, brk.get("output", ""))
    if isinstance(signal, KdBreakpointHit):
        if brk.get("reason") != "bp":
            return False
        obs = KdBreakObservation(symbol_hit=signal.symbol,
                                 register_dump=brk.get("output", ""), memory={})
        return eval_kd_breakpoint_hit(signal, obs)
    if isinstance(signal, UsermodeException):
        return bool(wer_xml) and eval_usermode_exception(signal, wer_xml)
    if isinstance(signal, ServiceCrash):
        return bool(eventlog_xml) and eval_service_crash(signal, eventlog_xml)
    return False
