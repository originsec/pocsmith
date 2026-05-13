"""Driver tool: terminal call. Returns a directive to the session driver."""
from pathlib import Path
from typing import Literal
import json
from pocsmith.verify.predicates import parse_signal

try:
    from pydantic import ValidationError as _PydanticValidationError
except ImportError:
    _PydanticValidationError = None


class ReportOutcomeError(ValueError):
    pass


_NEEDS_SIGNAL = {"crash_repro_success", "partial_primitive", "full_exploit"}
_TERMINAL_NO_VERIFY = {"give_up", "error", "unverified_claim"}
_VALID_STATUSES = _NEEDS_SIGNAL | _TERMINAL_NO_VERIFY
Status = Literal["crash_repro_success", "partial_primitive", "full_exploit",
                 "unverified_claim", "give_up", "error"]

_SIGNAL_SCHEMAS = {
    "bugcheck":           "kind, code (str), module (str)",
    "usermode_exception": "kind, module (str), rva_range ([int, int]), exception_code (str)",
    "kd_breakpoint_hit":  "kind, symbol (str), register_predicate (str)",
    "service_crash":      "kind, service_name (str), module (str), rva_range ([int, int])",
    "assertion":          "kind, module (str), assert_text_substring (str)",
}


def report_outcome(workspace: Path, *, status: Status,
                   attempt_id: int | None, signal: dict | None,
                   notes: str) -> dict:
    if status not in _VALID_STATUSES:
        raise ReportOutcomeError(
            f"unknown status {status!r}; must be one of {sorted(_VALID_STATUSES)}"
        )
    if status in _NEEDS_SIGNAL:
        missing = [f for f, v in [("attempt_id", attempt_id), ("signal", signal)] if v is None]
        if missing:
            raise ReportOutcomeError(
                f"status={status!r} requires {', '.join(missing)}; "
                f"attempt_id is the int returned by record_attempt"
            )
        kind = signal.get("kind", "<missing>") if isinstance(signal, dict) else "<not a dict>"
        schema_hint = _SIGNAL_SCHEMAS.get(kind, f"unknown kind {kind!r}; valid kinds: {sorted(_SIGNAL_SCHEMAS)}")
        try:
            validated = parse_signal(signal)
        except Exception as exc:
            exc_type = type(exc).__name__
            raise ReportOutcomeError(
                f"signal validation failed for kind={kind!r}. "
                f"Required fields: {schema_hint}. "
                f"{exc_type}: {exc}"
            ) from exc
        action = "replay_verify"
        sig_payload = validated.model_dump()
    elif status in _TERMINAL_NO_VERIFY:
        action = "terminate"
        sig_payload = None

    saved = {
        "status": status, "attempt_id": attempt_id,
        "signal": sig_payload, "notes": notes,
    }
    (Path(workspace) / "outcome.json").write_text(json.dumps(saved, indent=2), encoding="utf-8")
    return {"action": action, **saved}
