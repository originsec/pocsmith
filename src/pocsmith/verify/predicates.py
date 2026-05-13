"""Five typed signal predicates for replay-verification (design.md §7)."""
from typing import Literal, Union, Annotated
from pydantic import BaseModel, Field, TypeAdapter


class Bugcheck(BaseModel):
    kind: Literal["bugcheck"] = "bugcheck"
    code: str
    module: str


class UsermodeException(BaseModel):
    kind: Literal["usermode_exception"] = "usermode_exception"
    module: str
    rva_range: tuple[int, int]
    exception_code: str


class KdBreakpointHit(BaseModel):
    kind: Literal["kd_breakpoint_hit"] = "kd_breakpoint_hit"
    symbol: str
    register_predicate: str


class ServiceCrash(BaseModel):
    kind: Literal["service_crash"] = "service_crash"
    service_name: str
    module: str
    rva_range: tuple[int, int]


class Assertion(BaseModel):
    kind: Literal["assertion"] = "assertion"
    module: str
    assert_text_substring: str


SignalPredicate = Annotated[
    Union[Bugcheck, UsermodeException, KdBreakpointHit, ServiceCrash, Assertion],
    Field(discriminator="kind"),
]
_adapter: TypeAdapter[SignalPredicate] = TypeAdapter(SignalPredicate)


def parse_signal(raw: dict) -> SignalPredicate:
    return _adapter.validate_python(raw)
