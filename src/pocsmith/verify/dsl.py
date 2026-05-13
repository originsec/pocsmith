"""Register-predicate DSL parser/evaluator for KdBreakpointHit (design.md §7)."""
import re

X64_REGS = {"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
            "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip", "rflags"}

_INT_RE = r"(?:0x[0-9a-fA-F]+|\d+)"
_DEREF_RE = re.compile(
    rf"qword\s+ptr\s+\[\s*([a-z][a-z0-9]+)(?:\s*([+\-])\s*({_INT_RE}))?\s*\]",
    re.IGNORECASE,
)
_REG_RE = re.compile(r"^[a-z][a-z0-9]+$", re.IGNORECASE)


def _to_int(s: str) -> int:
    return int(s, 16) if s.lower().startswith("0x") else int(s)


def _resolve_term(term: str, regs: dict[str, int], mem: dict[int, int]) -> int:
    term = term.strip()
    m = _DEREF_RE.fullmatch(term)
    if m:
        reg = m.group(1).lower()
        if reg not in X64_REGS:
            raise ValueError(f"unknown register {reg}")
        offset = 0
        if m.group(2) is not None:
            sign = 1 if m.group(2) == "+" else -1
            offset = sign * _to_int(m.group(3))
        addr = regs[reg] + offset
        if addr not in mem:
            raise KeyError(f"memory at {hex(addr)} not captured")
        return mem[addr]
    if _REG_RE.fullmatch(term):
        if term.lower() not in X64_REGS:
            raise ValueError(f"unknown register {term}")
        return regs[term.lower()]
    return _to_int(term)


_CMP_RE = re.compile(r"^(.+?)\s*(==|!=|<=|>=|<|>)\s*(.+)$")


def _eval_atom(expr: str, regs: dict[str, int], mem: dict[int, int]) -> bool:
    m = _CMP_RE.match(expr.strip())
    if not m:
        raise ValueError(f"unparseable comparison: {expr!r}")
    lhs = _resolve_term(m.group(1), regs, mem)
    rhs = _resolve_term(m.group(3), regs, mem)
    op = m.group(2)
    return {
        "==": lhs == rhs, "!=": lhs != rhs,
        "<": lhs < rhs, "<=": lhs <= rhs,
        ">": lhs > rhs, ">=": lhs >= rhs,
    }[op]


def evaluate(expr: str, regs: dict[str, int], mem: dict[int, int]) -> bool:
    """Evaluate a register predicate. Supports atoms, &&, ||, parentheses."""
    expr = expr.strip()
    while expr.startswith("(") and expr.endswith(")") and _matches(expr):
        expr = expr[1:-1].strip()
    parts = _split_top(expr, "||")
    if len(parts) > 1:
        return any(evaluate(p, regs, mem) for p in parts)
    parts = _split_top(expr, "&&")
    if len(parts) > 1:
        return all(evaluate(p, regs, mem) for p in parts)
    return _eval_atom(expr, regs, mem)


def _matches(expr: str) -> bool:
    depth = 0
    for i, c in enumerate(expr):
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0 and i < len(expr) - 1:
                return False
    return depth == 0


def _split_top(expr: str, op: str) -> list[str]:
    out, depth, buf = [], 0, []
    i = 0
    while i < len(expr):
        c = expr[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        if depth == 0 and expr[i:i + len(op)] == op:
            out.append("".join(buf).strip())
            buf = []
            i += len(op)
            continue
        buf.append(c)
        i += 1
    out.append("".join(buf).strip())
    return out
