"""Wall-clock + token + iteration + phase ceiling tracker (design.md [6)."""
from dataclasses import dataclass, field


@dataclass
class Reminder:
    text: str


@dataclass
class Budget:
    wall_min: int
    iterations: int
    dollars: float
    phases: int
    input_per_mtok: float = 15.0
    output_per_mtok: float = 75.0
    _seconds: int = 0
    _tokens_in: int = 0
    _tokens_out: int = 0
    _attempts: int = 0
    _phases: int = 0
    _last_warn: set[str] = field(default_factory=set)

    def tick(self, *, seconds: int, tokens_input: int, tokens_output: int,
             attempts: int, phases: int) -> None:
        self._seconds += seconds
        self._tokens_in += tokens_input
        self._tokens_out += tokens_output
        self._attempts += attempts
        self._phases += phases

    def dollars_spent(self) -> float:
        return (self._tokens_in / 1_000_000) * self.input_per_mtok \
             + (self._tokens_out / 1_000_000) * self.output_per_mtok

    def _ratios(self) -> dict[str, float]:
        return {
            "wall": self._seconds / max(1, self.wall_min * 60),
            "iterations": self._attempts / max(1, self.iterations),
            "dollars": self.dollars_spent() / max(0.01, self.dollars),
            "phases": self._phases / max(1, self.phases),
        }

    def reminder(self) -> Reminder | None:
        ratios = self._ratios()
        triggered = [k for k, r in ratios.items()
                     if 0.75 <= r < 1.0 and k not in self._last_warn]
        if not triggered:
            return None
        for k in triggered:
            self._last_warn.add(k)
        return Reminder(text=f"Budget reminder: {', '.join(triggered)} at >=75% of ceiling. Wrap phases tighter.")

    def exhausted(self) -> str | None:
        for k, r in self._ratios().items():
            if r >= 1.0:
                return k
        return None
