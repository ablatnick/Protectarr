"""Verdicts and findings shared by every check."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import IntEnum


class Level(IntEnum):
    CLEAN = 0
    SUSPICIOUS = 1
    MALICIOUS = 2

    @property
    def label(self) -> str:
        return self.name.lower()


@dataclass(frozen=True)
class Finding:
    level: Level
    code: str
    message: str
    path: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["level"] = self.level.label
        return d


@dataclass
class Verdict:
    findings: list[Finding] = field(default_factory=list)

    @property
    def level(self) -> Level:
        return max((f.level for f in self.findings), default=Level.CLEAN)

    def add(self, level: Level, code: str, message: str, path: str = "") -> None:
        self.findings.append(Finding(level, code, message, path))

    def extend(self, other: "Verdict") -> None:
        self.findings.extend(other.findings)

    def summary(self) -> str:
        worst = [f for f in self.findings if f.level == self.level and f.level > Level.CLEAN]
        if not worst:
            return "clean"
        return "; ".join(f.message for f in worst[:3]) + (" (+more)" if len(worst) > 3 else "")

    def to_list(self) -> list[dict]:
        return [f.to_dict() for f in self.findings]
