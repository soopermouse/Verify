from __future__ import annotations
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class ReviewStatus(str, Enum):
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"
    SKIP = "skip"


@dataclass(frozen=True)
class ToolCommand:
    name: str
    argv: tuple[str, ...]
    category: str
    optional: bool = True


@dataclass
class CheckResult:
    name: str
    category: str
    status: ReviewStatus
    command: list[str] = field(default_factory=list)
    returncode: int | None = None
    duration_ms: int = 0
    stdout: str = ""
    stderr: str = ""
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        return data


@dataclass
class StackProfile:
    root: str
    languages: list[str] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)
    manifests: list[str] = field(default_factory=list)
    test_frameworks: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ReviewReport:
    root: str
    stack: StackProfile
    trust: str
    checks: list[CheckResult]
    status: ReviewStatus
    score: int
    passed: int
    warnings: int
    failed: int
    skipped: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": self.root,
            "stack": self.stack.to_dict(),
            "trust": self.trust,
            "checks": [c.to_dict() for c in self.checks],
            "status": self.status.value,
            "score": self.score,
            "summary": {
                "passed": self.passed,
                "warnings": self.warnings,
                "failed": self.failed,
                "skipped": self.skipped,
            },
        }
