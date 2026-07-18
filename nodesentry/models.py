from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import StrEnum


class Status(StrEnum):
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"
    UNKNOWN = "unknown"
    SKIP = "skip"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class Finding:
    check_id: str
    title: str
    status: Status
    severity: Severity
    evidence: str
    remediation: str

    def as_dict(self) -> dict[str, str]:
        data = asdict(self)
        data["id"] = data.pop("check_id")
        data["status"] = self.status.value
        data["severity"] = self.severity.value
        return data


@dataclass(frozen=True)
class Report:
    status: Status
    score: int
    findings: tuple[Finding, ...]

    def as_dict(self) -> dict:
        return {
            "schema_version": "1",
            "status": self.status.value,
            "score": self.score,
            "findings": [finding.as_dict() for finding in self.findings],
        }


def summarize(findings: list[Finding]) -> Report:
    active = [item for item in findings if item.status is not Status.SKIP]
    if not active or all(item.status is Status.UNKNOWN for item in active):
        return Report(Status.UNKNOWN, 0, tuple(findings))
    weights = {Status.PASS: 100, Status.WARN: 50, Status.FAIL: 0, Status.UNKNOWN: 0}
    score = round(sum(weights[item.status] for item in active) / len(active))
    critical_fail = any(
        item.status is Status.FAIL and item.severity is Severity.CRITICAL for item in active
    )
    if critical_fail or any(item.status is Status.FAIL for item in active):
        status = Status.FAIL
    elif any(item.status is Status.WARN for item in active):
        status = Status.WARN
    elif any(item.status is Status.UNKNOWN for item in active):
        status = Status.UNKNOWN
    else:
        status = Status.PASS
    return Report(status, score, tuple(findings))
