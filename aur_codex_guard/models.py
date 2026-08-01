from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Literal, cast

Severity = Literal["info", "low", "medium", "high", "critical"]
Verdict = Literal["allow", "warn", "block"]

SEVERITY_RANK: dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: Severity
    file: str
    line: int | None
    message: str
    evidence: str = ""
    recommendation: str = "Review this behavior before continuing."

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class ReviewedFile:
    package: str
    package_root: str
    relative_path: str
    content: str
    sha256: str
    mode: int

    @property
    def display_path(self) -> str:
        return f"{self.package}/{self.relative_path}"


@dataclass
class DeterministicReport:
    package_roots: list[str]
    reviewed_files: list[ReviewedFile] = field(default_factory=list)
    skipped_files: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    diffs: dict[str, str] = field(default_factory=dict)

    @property
    def expected_reviewed_files(self) -> set[str]:
        return {item.display_path for item in self.reviewed_files}

    @property
    def highest_severity(self) -> Severity:
        if not self.findings:
            return "info"
        return max(
            (finding.severity for finding in self.findings),
            key=lambda severity: SEVERITY_RANK[severity],
        )

    @property
    def deterministic_verdict(self) -> Verdict:
        rank = SEVERITY_RANK[self.highest_severity]
        if rank >= SEVERITY_RANK["high"]:
            return "block"
        if rank >= SEVERITY_RANK["medium"]:
            return "warn"
        return "allow"

    def to_dict(self) -> dict[str, object]:
        return {
            "package_roots": self.package_roots,
            "reviewed_files": [item.display_path for item in self.reviewed_files],
            "file_hashes": {item.display_path: item.sha256 for item in self.reviewed_files},
            "skipped_files": self.skipped_files,
            "highest_severity": self.highest_severity,
            "verdict": self.deterministic_verdict,
            "findings": [finding.to_dict() for finding in self.findings],
        }


@dataclass
class CodexReport:
    verdict: Verdict
    confidence: Literal["low", "medium", "high"]
    summary: str
    findings: list[dict[str, object]]
    reviewed_files: list[str]
    coverage_complete: bool
    limitations: list[str]

    @classmethod
    def from_dict(cls, value: dict[str, object]) -> CodexReport:
        verdict = value.get("verdict")
        confidence = value.get("confidence")
        if verdict not in {"allow", "warn", "block"}:
            raise ValueError("Codex response has an invalid verdict")
        if confidence not in {"low", "medium", "high"}:
            raise ValueError("Codex response has invalid confidence")
        coverage_complete = value.get("coverage_complete")
        if not isinstance(coverage_complete, bool):
            raise TypeError("Codex response has invalid coverage_complete")
        findings = value.get("findings")
        reviewed_files = value.get("reviewed_files")
        limitations = value.get("limitations")
        if not isinstance(findings, list) or not all(isinstance(item, dict) for item in findings):
            raise TypeError("Codex response has invalid findings")
        if not isinstance(reviewed_files, list) or not all(
            isinstance(item, str) for item in reviewed_files
        ):
            raise TypeError("Codex response has invalid reviewed_files")
        if not isinstance(limitations, list) or not all(
            isinstance(item, str) for item in limitations
        ):
            raise TypeError("Codex response has invalid limitations")
        return cls(
            verdict=verdict,  # type: ignore[arg-type]
            confidence=confidence,  # type: ignore[arg-type]
            summary=str(value.get("summary", "")),
            findings=cast(list[dict[str, object]], findings),
            reviewed_files=cast(list[str], reviewed_files),
            coverage_complete=coverage_complete,
            limitations=cast(list[str], limitations),
        )

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass
class GateReport:
    verdict: Verdict
    reason: str
    deterministic: DeterministicReport
    codex: CodexReport | None

    @property
    def allowed(self) -> bool:
        return self.verdict == "allow"

    def to_dict(self) -> dict[str, object]:
        return {
            "verdict": self.verdict,
            "reason": self.reason,
            "deterministic": self.deterministic.to_dict(),
            "codex": self.codex.to_dict() if self.codex else None,
        }
