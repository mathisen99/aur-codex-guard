from __future__ import annotations

import os

from .codex_review import CodexReviewError, review_with_codex
from .models import GateReport
from .scanner import deterministic_scan


def review_packages(
    inputs: list[str | os.PathLike[str]],
    *,
    deterministic_only: bool = False,
    timeout_seconds: int = 240,
    codex_binary: str = "codex",
) -> GateReport:
    deterministic = deterministic_scan(inputs)

    if deterministic.deterministic_verdict == "block":
        return GateReport(
            "block",
            "A high or critical deterministic finding requires the operation to stop.",
            deterministic,
            None,
        )

    if deterministic_only:
        verdict = deterministic.deterministic_verdict
        return GateReport(
            verdict,
            "Codex review was explicitly disabled; deterministic findings are the final result.",
            deterministic,
            None,
        )

    try:
        codex = review_with_codex(
            deterministic,
            codex_binary=codex_binary,
            timeout_seconds=timeout_seconds,
        )
    except CodexReviewError as error:
        return GateReport(
            "block",
            f"Fail-closed because Codex review did not complete: {error}",
            deterministic,
            None,
        )

    if codex.verdict != "allow":
        return GateReport(
            "block",
            f"Codex returned {codex.verdict}; only an explicit allow can open the gate.",
            deterministic,
            codex,
        )
    if codex.confidence != "high":
        return GateReport(
            "block",
            "Codex did not return allow with high confidence, so the gate remains closed.",
            deterministic,
            codex,
        )
    if not codex.coverage_complete:
        return GateReport(
            "block",
            "Codex did not attest to complete file coverage.",
            deterministic,
            codex,
        )
    if set(codex.reviewed_files) != deterministic.expected_reviewed_files or len(
        codex.reviewed_files
    ) != len(deterministic.expected_reviewed_files):
        return GateReport(
            "block",
            "Codex's reviewed-file manifest did not exactly match the scanner input.",
            deterministic,
            codex,
        )
    if codex.limitations:
        return GateReport(
            "block",
            "Codex reported review limitations, so the gate remains closed.",
            deterministic,
            codex,
        )
    return GateReport(
        "allow",
        "Deterministic checks and Codex review both allowed the package metadata.",
        deterministic,
        codex,
    )
