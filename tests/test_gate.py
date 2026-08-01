from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import patch

from aur_codex_guard.codex_review import CodexReviewError, build_review_input
from aur_codex_guard.gate import review_packages
from aur_codex_guard.models import CodexReport
from aur_codex_guard.scanner import deterministic_scan

FIXTURES = Path(__file__).parent / "fixtures"


def codex_report(verdict: str = "allow", confidence: str = "high") -> CodexReport:
    return CodexReport(
        verdict=verdict,  # type: ignore[arg-type]
        confidence=confidence,  # type: ignore[arg-type]
        summary="fixture response",
        findings=[],
        reviewed_files=["benign/PKGBUILD", "benign/hello.sh"],
        coverage_complete=True,
        limitations=[],
    )


class GateTests(unittest.TestCase):
    @patch("aur_codex_guard.gate.review_with_codex")
    def test_allows_only_after_codex_allow(self, review_mock) -> None:
        review_mock.return_value = codex_report()
        report = review_packages([FIXTURES / "benign"])
        self.assertTrue(report.allowed)

    @patch("aur_codex_guard.gate.review_with_codex")
    def test_complete_codex_warn_requires_human_decision(self, review_mock) -> None:
        review_mock.return_value = codex_report("warn", "medium")
        report = review_packages([FIXTURES / "benign"])
        self.assertEqual(report.verdict, "warn")

    @patch("aur_codex_guard.gate.review_with_codex")
    def test_low_confidence_warn_cannot_be_overridden(self, review_mock) -> None:
        review_mock.return_value = codex_report("warn", "low")
        report = review_packages([FIXTURES / "benign"])
        self.assertEqual(report.verdict, "block")

    @patch("aur_codex_guard.gate.review_with_codex")
    def test_incomplete_warn_cannot_be_overridden(self, review_mock) -> None:
        response = codex_report("warn", "high")
        response.coverage_complete = False
        review_mock.return_value = response
        report = review_packages([FIXTURES / "benign"])
        self.assertEqual(report.verdict, "block")

    @patch("aur_codex_guard.gate.review_with_codex")
    def test_warn_with_limitations_cannot_be_overridden(self, review_mock) -> None:
        response = codex_report("warn", "high")
        response.limitations = ["Could not inspect a supplied file"]
        review_mock.return_value = response
        report = review_packages([FIXTURES / "benign"])
        self.assertEqual(report.verdict, "block")

    @patch("aur_codex_guard.gate.review_with_codex")
    def test_low_confidence_allow_closes_gate(self, review_mock) -> None:
        review_mock.return_value = codex_report("allow", "low")
        report = review_packages([FIXTURES / "benign"])
        self.assertEqual(report.verdict, "block")

    @patch("aur_codex_guard.gate.review_with_codex")
    def test_medium_confidence_allow_closes_gate(self, review_mock) -> None:
        review_mock.return_value = codex_report("allow", "medium")
        report = review_packages([FIXTURES / "benign"])
        self.assertEqual(report.verdict, "block")

    @patch("aur_codex_guard.gate.review_with_codex")
    def test_incomplete_file_manifest_closes_gate(self, review_mock) -> None:
        response = codex_report()
        response.reviewed_files = ["benign/PKGBUILD"]
        review_mock.return_value = response
        report = review_packages([FIXTURES / "benign"])
        self.assertEqual(report.verdict, "block")

    @patch("aur_codex_guard.gate.review_with_codex")
    def test_limitations_close_gate(self, review_mock) -> None:
        response = codex_report()
        response.limitations = ["Could not inspect hello.sh"]
        review_mock.return_value = response
        report = review_packages([FIXTURES / "benign"])
        self.assertEqual(report.verdict, "block")

    @patch("aur_codex_guard.gate.review_with_codex")
    def test_allow_with_any_finding_closes_gate(self, review_mock) -> None:
        response = codex_report()
        response.findings = [{"severity": "critical", "title": "inconsistent"}]
        review_mock.return_value = response
        report = review_packages([FIXTURES / "benign"])
        self.assertEqual(report.verdict, "block")
        self.assertIn("inconsistent", report.reason)

    @patch("aur_codex_guard.gate.review_with_codex")
    def test_codex_failure_closes_gate(self, review_mock) -> None:
        review_mock.side_effect = CodexReviewError("offline")
        report = review_packages([FIXTURES / "benign"])
        self.assertEqual(report.verdict, "block")
        self.assertIn("offline", report.reason)

    @patch("aur_codex_guard.gate.review_with_codex")
    def test_critical_static_finding_short_circuits_codex(self, review_mock) -> None:
        report = review_packages([FIXTURES / "atomic_arch_like"])
        self.assertEqual(report.verdict, "block")
        review_mock.assert_not_called()

    def test_untrusted_content_is_delimited(self) -> None:
        report = deterministic_scan([FIXTURES / "benign"])
        bundle = build_review_input(report)
        self.assertIn("BEGIN UNTRUSTED FILE", bundle)
        self.assertIn("END UNTRUSTED FILE", bundle)


if __name__ == "__main__":
    unittest.main()
