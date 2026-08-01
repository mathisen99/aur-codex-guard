from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import patch

from aur_codex_guard.cli import EXIT_ALLOW, EXIT_BLOCK, hook_main
from aur_codex_guard.models import CodexReport, GateReport
from aur_codex_guard.scanner import deterministic_scan

FIXTURES = Path(__file__).parent / "fixtures"


def warning_report() -> GateReport:
    deterministic = deterministic_scan([FIXTURES / "benign"])
    codex = CodexReport(
        verdict="warn",
        confidence="high",
        summary="Conventional build-time dependency download requires human review.",
        findings=[{"severity": "medium", "title": "Build-time network access"}],
        reviewed_files=sorted(deterministic.expected_reviewed_files),
        coverage_complete=True,
        limitations=[],
    )
    return GateReport(
        "warn",
        "Codex found behavior that requires explicit human approval before continuing.",
        deterministic,
        codex,
    )


class HookWarningTests(unittest.TestCase):
    def test_explicit_warning_acceptance_creates_receipt_and_override_audit(self) -> None:
        report = warning_report()
        with (
            patch.dict("os.environ", {"AUR_CODEX_GUARD_ACTIVE": "1"}),
            patch("aur_codex_guard.cli.review_packages", return_value=report),
            patch("aur_codex_guard.cli.print_review_start") as start_mock,
            patch("aur_codex_guard.cli.print_human"),
            patch("aur_codex_guard.cli.prompt_warning_approval", return_value=True),
            patch("aur_codex_guard.cli.write_receipts") as receipt_mock,
            patch("aur_codex_guard.cli.write_audit_event") as audit_mock,
            patch("aur_codex_guard.cli.print_warning_decision") as decision_mock,
        ):
            result = hook_main(["/tmp/fvs2/PKGBUILD"])
        self.assertEqual(result, EXIT_ALLOW)
        start_mock.assert_called_once_with(["/tmp/fvs2/PKGBUILD"])
        receipt_mock.assert_called_once_with(report.deterministic)
        accepted_report = audit_mock.call_args.args[0]
        self.assertEqual(accepted_report.verdict, "allow")
        self.assertTrue(accepted_report.human_override)
        self.assertEqual(accepted_report.codex.verdict, "warn")
        decision_mock.assert_called_once_with(True)

    def test_declined_warning_remains_blocked(self) -> None:
        report = warning_report()
        with (
            patch.dict("os.environ", {"AUR_CODEX_GUARD_ACTIVE": "1"}),
            patch("aur_codex_guard.cli.review_packages", return_value=report),
            patch("aur_codex_guard.cli.print_review_start"),
            patch("aur_codex_guard.cli.print_human"),
            patch("aur_codex_guard.cli.prompt_warning_approval", return_value=False),
            patch("aur_codex_guard.cli.write_receipts") as receipt_mock,
            patch("aur_codex_guard.cli.write_audit_event") as audit_mock,
            patch("aur_codex_guard.cli.print_warning_decision") as decision_mock,
        ):
            result = hook_main(["/tmp/fvs2/PKGBUILD"])
        self.assertEqual(result, EXIT_BLOCK)
        receipt_mock.assert_not_called()
        audit_mock.assert_called_once_with(report)
        decision_mock.assert_called_once_with(False)


if __name__ == "__main__":
    unittest.main()
