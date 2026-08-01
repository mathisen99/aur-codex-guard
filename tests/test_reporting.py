from __future__ import annotations

import io
import os
import unittest
from pathlib import Path
from unittest.mock import patch

from aur_codex_guard.models import CodexReport, GateReport
from aur_codex_guard.reporting import (
    print_canary_start,
    print_human,
    print_review_start,
    prompt_warning_approval,
)
from aur_codex_guard.scanner import deterministic_scan

FIXTURES = Path(__file__).parent / "fixtures"


class TtyBuffer(io.StringIO):
    def isatty(self) -> bool:
        return True


def allowed_report() -> GateReport:
    deterministic = deterministic_scan([FIXTURES / "benign"])
    codex = CodexReport(
        verdict="allow",
        confidence="high",
        summary="No suspicious behavior found in the reviewed package metadata.",
        findings=[],
        reviewed_files=sorted(deterministic.expected_reviewed_files),
        coverage_complete=True,
        limitations=[],
    )
    return GateReport(
        verdict="allow",
        reason="Deterministic checks and Codex review both allowed the package metadata.",
        deterministic=deterministic,
        codex=codex,
    )


class HumanReportingTests(unittest.TestCase):
    def test_terminal_report_has_structured_color_output(self) -> None:
        output = TtyBuffer()
        with patch.dict(os.environ, {"TERM": "xterm-256color"}, clear=True):
            print_human(allowed_report(), stream=output)
        rendered = output.getvalue()
        self.assertIn("\x1b[36m", rendered)
        self.assertIn("\x1b[32m", rendered)
        self.assertIn("AUR Codex Guard", rendered)
        self.assertIn("Result", rendered)
        self.assertIn("PASS", rendered)
        self.assertIn("Codex review", rendered)
        self.assertIn("gpt-5.6-sol", rendered)

    def test_redirected_report_is_plain_text(self) -> None:
        output = io.StringIO()
        print_human(allowed_report(), stream=output)
        rendered = output.getvalue()
        self.assertNotIn("\x1b[", rendered)
        self.assertIn("==> AUR Codex Guard", rendered)
        self.assertIn("Summary", rendered)

    def test_no_color_environment_overrides_tty(self) -> None:
        output = TtyBuffer()
        with patch.dict(os.environ, {"NO_COLOR": "1", "TERM": "xterm-256color"}, clear=True):
            print_human(allowed_report(), stream=output)
        self.assertNotIn("\x1b[", output.getvalue())

    def test_review_start_identifies_package_and_expected_wait(self) -> None:
        output = io.StringIO()
        print_review_start(["/tmp/session/fvs2/PKGBUILD"], stream=output, color=False)
        rendered = output.getvalue()
        self.assertIn("Running AUR Codex Guard security review", rendered)
        self.assertIn("fvs2", rendered)
        self.assertIn("few minutes", rendered)

    def test_canary_start_explains_one_time_wait(self) -> None:
        output = io.StringIO()
        print_canary_start("0.146.0", stream=output, color=False)
        rendered = output.getvalue()
        self.assertIn("one-time AUR Codex Guard compatibility check", rendered)
        self.assertIn("0.146.0", rendered)
        self.assertIn("few minutes", rendered)

    def test_warning_requires_explicit_interactive_yes(self) -> None:
        output = TtyBuffer()
        self.assertTrue(
            prompt_warning_approval(
                input_stream=TtyBuffer("yes\n"),
                output_stream=output,
                color=False,
            )
        )
        self.assertFalse(
            prompt_warning_approval(
                input_stream=TtyBuffer("\n"),
                output_stream=output,
                color=False,
            )
        )
        self.assertIn("Proceed after reviewing these concerns?", output.getvalue())

    def test_warning_fails_closed_without_interactive_input(self) -> None:
        output = io.StringIO()
        self.assertFalse(
            prompt_warning_approval(
                input_stream=io.StringIO("yes\n"),
                output_stream=output,
                color=False,
            )
        )
        self.assertIn("Interactive approval is unavailable", output.getvalue())


if __name__ == "__main__":
    unittest.main()
