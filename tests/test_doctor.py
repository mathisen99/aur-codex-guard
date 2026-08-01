from __future__ import annotations

import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

from aur_codex_guard.cli import EXIT_ERROR, main
from aur_codex_guard.doctor import DoctorCheck, print_doctor


class DoctorTests(unittest.TestCase):
    def test_refresh_requires_live_canary(self) -> None:
        with redirect_stderr(io.StringIO()):
            self.assertEqual(main(["doctor", "--refresh"]), EXIT_ERROR)

    def test_blocked_tool_makes_doctor_fail(self) -> None:
        checks = [DoctorCheck("codex", "blocked", None, None, "missing capability")]
        with (
            patch("aur_codex_guard.cli.run_doctor", return_value=checks),
            patch("aur_codex_guard.cli.print_doctor"),
        ):
            self.assertEqual(main(["doctor"]), EXIT_ERROR)

    def test_json_output_is_machine_readable(self) -> None:
        checks = [
            DoctorCheck(
                "codex",
                "compatible",
                "0.146.0",
                "/usr/bin/codex",
                "canary passed",
            )
        ]
        output = io.StringIO()
        with redirect_stdout(output):
            print_doctor(checks, json_output=True)
        self.assertEqual(json.loads(output.getvalue())["checks"][0]["status"], "compatible")


if __name__ == "__main__":
    unittest.main()
