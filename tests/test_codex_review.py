from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from aur_codex_guard.codex_review import (
    DISABLED_CODEX_FEATURES,
    REQUIRED_MODEL,
    _review_once,
    review_with_codex,
)
from aur_codex_guard.scanner import deterministic_scan


class CodexExecutionTests(unittest.TestCase):
    def test_required_model_reasoning_and_isolation_are_forced(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "package"
            root.mkdir()
            (root / "PKGBUILD").write_text("pkgname=fixture\n", encoding="utf-8")
            report = deterministic_scan([root])

        response = {
            "verdict": "allow",
            "confidence": "high",
            "summary": "No suspicious metadata found.",
            "findings": [],
            "reviewed_files": ["package/PKGBUILD"],
            "coverage_complete": True,
            "limitations": [],
        }
        with (
            patch(
                "aur_codex_guard.codex_review.validate_codex_support",
                return_value="/usr/bin/codex",
            ),
            patch("aur_codex_guard.codex_review.subprocess.Popen") as popen_mock,
        ):
            process = MagicMock()
            process.returncode = 0
            process.communicate.return_value = (json.dumps(response), "")
            popen_mock.return_value = process
            result = review_with_codex(report)

        self.assertEqual(result.verdict, "allow")
        command = popen_mock.call_args.args[0]
        self.assertIn("--strict-config", command)
        self.assertEqual(command[command.index("--model") + 1], REQUIRED_MODEL)
        self.assertIn('model_reasoning_effort="high"', command)
        self.assertEqual(command[command.index("--sandbox") + 1], "read-only")
        self.assertIn('approval_policy="never"', command)
        self.assertIn("project_doc_max_bytes=0", command)
        for feature in DISABLED_CODEX_FEATURES:
            self.assertIn(feature, command)
        self.assertTrue(popen_mock.call_args.kwargs["start_new_session"])
        child_environment = popen_mock.call_args.kwargs["env"]
        self.assertFalse(any(key.startswith("AUR_CODEX_GUARD_") for key in child_environment))

    def test_timeout_kills_the_codex_process_group(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "package"
            root.mkdir()
            (root / "PKGBUILD").write_text("pkgname=fixture\n", encoding="utf-8")
            report = deterministic_scan([root])
        with (
            patch("aur_codex_guard.codex_review.subprocess.Popen") as popen_mock,
            patch("aur_codex_guard.codex_review._kill_process_group") as kill_mock,
        ):
            process = MagicMock()
            process.communicate.side_effect = __import__("subprocess").TimeoutExpired("codex", 1)
            popen_mock.return_value = process
            with self.assertRaisesRegex(Exception, "timed out"):
                _review_once(report, codex_binary="/usr/bin/codex", timeout_seconds=1)
            kill_mock.assert_called_once_with(process)


if __name__ == "__main__":
    unittest.main()
