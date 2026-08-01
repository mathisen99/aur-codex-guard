from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from aur_codex_guard.codex_review import REQUIRED_MODEL, review_with_codex
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
        with patch("aur_codex_guard.codex_review.subprocess.Popen") as popen_mock:
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
        self.assertTrue(popen_mock.call_args.kwargs["start_new_session"])
        child_environment = popen_mock.call_args.kwargs["env"]
        self.assertFalse(any(key.startswith("AUR_CODEX_GUARD_") for key in child_environment))


if __name__ == "__main__":
    unittest.main()
