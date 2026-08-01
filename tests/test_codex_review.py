from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from aur_codex_guard.codex_review import (
    DISABLED_CODEX_FEATURES,
    REQUIRED_MODEL,
    REVIEW_PROMPT,
    CodexReviewError,
    CodexSupport,
    _review_once,
    ensure_codex_canary,
    inspect_codex_support,
    review_with_codex,
)
from aur_codex_guard.models import CodexReport
from aur_codex_guard.scanner import deterministic_scan


class CodexExecutionTests(unittest.TestCase):
    def test_prompt_calibrates_by_trust_boundary_not_language(self) -> None:
        self.assertIn("not by programming language", REVIEW_PROMPT)
        self.assertIn("every known or unfamiliar toolchain", REVIEW_PROMPT)
        self.assertIn("restoring or resolving project dependencies", REVIEW_PROMPT)
        self.assertIn("running unit, integration, smoke", REVIEW_PROMPT)
        self.assertIn("writing outside the build workspace and $pkgdir", REVIEW_PROMPT)
        self.assertIn("Findings must name the crossed boundary", REVIEW_PROMPT)

    def test_newer_codex_uses_capability_contract_instead_of_exact_pin(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            executable = Path(temporary) / "codex"
            executable.write_bytes(b"fixture codex binary")
            help_text = (
                "--config --disable --strict-config --model --sandbox --cd "
                "--skip-git-repo-check --ephemeral --ignore-user-config --ignore-rules "
                "--output-schema --color"
            )
            features = "\n".join(f"{feature} stable false" for feature in DISABLED_CODEX_FEATURES)
            with (
                patch(
                    "aur_codex_guard.codex_review.resolve_trusted_executable",
                    return_value=str(executable),
                ),
                patch(
                    "aur_codex_guard.codex_review.subprocess.run",
                    side_effect=[
                        subprocess.CompletedProcess(
                            ["codex", "--version"], 0, "codex-cli 0.146.0\n", ""
                        ),
                        subprocess.CompletedProcess(["codex", "exec", "--help"], 0, help_text, ""),
                        subprocess.CompletedProcess(["codex", "features", "list"], 0, features, ""),
                    ],
                ),
            ):
                support = inspect_codex_support("codex")
        self.assertEqual(support.version_text, "0.146.0")

    def test_missing_codex_security_capability_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            executable = Path(temporary) / "codex"
            executable.write_bytes(b"fixture codex binary")
            with (
                patch(
                    "aur_codex_guard.codex_review.resolve_trusted_executable",
                    return_value=str(executable),
                ),
                patch(
                    "aur_codex_guard.codex_review.subprocess.run",
                    side_effect=[
                        subprocess.CompletedProcess(
                            ["codex", "--version"], 0, "codex-cli 0.146.0\n", ""
                        ),
                        subprocess.CompletedProcess(
                            ["codex", "exec", "--help"], 0, "--model --sandbox", ""
                        ),
                    ],
                ),
                self.assertRaisesRegex(CodexReviewError, "missing required exec capabilities"),
            ):
                inspect_codex_support("codex")

    def test_successful_canary_is_cached_by_binary_identity(self) -> None:
        support = CodexSupport("/usr/bin/codex", (0, 146, 0), "a" * 64)

        def allow_canary(report, **_kwargs):
            return CodexReport(
                verdict="allow",
                confidence="high",
                summary="Harmless fixture.",
                findings=[],
                reviewed_files=sorted(report.expected_reviewed_files),
                coverage_complete=True,
                limitations=[],
            )

        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.dict("os.environ", {"XDG_CACHE_HOME": temporary}),
            patch(
                "aur_codex_guard.codex_review.inspect_codex_support",
                return_value=support,
            ),
            patch(
                "aur_codex_guard.codex_review._review_once",
                side_effect=allow_canary,
            ) as review_mock,
        ):
            live_start = MagicMock()
            first = ensure_codex_canary(on_live_start=live_start)
            second = ensure_codex_canary(on_live_start=live_start)
        self.assertFalse(first.cached)
        self.assertTrue(second.cached)
        review_mock.assert_called_once()
        live_start.assert_called_once_with(support)

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
