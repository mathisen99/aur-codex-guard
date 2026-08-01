from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from aur_codex_guard.scanner import deterministic_scan, package_roots_from_inputs

FIXTURES = Path(__file__).parent / "fixtures"


class ScannerTests(unittest.TestCase):
    def test_benign_fixture_is_allowed_deterministically(self) -> None:
        report = deterministic_scan([FIXTURES / "benign"])
        self.assertEqual(report.deterministic_verdict, "allow")
        self.assertIn("PKGBUILD", {item.relative_path for item in report.reviewed_files})

    def test_atomic_arch_pattern_is_blocked(self) -> None:
        report = deterministic_scan([FIXTURES / "atomic_arch_like" / "PKGBUILD"])
        self.assertEqual(report.deterministic_verdict, "block")
        rules = {finding.rule_id for finding in report.findings}
        self.assertIn("network-in-install-script", rules)
        self.assertIn("checksum-skip", rules)

    def test_hidden_unicode_is_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "PKGBUILD").write_text("pkgname=safe\u202epayload\n", encoding="utf-8")
            report = deterministic_scan([root])
        self.assertEqual(report.deterministic_verdict, "block")
        self.assertIn(
            "invisible-control-character",
            {finding.rule_id for finding in report.findings},
        )

    def test_symlink_is_not_followed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "PKGBUILD").write_text("pkgname=fixture\n", encoding="utf-8")
            (root / "escape.sh").symlink_to("/etc/passwd")
            report = deterministic_scan([root])
        self.assertEqual(report.deterministic_verdict, "block")
        self.assertIn(
            "symlink-in-build-metadata",
            {finding.rule_id for finding in report.findings},
        )

    def test_rejects_non_pkgbuild_directory(self) -> None:
        with (
            tempfile.TemporaryDirectory() as temporary,
            self.assertRaises(ValueError),
        ):
            package_roots_from_inputs([temporary])


if __name__ == "__main__":
    unittest.main()
