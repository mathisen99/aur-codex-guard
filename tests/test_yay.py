from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aur_codex_guard.cli import main
from aur_codex_guard.codex_review import CodexReviewError
from aur_codex_guard.yay import (
    YayIntegrationError,
    _session_parent_directory,
    _write_makepkg_config,
    build_yay_command,
    run_guarded_yay,
    validate_yay_arguments,
    validate_yay_support,
)


class YayIntegrationTests(unittest.TestCase):
    def test_guard_options_precede_user_arguments(self) -> None:
        command = build_yay_command(
            "/usr/bin/yay",
            "/project/hook",
            "/project/makepkg",
            "/session/makepkg.conf",
            ["-S", "example", "--noconfirm"],
        )
        self.assertEqual(
            command[:20],
            [
                "/usr/bin/yay",
                "--cleanmenu",
                "--answerclean",
                "All",
                "--editmenu",
                "--answeredit",
                "All",
                "--editor",
                "/project/hook",
                "--editorflags",
                "",
                "--redownloadall",
                "--rebuildall",
                "--combinedupgrade",
                "--makepkg",
                "/project/makepkg",
                "--mflags",
                "",
                "--makepkgconf",
                "/session/makepkg.conf",
            ],
        )
        self.assertEqual(command[-3:], ["-S", "example", "--noconfirm"])

    def test_rejects_every_spelling_of_guard_controlled_options(self) -> None:
        for arguments in (
            ["-S", "pkg", "--editor", "/bin/true"],
            ["-S", "pkg", "--makepkg=/bin/false"],
            ["-S", "pkg", "--combinedupgrade=false"],
            ["-S", "pkg", "--save=true"],
            ["-S", "pkg", "--mflags=-p /tmp/PKGBUILD"],
        ):
            with self.subTest(arguments=arguments), self.assertRaises(YayIntegrationError):
                validate_yay_arguments(arguments)

    def test_rejects_non_sync_and_non_installing_modes(self) -> None:
        for arguments in (["-U", "file.pkg.tar.zst"], ["-Scc"], ["-Ss", "pkg"], ["pkg"]):
            with self.subTest(arguments=arguments), self.assertRaises(YayIntegrationError):
                validate_yay_arguments(arguments)

    def test_accepts_explicit_sync_install_and_upgrade(self) -> None:
        validate_yay_arguments(["-S", "pkg", "--needed"])
        validate_yay_arguments(["-Syu", "--noconfirm"])

    def test_private_makepkg_config_uses_fresh_destinations(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            session = Path(temporary)
            system_config = session / "system-makepkg.conf"
            system_config.write_text("# test system config\n", encoding="utf-8")
            with patch("aur_codex_guard.yay.SYSTEM_MAKEPKG_CONFIG", system_config):
                config, pkgdest = _write_makepkg_config(session)
            content = config.read_text(encoding="utf-8")
            self.assertIn(f"PKGDEST={pkgdest}", content)
            self.assertIn(f"SRCDEST={session / 'sources'}", content)
            self.assertIn(f"BUILDDIR={session / 'build'}", content)
            self.assertEqual(config.stat().st_mode & 0o777, 0o600)

    def test_private_sessions_use_user_cache_instead_of_system_temporary_space(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cache_home = Path(temporary) / "cache"
            with patch.dict(os.environ, {"XDG_CACHE_HOME": str(cache_home)}):
                session_parent = _session_parent_directory()
            self.assertEqual(session_parent, cache_home / "aur-codex-guard")
            self.assertEqual(session_parent.stat().st_mode & 0o777, 0o700)

    def test_relative_xdg_cache_home_is_rejected(self) -> None:
        with (
            patch.dict(os.environ, {"XDG_CACHE_HOME": "relative/cache"}),
            self.assertRaisesRegex(YayIntegrationError, "must be an absolute path"),
        ):
            _session_parent_directory()

    @patch("aur_codex_guard.cli.run_guarded_yay")
    def test_cli_forwards_yay_options_without_separator(self, run_mock) -> None:
        run_mock.return_value = 0
        self.assertEqual(main(["yay", "-S", "example", "--noconfirm"]), 0)
        run_mock.assert_called_once_with(["-S", "example", "--noconfirm"])

    def test_save_is_rejected_before_yay_runs(self) -> None:
        with self.assertRaises(YayIntegrationError):
            run_guarded_yay(["--devel", "--save"])

    def test_guarded_session_wires_private_config_and_terminal_audit(self) -> None:
        lock_descriptor = os.open("/dev/null", os.O_RDONLY)
        completed = subprocess.CompletedProcess(["yay"], 0)
        with tempfile.TemporaryDirectory() as temporary:
            system_config = Path(temporary) / "system-makepkg.conf"
            system_config.write_text("# test system config\n", encoding="utf-8")
            with (
                patch.dict(
                    os.environ,
                    {"XDG_CACHE_HOME": str(Path(temporary) / "cache")},
                ),
                patch("aur_codex_guard.yay.SYSTEM_MAKEPKG_CONFIG", system_config),
                patch("aur_codex_guard.yay.find_real_yay", return_value="/usr/bin/yay"),
                patch("aur_codex_guard.yay.validate_yay_support"),
                patch("aur_codex_guard.yay.hook_executable", return_value="/project/hook"),
                patch(
                    "aur_codex_guard.yay.makepkg_executable",
                    return_value="/project/makepkg",
                ),
                patch(
                    "aur_codex_guard.yay.find_real_makepkg",
                    return_value="/usr/bin/makepkg",
                ),
                patch("aur_codex_guard.yay.inspect_makepkg_support"),
                patch("aur_codex_guard.yay.inspect_bsdtar_support"),
                patch("aur_codex_guard.yay.ensure_codex_canary"),
                patch("aur_codex_guard.yay._lock_file", return_value=lock_descriptor),
                patch("aur_codex_guard.yay.subprocess.run", return_value=completed) as run_mock,
                patch("aur_codex_guard.yay.write_transaction_event") as audit_mock,
            ):
                self.assertEqual(run_guarded_yay(["-S", "fixture"]), 0)
        command = run_mock.call_args.args[0]
        environment = run_mock.call_args.kwargs["env"]
        config = environment["AUR_CODEX_GUARD_MAKEPKG_CONFIG"]
        self.assertEqual(command[command.index("--makepkgconf") + 1], config)
        self.assertEqual(command[command.index("--makepkg") + 1], "/project/makepkg")
        self.assertIn("AUR_CODEX_GUARD_PKGDEST", environment)
        self.assertIn("XDG_CONFIG_HOME", environment)
        self.assertIn("XDG_CACHE_HOME", environment)
        audit_mock.assert_called_once_with(["-S", "fixture"], 0)

    def test_failed_codex_canary_prevents_yay_from_starting(self) -> None:
        lock_descriptor = os.open("/dev/null", os.O_RDONLY)
        with (
            patch("aur_codex_guard.yay.find_real_yay", return_value="/usr/bin/yay"),
            patch("aur_codex_guard.yay.validate_yay_support"),
            patch("aur_codex_guard.yay.hook_executable", return_value="/project/hook"),
            patch("aur_codex_guard.yay.makepkg_executable", return_value="/project/makepkg"),
            patch("aur_codex_guard.yay.find_real_makepkg", return_value="/usr/bin/makepkg"),
            patch("aur_codex_guard.yay.inspect_makepkg_support"),
            patch("aur_codex_guard.yay.inspect_bsdtar_support"),
            patch("aur_codex_guard.yay._lock_file", return_value=lock_descriptor),
            patch(
                "aur_codex_guard.yay.ensure_codex_canary",
                side_effect=CodexReviewError("fixture failure"),
            ),
            patch("aur_codex_guard.yay.subprocess.run") as run_mock,
            self.assertRaisesRegex(YayIntegrationError, "compatibility preflight failed"),
        ):
            run_guarded_yay(["-S", "fixture"])
        run_mock.assert_not_called()

    def test_yay_13_minor_updates_use_capability_contract(self) -> None:
        help_result = subprocess.CompletedProcess(
            ["yay", "--help"],
            0,
            "--editmenu --answeredit --editor --redownloadall --rebuildall --makepkg",
            "",
        )
        combined_result = subprocess.CompletedProcess(
            ["yay", "--combinedupgrade", "--help"], 0, "", ""
        )
        with patch(
            "aur_codex_guard.yay.subprocess.run",
            side_effect=[
                subprocess.CompletedProcess(
                    ["yay", "--version"], 0, "yay v13.9.2 - libalpm v16.0.1\n", ""
                ),
                help_result,
                combined_result,
            ],
        ):
            validate_yay_support("/usr/bin/yay")

    def test_yay_new_major_fails_closed(self) -> None:
        with (
            patch(
                "aur_codex_guard.yay.subprocess.run",
                return_value=subprocess.CompletedProcess(
                    ["yay", "--version"], 0, "yay v14.0.0 - libalpm v17.0.0\n", ""
                ),
            ),
            self.assertRaisesRegex(YayIntegrationError, "required range"),
        ):
            validate_yay_support("/usr/bin/yay")


if __name__ == "__main__":
    unittest.main()
