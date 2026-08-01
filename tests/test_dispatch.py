from __future__ import annotations

import unittest
from unittest.mock import patch

from aur_codex_guard.dispatch import decide_yay_dispatch, dispatch_yay


class YayDispatchTests(unittest.TestCase):
    def test_plain_yay_becomes_guarded_full_update(self) -> None:
        decision = decide_yay_dispatch([])
        self.assertEqual(decision.mode, "guard")
        self.assertEqual(decision.arguments, ["-Syu"])

    def test_default_update_options_remain_guarded(self) -> None:
        decision = decide_yay_dispatch(["--devel", "--noconfirm"])
        self.assertEqual(decision.mode, "guard")
        self.assertEqual(decision.arguments, ["-Syu", "--devel", "--noconfirm"])

    def test_installing_sync_operations_are_guarded(self) -> None:
        for arguments in (["-S", "pkg"], ["-Syu"], ["--sync", "--sysupgrade"]):
            with self.subTest(arguments=arguments):
                self.assertEqual(decide_yay_dispatch(list(arguments)).mode, "guard")

    def test_read_only_sync_and_other_operations_pass_through(self) -> None:
        for arguments in (
            ["-Ss", "browser"],
            ["--sync", "--info", "pkg"],
            ["-Qua"],
            ["--version"],
            ["-Rns", "pkg"],
        ):
            with self.subTest(arguments=arguments):
                self.assertEqual(decide_yay_dispatch(arguments).mode, "passthrough")

    def test_download_only_sync_stays_in_fail_closed_guard_path(self) -> None:
        for arguments in (["-Sw", "pkg"], ["--sync", "--downloadonly", "pkg"]):
            with self.subTest(arguments=arguments):
                self.assertEqual(decide_yay_dispatch(list(arguments)).mode, "guard")

    def test_unsupported_build_and_local_install_operations_are_blocked(self) -> None:
        for arguments in (["-B", "."], ["-U", "package.pkg.tar.zst"], ["-Y", "pkg"]):
            with self.subTest(arguments=arguments):
                self.assertEqual(decide_yay_dispatch(list(arguments)).mode, "block")

    def test_target_only_interactive_install_form_is_blocked(self) -> None:
        decision = decide_yay_dispatch(["firefox"])
        self.assertEqual(decision.mode, "block")
        self.assertIn("yay -S package-name", decision.reason)

    @patch("aur_codex_guard.dispatch.run_guarded_yay")
    def test_dispatch_uses_explicit_system_yay_for_guarded_operation(self, run_mock) -> None:
        run_mock.return_value = 17
        result = dispatch_yay([], yay_binary="/usr/bin/yay")
        self.assertEqual(result, 17)
        run_mock.assert_called_once_with(["-Syu"], yay_binary="/usr/bin/yay")

    @patch("aur_codex_guard.dispatch.os.execv")
    @patch("aur_codex_guard.dispatch.find_real_yay", return_value="/usr/bin/yay")
    def test_passthrough_replaces_shim_process(self, _find_mock, exec_mock) -> None:
        exec_mock.side_effect = OSError("fixture stop")
        with self.assertRaisesRegex(Exception, "fixture stop"):
            dispatch_yay(["-Qua"])
        exec_mock.assert_called_once_with("/usr/bin/yay", ["/usr/bin/yay", "-Qua"])


if __name__ == "__main__":
    unittest.main()
