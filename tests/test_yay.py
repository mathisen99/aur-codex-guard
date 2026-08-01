from __future__ import annotations

import unittest
from unittest.mock import patch

from aur_codex_guard.cli import main
from aur_codex_guard.yay import YayIntegrationError, build_yay_command, run_guarded_yay


class YayIntegrationTests(unittest.TestCase):
    def test_guard_options_are_appended_after_user_arguments(self) -> None:
        command = build_yay_command(
            "/usr/bin/yay",
            "/project/hook",
            ["-S", "example", "--noeditmenu", "--editor", "/bin/true"],
        )
        self.assertEqual(command[:2], ["/usr/bin/yay", "-S"])
        self.assertEqual(
            command[-9:],
            [
                "--editmenu",
                "--answeredit",
                "All",
                "--editor",
                "/project/hook",
                "--editorflags",
                "",
                "--redownloadall",
                "--rebuildall",
            ],
        )

    @patch("aur_codex_guard.cli.run_guarded_yay")
    def test_cli_forwards_yay_options_without_separator(self, run_mock) -> None:
        run_mock.return_value = 0
        self.assertEqual(main(["yay", "-S", "example", "--noconfirm"]), 0)
        run_mock.assert_called_once_with(["-S", "example", "--noconfirm"])

    def test_save_is_rejected_before_yay_runs(self) -> None:
        with self.assertRaises(YayIntegrationError):
            run_guarded_yay(["--devel", "--save"])


if __name__ == "__main__":
    unittest.main()
