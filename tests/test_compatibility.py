from __future__ import annotations

import subprocess
import unittest
from unittest.mock import patch

from aur_codex_guard.compatibility import (
    CompatibilityError,
    inspect_bsdtar_support,
    inspect_makepkg_support,
)


class ArchToolCompatibilityTests(unittest.TestCase):
    def test_makepkg_accepts_compatible_patch_and_minor_versions(self) -> None:
        result = subprocess.CompletedProcess(
            ["makepkg", "--version"], 0, "makepkg (pacman) 7.9.4\n", ""
        )
        with (
            patch(
                "aur_codex_guard.compatibility.resolve_trusted_executable",
                return_value="/usr/bin/makepkg",
            ),
            patch("aur_codex_guard.compatibility.subprocess.run", return_value=result),
        ):
            support = inspect_makepkg_support()
        self.assertEqual(support.version, (7, 9, 4))

    def test_makepkg_new_major_fails_closed(self) -> None:
        result = subprocess.CompletedProcess(
            ["makepkg", "--version"], 0, "makepkg (pacman) 8.0.0\n", ""
        )
        with (
            patch(
                "aur_codex_guard.compatibility.resolve_trusted_executable",
                return_value="/usr/bin/makepkg",
            ),
            patch("aur_codex_guard.compatibility.subprocess.run", return_value=result),
            self.assertRaisesRegex(CompatibilityError, "required range"),
        ):
            inspect_makepkg_support()

    def test_bsdtar_patch_update_is_compatible(self) -> None:
        result = subprocess.CompletedProcess(
            ["bsdtar", "--version"], 0, "bsdtar 3.8.9 - libarchive 3.8.9\n", ""
        )
        with (
            patch(
                "aur_codex_guard.compatibility.resolve_trusted_executable",
                return_value="/usr/bin/bsdtar",
            ),
            patch("aur_codex_guard.compatibility.subprocess.run", return_value=result),
        ):
            support = inspect_bsdtar_support()
        self.assertEqual(support.version_text, "3.8.9")


if __name__ == "__main__":
    unittest.main()
