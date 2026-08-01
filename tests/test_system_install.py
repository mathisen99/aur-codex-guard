from __future__ import annotations

import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

from aur_codex_guard import __version__

PROJECT_ROOT = Path(__file__).resolve().parents[1]
INSTALLER = PROJECT_ROOT / "scripts" / "install-system.sh"
UNINSTALLER = PROJECT_ROOT / "scripts" / "uninstall-system.sh"


class SystemInstallTests(unittest.TestCase):
    def _run(self, script: Path, destination: Path) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment["DESTDIR"] = str(destination)
        return subprocess.run(
            [str(script)],
            cwd=PROJECT_ROOT,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_checkout_internal_launchers_import_outside_project_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            hook = subprocess.run(
                [str(PROJECT_ROOT / "scripts/aur-codex-guard-hook"), "--help"],
                cwd=temporary,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(hook.returncode, 0, hook.stderr)

            makepkg = subprocess.run(
                [str(PROJECT_ROOT / "scripts/aur-codex-guard-makepkg")],
                cwd=temporary,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(makepkg.returncode, 3, makepkg.stderr)
            self.assertIn("Missing trusted makepkg path", makepkg.stderr)
            self.assertNotIn("ModuleNotFoundError", makepkg.stderr)

    def test_staged_install_provides_working_plain_yay_shim(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary)
            result = self._run(INSTALLER, destination)
            self.assertEqual(result.returncode, 0, result.stderr)

            bindir = destination / "usr/local/bin"
            guard = bindir / "aur-codex-guard"
            shim = bindir / "yay"
            self.assertEqual(stat.S_IMODE(guard.stat().st_mode), 0o755)
            self.assertEqual(stat.S_IMODE(shim.stat().st_mode), 0o755)

            version = subprocess.run(
                [str(guard), "--version"],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(version.returncode, 0, version.stderr)
            self.assertIn(__version__, version.stdout)

            self.assertIn(
                "dispatch-yay",
                shim.read_text(encoding="utf-8"),
            )

            ambiguous = subprocess.run(
                [str(shim), "package-name"],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(ambiguous.returncode, 3)
            self.assertIn("yay -S package-name", ambiguous.stderr)

            removal = self._run(UNINSTALLER, destination)
            self.assertEqual(removal.returncode, 0, removal.stderr)
            self.assertFalse(shim.exists())
            self.assertFalse(guard.exists())

    def test_installer_refuses_to_replace_an_unmanaged_yay(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary)
            bindir = destination / "usr/local/bin"
            bindir.mkdir(parents=True)
            (bindir / "yay").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")

            result = self._run(INSTALLER, destination)
            self.assertEqual(result.returncode, 2)
            self.assertIn("refusing to overwrite unmanaged path", result.stderr)


if __name__ == "__main__":
    unittest.main()
