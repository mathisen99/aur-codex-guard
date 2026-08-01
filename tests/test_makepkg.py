from __future__ import annotations

import unittest
from pathlib import Path

from aur_codex_guard.makepkg import MakepkgGuardError, _validate_archive_paths


class PackageInspectionTests(unittest.TestCase):
    def test_rejects_archive_traversal(self) -> None:
        with self.assertRaises(MakepkgGuardError):
            _validate_archive_paths(Path("bad.pkg.tar.zst"), ["../../etc/passwd"], [])

    def test_rejects_setuid_entry(self) -> None:
        listing = ["-rwsr-xr-x root/root 1 Jan 1 00:00 usr/bin/tool"]
        with self.assertRaises(MakepkgGuardError):
            _validate_archive_paths(Path("bad.pkg.tar.zst"), ["usr/bin/tool"], listing)


if __name__ == "__main__":
    unittest.main()
