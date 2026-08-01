from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from aur_codex_guard.receipts import (
    RECEIPT_DIR_ENV,
    SESSION_KEY_ENV,
    ReceiptError,
    verify_receipt,
    write_receipts,
)
from aur_codex_guard.scanner import deterministic_scan


class ReceiptTests(unittest.TestCase):
    def test_receipt_detects_metadata_change(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "package"
            receipts = base / "receipts"
            root.mkdir()
            receipts.mkdir(mode=0o700)
            pkgbuild = root / "PKGBUILD"
            pkgbuild.write_text("pkgname=fixture\n", encoding="utf-8")
            report = deterministic_scan([root])
            environment = {
                SESSION_KEY_ENV: os.urandom(32).hex(),
                RECEIPT_DIR_ENV: str(receipts),
            }
            write_receipts(report, environment)
            verify_receipt(root, environment)
            pkgbuild.write_text("pkgname=changed\n", encoding="utf-8")
            with self.assertRaises(ReceiptError):
                verify_receipt(root, environment)

    def test_receipt_detects_mode_change(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "package"
            receipts = base / "receipts"
            root.mkdir()
            receipts.mkdir(mode=0o700)
            pkgbuild = root / "PKGBUILD"
            pkgbuild.write_text("pkgname=fixture\n", encoding="utf-8")
            report = deterministic_scan([root])
            environment = {
                SESSION_KEY_ENV: os.urandom(32).hex(),
                RECEIPT_DIR_ENV: str(receipts),
            }
            write_receipts(report, environment)
            pkgbuild.chmod(0o755)
            with self.assertRaises(ReceiptError):
                verify_receipt(root, environment)

    def test_receipt_rejects_intermediate_symlink_substitution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "package"
            receipts = base / "receipts"
            nested = root / "nested"
            nested.mkdir(parents=True)
            receipts.mkdir(mode=0o700)
            (root / "PKGBUILD").write_text("pkgname=fixture\n", encoding="utf-8")
            (nested / "payload.sh").write_text("echo safe\n", encoding="utf-8")
            report = deterministic_scan([root])
            environment = {
                SESSION_KEY_ENV: os.urandom(32).hex(),
                RECEIPT_DIR_ENV: str(receipts),
            }
            write_receipts(report, environment)
            moved = root / "moved"
            nested.rename(moved)
            nested.symlink_to(moved, target_is_directory=True)
            with self.assertRaises(ReceiptError):
                verify_receipt(root, environment)


if __name__ == "__main__":
    unittest.main()
