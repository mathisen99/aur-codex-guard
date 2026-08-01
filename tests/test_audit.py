from __future__ import annotations

import json
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aur_codex_guard.audit import write_audit_event, write_transaction_event
from aur_codex_guard.models import GateReport
from aur_codex_guard.scanner import deterministic_scan


class AuditTests(unittest.TestCase):
    def test_audit_log_is_private_and_excludes_file_content(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            package = base / "package"
            state = base / "state"
            package.mkdir()
            secret_marker = "fixture-content-must-not-be-logged"
            (package / "PKGBUILD").write_text(
                f"pkgname=fixture\n# {secret_marker}\n", encoding="utf-8"
            )
            deterministic = deterministic_scan([package])
            report = GateReport("allow", "test", deterministic, None)
            with patch.dict("os.environ", {"XDG_STATE_HOME": str(state)}, clear=False):
                write_audit_event(report)
            path = state / "aur-codex-guard" / "audit.jsonl"
            raw = path.read_text(encoding="utf-8")
            event = json.loads(raw)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertNotIn(secret_marker, raw)
            self.assertEqual(event["verdict"], "allow")
            self.assertEqual(event["phase"], "review")

    def test_terminal_event_hashes_arguments_instead_of_logging_them(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "state"
            marker = "private-package-name"
            with patch.dict("os.environ", {"XDG_STATE_HOME": str(state)}, clear=False):
                write_transaction_event(["-S", marker], 7)
            raw = (state / "aur-codex-guard" / "audit.jsonl").read_text(encoding="utf-8")
            event = json.loads(raw)
            self.assertNotIn(marker, raw)
            self.assertEqual(event["phase"], "transaction-finished")
            self.assertEqual(event["yay_exit_code"], 7)

    def test_audit_log_rotates_at_the_size_limit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "state"
            with (
                patch.dict("os.environ", {"XDG_STATE_HOME": str(state)}, clear=False),
                patch("aur_codex_guard.audit.MAX_AUDIT_BYTES", 1),
            ):
                write_transaction_event(["-S", "first"], 0)
                write_transaction_event(["-S", "second"], 0)
            directory = state / "aur-codex-guard"
            self.assertTrue((directory / "audit.jsonl").is_file())
            self.assertTrue((directory / "audit.jsonl.1").is_file())


if __name__ == "__main__":
    unittest.main()
