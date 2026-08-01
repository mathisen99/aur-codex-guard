from __future__ import annotations

import json
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aur_codex_guard.audit import write_audit_event
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


if __name__ == "__main__":
    unittest.main()
