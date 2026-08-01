from __future__ import annotations

import fcntl
import json
import os
import stat
from datetime import UTC, datetime
from pathlib import Path

from .codex_review import REQUIRED_MODEL, REQUIRED_REASONING_EFFORT
from .models import GateReport


class AuditError(RuntimeError):
    pass


def _audit_path() -> Path:
    state_home = os.environ.get("XDG_STATE_HOME")
    base = Path(state_home).expanduser() if state_home else Path.home() / ".local" / "state"
    if not base.is_absolute():
        raise AuditError("XDG_STATE_HOME must be an absolute path")
    return base / "aur-codex-guard" / "audit.jsonl"


def write_audit_event(report: GateReport) -> None:
    path = _audit_path()
    try:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        parent = path.parent.stat()
        if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid():
            raise AuditError("Audit directory is not owned by the current user")
        os.chmod(path.parent, 0o700)
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
        )
        try:
            os.fchmod(descriptor, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            event = {
                "timestamp": datetime.now(UTC).isoformat(),
                "verdict": report.verdict,
                "model": REQUIRED_MODEL,
                "reasoning_effort": REQUIRED_REASONING_EFFORT,
                "packages": report.deterministic.package_roots,
                "files": {
                    item.display_path: item.sha256 for item in report.deterministic.reviewed_files
                },
                "deterministic_rules": sorted(
                    {item.rule_id for item in report.deterministic.findings}
                ),
                "codex_verdict": report.codex.verdict if report.codex else None,
                "codex_confidence": report.codex.confidence if report.codex else None,
            }
            os.write(descriptor, json.dumps(event, sort_keys=True).encode("utf-8") + b"\n")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except AuditError:
        raise
    except OSError as error:
        raise AuditError(f"Could not append the audit log: {error}") from error
