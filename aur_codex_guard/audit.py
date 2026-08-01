from __future__ import annotations

import fcntl
import hashlib
import json
import os
import stat
from datetime import UTC, datetime
from pathlib import Path

from .codex_review import REQUIRED_MODEL, REQUIRED_REASONING_EFFORT
from .models import GateReport


class AuditError(RuntimeError):
    pass


MAX_AUDIT_BYTES = 5 * 1024 * 1024


def _audit_path() -> Path:
    state_home = os.environ.get("XDG_STATE_HOME")
    base = Path(state_home).expanduser() if state_home else Path.home() / ".local" / "state"
    if not base.is_absolute():
        raise AuditError("XDG_STATE_HOME must be an absolute path")
    return base / "aur-codex-guard" / "audit.jsonl"


def _validate_private_file(path: Path) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise AuditError(f"Unsafe audit file: {path}")


def _append_event(event: dict[str, object]) -> None:
    path = _audit_path()
    try:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        parent = path.parent.stat()
        if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid():
            raise AuditError("Audit directory is not owned by the current user")
        os.chmod(path.parent, 0o700)
        lock_path = path.with_suffix(".lock")
        _validate_private_file(lock_path)
        lock_descriptor = os.open(
            lock_path,
            os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
        )
        try:
            os.fchmod(lock_descriptor, 0o600)
            fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
            _validate_private_file(path)
            if path.exists() and path.stat().st_size >= MAX_AUDIT_BYTES:
                rotated = path.with_suffix(".jsonl.1")
                _validate_private_file(rotated)
                os.replace(path, rotated)
            descriptor = os.open(
                path,
                os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o600,
            )
            try:
                metadata = os.fstat(descriptor)
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid():
                    raise AuditError("Unsafe audit log")
                os.fchmod(descriptor, 0o600)
                os.write(descriptor, json.dumps(event, sort_keys=True).encode("utf-8") + b"\n")
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        finally:
            os.close(lock_descriptor)
    except AuditError:
        raise
    except OSError as error:
        raise AuditError(f"Could not append the audit log: {error}") from error


def write_audit_event(report: GateReport) -> None:
    event: dict[str, object] = {
        "timestamp": datetime.now(UTC).isoformat(),
        "phase": "review",
        "verdict": report.verdict,
        "model": REQUIRED_MODEL,
        "reasoning_effort": REQUIRED_REASONING_EFFORT,
        "packages": report.deterministic.package_roots,
        "files": {item.display_path: item.sha256 for item in report.deterministic.reviewed_files},
        "deterministic_rules": sorted({item.rule_id for item in report.deterministic.findings}),
        "codex_verdict": report.codex.verdict if report.codex else None,
        "codex_confidence": report.codex.confidence if report.codex else None,
    }
    _append_event(event)


def write_transaction_event(arguments: list[str], returncode: int) -> None:
    payload = "\0".join(arguments).encode("utf-8", errors="surrogateescape")
    _append_event(
        {
            "timestamp": datetime.now(UTC).isoformat(),
            "phase": "transaction-finished",
            "yay_exit_code": returncode,
            "arguments_sha256": hashlib.sha256(payload).hexdigest(),
        }
    )
