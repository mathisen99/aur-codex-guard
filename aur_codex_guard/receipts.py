from __future__ import annotations

import hashlib
import hmac
import json
import os
import stat
import tempfile
from pathlib import Path

from .models import DeterministicReport, ReviewedFile

SESSION_KEY_ENV = "AUR_CODEX_GUARD_SESSION_KEY"
RECEIPT_DIR_ENV = "AUR_CODEX_GUARD_RECEIPT_DIR"
REAL_MAKEPKG_ENV = "AUR_CODEX_GUARD_REAL_MAKEPKG"
MAKEPKG_CONFIG_ENV = "AUR_CODEX_GUARD_MAKEPKG_CONFIG"
PKGDEST_ENV = "AUR_CODEX_GUARD_PKGDEST"
ACTIVE_ENV = "AUR_CODEX_GUARD_ACTIVE"
INTERNAL_ENV_PREFIX = "AUR_CODEX_GUARD_"


class ReceiptError(RuntimeError):
    pass


def _session_key(environment: dict[str, str] | os._Environ[str]) -> bytes:
    encoded = environment.get(SESSION_KEY_ENV, "")
    try:
        key = bytes.fromhex(encoded)
    except ValueError as error:
        raise ReceiptError("Invalid guarded-yay session key") from error
    if len(key) != 32:
        raise ReceiptError("Missing guarded-yay session key")
    return key


def _receipt_dir(environment: dict[str, str] | os._Environ[str]) -> Path:
    raw = environment.get(RECEIPT_DIR_ENV, "")
    if not raw:
        raise ReceiptError("Missing guarded-yay receipt directory")
    directory = Path(raw)
    try:
        metadata = directory.stat()
    except OSError as error:
        raise ReceiptError(f"Cannot access receipt directory: {error}") from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise ReceiptError("Unsafe guarded-yay receipt directory")
    return directory


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _receipt_path(directory: Path, root: Path) -> Path:
    name = hashlib.sha256(os.fsencode(str(root))).hexdigest() + ".json"
    return directory / name


def _file_record(item: ReviewedFile) -> dict[str, object]:
    return {"path": item.relative_path, "sha256": item.sha256, "mode": item.mode}


def write_receipts(
    report: DeterministicReport,
    environment: dict[str, str] | os._Environ[str] = os.environ,
) -> None:
    key = _session_key(environment)
    directory = _receipt_dir(environment)
    for root_text in report.package_roots:
        root = Path(root_text).resolve(strict=True)
        files = [item for item in report.reviewed_files if item.package_root == str(root)]
        payload = {
            "version": 2,
            "root": str(root),
            "root_device": root.stat().st_dev,
            "root_inode": root.stat().st_ino,
            "files": sorted((_file_record(item) for item in files), key=lambda x: str(x["path"])),
        }
        document = {
            "payload": payload,
            "hmac_sha256": hmac.new(key, _canonical(payload), hashlib.sha256).hexdigest(),
        }
        descriptor, temporary = tempfile.mkstemp(prefix=".receipt-", dir=directory)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as output:
                output.write(_canonical(document) + b"\n")
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, _receipt_path(directory, root))
        except BaseException:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
            raise


def _hash_regular_file_at(root_descriptor: int, relative: Path, expected_mode: int) -> str:
    parts = relative.parts
    if not parts:
        raise ReceiptError("Approval receipt contains an empty path")
    directory_descriptor = os.dup(root_descriptor)
    try:
        for part in parts[:-1]:
            next_descriptor = os.open(
                part,
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY,
                dir_fd=directory_descriptor,
            )
            os.close(directory_descriptor)
            directory_descriptor = next_descriptor
        descriptor = os.open(
            parts[-1],
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=directory_descriptor,
        )
    except OSError as error:
        raise ReceiptError(
            f"Reviewed file cannot be reopened safely: {relative}: {error}"
        ) from error
    finally:
        os.close(directory_descriptor)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ReceiptError(f"Reviewed path is no longer a regular file: {relative}")
        if stat.S_IMODE(metadata.st_mode) != expected_mode:
            raise ReceiptError(f"Reviewed file mode changed after approval: {relative}")
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 128 * 1024):
            digest.update(chunk)
        finished = os.fstat(descriptor)
        if (
            finished.st_size != metadata.st_size
            or finished.st_mtime_ns != metadata.st_mtime_ns
            or finished.st_ctime_ns != metadata.st_ctime_ns
        ):
            raise ReceiptError(f"Reviewed file changed while being verified: {relative}")
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def verify_receipt(
    root: Path,
    environment: dict[str, str] | os._Environ[str] = os.environ,
) -> None:
    resolved_root = root.resolve(strict=True)
    key = _session_key(environment)
    directory = _receipt_dir(environment)
    path = _receipt_path(directory, resolved_root)
    try:
        raw = path.read_bytes()
        document = json.loads(raw)
        payload = document["payload"]
        signature = document["hmac_sha256"]
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise ReceiptError(f"Missing or invalid approval receipt for {resolved_root}") from error
    expected_signature = hmac.new(key, _canonical(payload), hashlib.sha256).hexdigest()
    if not isinstance(signature, str) or not hmac.compare_digest(signature, expected_signature):
        raise ReceiptError(f"Approval receipt authentication failed for {resolved_root}")
    if payload.get("version") != 2 or payload.get("root") != str(resolved_root):
        raise ReceiptError(f"Approval receipt does not match {resolved_root}")
    try:
        root_descriptor = os.open(
            resolved_root,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY,
        )
    except OSError as error:
        raise ReceiptError(f"Reviewed package root cannot be reopened safely: {error}") from error
    root_metadata = os.fstat(root_descriptor)
    if (
        payload.get("root_device") != root_metadata.st_dev
        or payload.get("root_inode") != root_metadata.st_ino
    ):
        os.close(root_descriptor)
        raise ReceiptError(f"Reviewed package root identity changed: {resolved_root}")
    files = payload.get("files")
    if not isinstance(files, list) or not files:
        os.close(root_descriptor)
        raise ReceiptError(f"Approval receipt has no reviewed files for {resolved_root}")
    try:
        seen: set[str] = set()
        for value in files:
            if not isinstance(value, dict):
                raise ReceiptError("Approval receipt contains an invalid file record")
            relative = value.get("path")
            expected_hash = value.get("sha256")
            expected_mode = value.get("mode")
            if (
                not isinstance(relative, str)
                or not isinstance(expected_hash, str)
                or not isinstance(expected_mode, int)
            ):
                raise ReceiptError("Approval receipt contains an invalid file record")
            relative_path = Path(relative)
            if relative_path.is_absolute() or ".." in relative_path.parts or relative in seen:
                raise ReceiptError("Approval receipt contains an escaping or duplicate path")
            seen.add(relative)
            if (
                _hash_regular_file_at(root_descriptor, relative_path, expected_mode)
                != expected_hash
            ):
                raise ReceiptError(
                    f"Reviewed file changed after approval: {resolved_root / relative_path}"
                )
    finally:
        os.close(root_descriptor)


def sanitized_child_environment(
    environment: dict[str, str] | os._Environ[str] = os.environ,
) -> dict[str, str]:
    return {
        key: value for key, value in environment.items() if not key.startswith(INTERNAL_ENV_PREFIX)
    }
