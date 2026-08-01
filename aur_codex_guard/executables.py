from __future__ import annotations

import os
import shutil
import stat
from pathlib import Path


class ExecutableTrustError(RuntimeError):
    pass


def resolve_trusted_executable(candidate: str, label: str) -> str:
    resolved = shutil.which(candidate)
    if not resolved:
        raise ExecutableTrustError(f"Could not find {label} executable: {candidate}")
    try:
        path = Path(resolved).resolve(strict=True)
        metadata = path.stat()
    except OSError as error:
        raise ExecutableTrustError(f"Could not inspect {label} executable: {error}") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or not os.access(path, os.X_OK)
    ):
        raise ExecutableTrustError(f"Unsafe {label} executable: {path}")
    return str(path)
