from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass

from .executables import ExecutableTrustError, resolve_trusted_executable

Version = tuple[int, int, int]

MINIMUM_MAKEPKG_VERSION: Version = (7, 1, 0)
MAXIMUM_MAKEPKG_VERSION: Version = (8, 0, 0)
MINIMUM_BSDTAR_VERSION: Version = (3, 8, 0)
MAXIMUM_BSDTAR_VERSION: Version = (4, 0, 0)


class CompatibilityError(RuntimeError):
    pass


@dataclass(frozen=True)
class ToolSupport:
    name: str
    path: str
    version: Version

    @property
    def version_text(self) -> str:
        return ".".join(str(part) for part in self.version)


def parse_version(text: str, pattern: re.Pattern[str], label: str) -> Version:
    match = pattern.search(text)
    if not match:
        raise CompatibilityError(f"Could not parse {label} version")
    return (int(match.group(1)), int(match.group(2)), int(match.group(3)))


def _inspect_version(
    candidate: str,
    *,
    label: str,
    pattern: re.Pattern[str],
    minimum: Version,
    maximum: Version,
) -> ToolSupport:
    try:
        resolved = resolve_trusted_executable(candidate, label)
    except ExecutableTrustError as error:
        raise CompatibilityError(str(error)) from error
    try:
        result = subprocess.run(
            [resolved, "--version"],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CompatibilityError(f"Could not inspect {label} version: {error}") from error
    if result.returncode != 0:
        raise CompatibilityError(f"Could not inspect {label} version")
    version = parse_version(result.stdout + result.stderr, pattern, label)
    if version < minimum or version >= maximum:
        lower = ".".join(str(part) for part in minimum)
        upper = ".".join(str(part) for part in maximum)
        raise CompatibilityError(
            f"Unsupported {label} version {'.'.join(str(part) for part in version)}; "
            f"required range is >= {lower}, < {upper}"
        )
    return ToolSupport(label, resolved, version)


def inspect_makepkg_support(candidate: str = "makepkg") -> ToolSupport:
    return _inspect_version(
        candidate,
        label="makepkg",
        pattern=re.compile(r"makepkg \(pacman\) (\d+)\.(\d+)\.(\d+)"),
        minimum=MINIMUM_MAKEPKG_VERSION,
        maximum=MAXIMUM_MAKEPKG_VERSION,
    )


def inspect_bsdtar_support(candidate: str = "bsdtar") -> ToolSupport:
    return _inspect_version(
        candidate,
        label="bsdtar",
        pattern=re.compile(r"\bbsdtar (\d+)\.(\d+)\.(\d+)\b"),
        minimum=MINIMUM_BSDTAR_VERSION,
        maximum=MAXIMUM_BSDTAR_VERSION,
    )
