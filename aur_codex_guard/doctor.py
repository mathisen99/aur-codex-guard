from __future__ import annotations

import json
import re
import subprocess
from dataclasses import asdict, dataclass

from .codex_review import (
    CodexReviewError,
    codex_canary_is_cached,
    ensure_codex_canary,
    inspect_codex_support,
)
from .compatibility import CompatibilityError, inspect_bsdtar_support, inspect_makepkg_support
from .yay import YayIntegrationError, find_real_yay, validate_yay_support


@dataclass(frozen=True)
class DoctorCheck:
    tool: str
    status: str
    version: str | None
    path: str | None
    detail: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _check_yay() -> DoctorCheck:
    try:
        path = find_real_yay()
        validate_yay_support(path)
        result = subprocess.run(
            [path, "--version"],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        match = re.search(r"^yay v([^\s]+)", result.stdout, re.MULTILINE)
        version = match.group(1) if match else None
        return DoctorCheck("yay", "compatible", version, path, "13.x transaction contract passed")
    except (OSError, subprocess.TimeoutExpired, YayIntegrationError) as error:
        return DoctorCheck("yay", "blocked", None, None, str(error))


def _check_arch_tool(name: str) -> DoctorCheck:
    try:
        support = inspect_makepkg_support() if name == "makepkg" else inspect_bsdtar_support()
        return DoctorCheck(
            name,
            "compatible",
            support.version_text,
            support.path,
            "supported major-version contract passed",
        )
    except CompatibilityError as error:
        return DoctorCheck(name, "blocked", None, None, str(error))


def _check_codex(*, live: bool, refresh: bool, timeout_seconds: int) -> DoctorCheck:
    try:
        if live:
            canary = ensure_codex_canary(timeout_seconds=timeout_seconds, force=refresh)
            source = "cached" if canary.cached else "live"
            detail = f"static capabilities and {source} structured-output canary passed"
            if canary.cache_warning:
                detail += f"; {canary.cache_warning}"
            return DoctorCheck(
                "codex",
                "compatible",
                canary.support.version_text,
                canary.support.path,
                detail,
            )
        support = inspect_codex_support("codex")
        cached = codex_canary_is_cached(support)
        return DoctorCheck(
            "codex",
            "compatible" if cached else "needs-canary",
            support.version_text,
            support.path,
            (
                "static capabilities and cached structured-output canary passed"
                if cached
                else "static capabilities passed; next guarded transaction will run a live canary"
            ),
        )
    except CodexReviewError as error:
        return DoctorCheck("codex", "blocked", None, None, str(error))


def run_doctor(
    *,
    live: bool = False,
    refresh: bool = False,
    timeout_seconds: int = 240,
) -> list[DoctorCheck]:
    return [
        _check_yay(),
        _check_arch_tool("makepkg"),
        _check_arch_tool("bsdtar"),
        _check_codex(live=live, refresh=refresh, timeout_seconds=timeout_seconds),
    ]


def print_doctor(checks: list[DoctorCheck], *, json_output: bool = False) -> None:
    if json_output:
        print(json.dumps({"checks": [check.to_dict() for check in checks]}, indent=2))
        return
    for check in checks:
        identity = check.tool
        if check.version:
            identity += f" {check.version}"
        print(f"{check.status:13} {identity}: {check.detail}")
