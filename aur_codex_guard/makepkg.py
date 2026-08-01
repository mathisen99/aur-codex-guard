from __future__ import annotations

import os
import re
import stat
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path, PurePosixPath

from .executables import ExecutableTrustError, resolve_trusted_executable
from .receipts import (
    MAKEPKG_CONFIG_ENV,
    PKGDEST_ENV,
    REAL_MAKEPKG_ENV,
    ReceiptError,
    sanitized_child_environment,
    verify_receipt,
)
from .scanner import _scan_content

PACKAGE_SUFFIX = re.compile(r"\.pkg\.tar(?:\.(?:zst|xz|gz|bz2|lz4|lrz|lzo|Z))?$")
NO_PACKAGE_OPTIONS = {
    "--allsource",
    "--clean",
    "--geninteg",
    "--packagelist",
    "--printsrcinfo",
    "--source",
    "--verifysource",
}
ALLOWED_MAKEPKG_FLAGS = {
    "--clean",
    "--cleanbuild",
    "--force",
    "--holdver",
    "--ignorearch",
    "--nobuild",
    "--noconfirm",
    "--noextract",
    "--noprepare",
    "--packagelist",
    "--skippgpcheck",
    "--verifysource",
    "-C",
    "-Cc",
    "-c",
    "-f",
}
CONTROL_PATH_PREFIXES = (
    "etc/sudoers.d/",
    "usr/lib/systemd/system-preset/",
    "usr/lib/sysusers.d/",
    "usr/lib/tmpfiles.d/",
    "usr/lib/udev/rules.d/",
    "usr/share/libalpm/hooks/",
)
CONTROL_PATHS = {".BUILDINFO", ".INSTALL", ".PKGINFO", "etc/sudoers"}
PRIVILEGED_CONTROL_RULES = (
    (
        "pacman-hook-exec",
        lambda path: path.startswith("usr/share/libalpm/hooks/"),
        re.compile(r"(?mi)^\s*Exec\s*="),
    ),
    (
        "systemd-preset-enable",
        lambda path: path.startswith("usr/lib/systemd/system-preset/"),
        re.compile(r"(?mi)^\s*enable\s+"),
    ),
    (
        "udev-run-directive",
        lambda path: path.startswith("usr/lib/udev/rules.d/"),
        re.compile(r"(?i)\bRUN\s*(?::)?="),
    ),
    (
        "sudoers-privilege-rule",
        lambda path: path == "etc/sudoers" or path.startswith("etc/sudoers.d/"),
        re.compile(r"(?mi)^\s*[^#\s].*(?:NOPASSWD|PASSWD|\bALL\s*=)"),
    ),
    (
        "tmpfiles-privileged-write",
        lambda path: path.startswith("usr/lib/tmpfiles.d/"),
        re.compile(r"(?m)^\s*[fFwWpPcCbB]\s+"),
    ),
)


class MakepkgGuardError(RuntimeError):
    pass


def _run_checked(command: list[str], *, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
            env=sanitized_child_environment(),
        )
    except (OSError, UnicodeError, subprocess.TimeoutExpired) as error:
        raise MakepkgGuardError(f"Could not inspect built package: {error}") from error


def _archive_entries(bsdtar: str, archive: Path) -> tuple[list[str], list[str]]:
    plain = _run_checked([bsdtar, "-tf", str(archive)])
    verbose = _run_checked([bsdtar, "-tvf", str(archive)])
    if plain.returncode != 0 or verbose.returncode != 0:
        detail = (plain.stderr or verbose.stderr).strip()[-800:]
        raise MakepkgGuardError(f"Package archive cannot be listed: {archive}: {detail}")
    if len(plain.stdout) > 16 * 1024 * 1024 or len(verbose.stdout) > 32 * 1024 * 1024:
        raise MakepkgGuardError(f"Package archive listing is unreasonably large: {archive}")
    return plain.stdout.splitlines(), verbose.stdout.splitlines()


def _validate_archive_paths(archive: Path, entries: list[str], verbose: list[str]) -> None:
    if not entries or len(entries) > 200_000:
        raise MakepkgGuardError(f"Package archive has an invalid entry count: {archive}")
    if len(verbose) != len(entries):
        raise MakepkgGuardError(f"Package archive listings disagree: {archive}")
    normalized_entries: set[str] = set()
    for name in entries:
        path = PurePosixPath(name)
        if not name or name.startswith("/") or ".." in path.parts or any(ord(c) < 32 for c in name):
            raise MakepkgGuardError(f"Unsafe path in package archive {archive}: {name!r}")
        normalized = _normalize_archive_path(name)
        if normalized in normalized_entries:
            raise MakepkgGuardError(f"Duplicate path in package archive {archive}: {name!r}")
        normalized_entries.add(normalized)
    for line in verbose:
        mode = line.split(maxsplit=1)[0] if line else ""
        if len(mode) < 10:
            raise MakepkgGuardError(f"Malformed verbose archive listing: {archive}")
        if mode[0] not in {"-", "d", "l"}:
            raise MakepkgGuardError(
                f"Special file or hardlink in package archive {archive}: {mode[0]}"
            )
        if mode[3] in "sS" or mode[6] in "sS":
            raise MakepkgGuardError(f"Setuid/setgid entry in package archive {archive}")
        if mode[8] == "w" and mode[9] not in "tT":
            raise MakepkgGuardError(f"World-writable entry in package archive {archive}")
        if " -> " in line:
            target = line.rsplit(" -> ", 1)[1]
            target_path = PurePosixPath(target)
            if target.startswith("/") or ".." in target_path.parts:
                raise MakepkgGuardError(
                    f"Unsafe symlink target in package archive {archive}: {target!r}"
                )
        if " link to " in line:
            raise MakepkgGuardError(f"Hardlink in package archive {archive}")


def _normalize_archive_path(name: str) -> str:
    return PurePosixPath(name).as_posix().rstrip("/")


def _is_control_path(name: str) -> bool:
    normalized = _normalize_archive_path(name)
    return normalized in CONTROL_PATHS or any(
        normalized.startswith(prefix) for prefix in CONTROL_PATH_PREFIXES
    )


def _inspect_metadata(bsdtar: str, archive: Path, entries: list[str]) -> None:
    inspected_bytes = 0
    for candidate in entries:
        if not _is_control_path(candidate):
            continue
        display_name = _normalize_archive_path(candidate)
        result = _run_checked([bsdtar, "-xOf", str(archive), candidate])
        size = len(result.stdout.encode("utf-8"))
        inspected_bytes += size
        if result.returncode != 0 or size > 1024 * 1024 or inspected_bytes > 4 * 1024 * 1024:
            raise MakepkgGuardError(f"Cannot safely inspect {display_name} in {archive}")
        if "\x00" in result.stdout:
            raise MakepkgGuardError(f"Binary package control file in {archive}: {display_name}")
        privileged_rules = [
            rule_id
            for rule_id, applies, pattern in PRIVILEGED_CONTROL_RULES
            if applies(display_name) and pattern.search(result.stdout)
        ]
        if privileged_rules:
            raise MakepkgGuardError(
                f"Privileged built-package control directive in {archive}: "
                f"{', '.join(privileged_rules)}"
            )
        findings = _scan_content(f"{archive.name}/{display_name}", result.stdout)
        dangerous = [item for item in findings if item.severity in {"medium", "high", "critical"}]
        if dangerous:
            rules = ", ".join(sorted({item.rule_id for item in dangerous}))
            raise MakepkgGuardError(
                f"Dangerous built-package control metadata in {archive}: {rules}"
            )


def inspect_package(archive: Path) -> None:
    try:
        metadata = archive.lstat()
    except OSError as error:
        raise MakepkgGuardError(f"Expected package archive is missing: {archive}") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise MakepkgGuardError(f"Package archive is not a regular file: {archive}")
    try:
        bsdtar = resolve_trusted_executable("bsdtar", "bsdtar")
    except ExecutableTrustError as error:
        raise MakepkgGuardError(str(error)) from error
    entries, verbose = _archive_entries(bsdtar, archive)
    _validate_archive_paths(archive, entries, verbose)
    _inspect_metadata(bsdtar, archive, entries)


def _package_list(real_makepkg: str, config: str) -> list[Path]:
    result = _run_checked([real_makepkg, "--config", config, "--packagelist", "--ignorearch"])
    if result.returncode != 0:
        raise MakepkgGuardError("makepkg --packagelist failed after the build")
    packages = [Path(line).expanduser() for line in result.stdout.splitlines() if line.strip()]
    if not packages or any(not PACKAGE_SUFFIX.search(path.name) for path in packages):
        raise MakepkgGuardError("makepkg returned an invalid or empty package list")
    return packages


def _expects_package(arguments: list[str]) -> bool:
    if any(argument in NO_PACKAGE_OPTIONS for argument in arguments):
        return False
    return "--nobuild" not in arguments or "--noextract" in arguments


def _validate_makepkg_arguments(arguments: list[str]) -> tuple[str, Path]:
    expected_config = os.environ.get(MAKEPKG_CONFIG_ENV, "")
    expected_pkgdest = os.environ.get(PKGDEST_ENV, "")
    if not expected_config or not Path(expected_config).is_absolute():
        raise MakepkgGuardError("Missing trusted makepkg configuration from guarded-yay session")
    if not expected_pkgdest or not Path(expected_pkgdest).is_absolute():
        raise MakepkgGuardError("Missing private package destination from guarded-yay session")
    config_values: list[str] = []
    flags: list[str] = []
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument == "--config":
            if index + 1 >= len(arguments):
                raise MakepkgGuardError("makepkg --config is missing its value")
            config_values.append(arguments[index + 1])
            index += 2
            continue
        if argument.startswith("--config="):
            config_values.append(argument.split("=", 1)[1])
            index += 1
            continue
        if argument not in ALLOWED_MAKEPKG_FLAGS:
            raise MakepkgGuardError(f"Unsupported makepkg argument from yay: {argument}")
        flags.append(argument)
        index += 1
    if config_values != [expected_config]:
        raise MakepkgGuardError("makepkg did not receive exactly the guarded configuration")
    allowed_invocations = {
        ("--nobuild", "-f", "-C"),
        ("--nobuild", "-f", "-C", "--ignorearch"),
        ("--packagelist", "--ignorearch"),
        ("--verifysource", "--skippgpcheck", "-f", "-Cc"),
        ("--verifysource", "--skippgpcheck", "-f", "-Cc", "--ignorearch"),
        ("--nobuild", "--noextract", "--ignorearch", "-c"),
        ("-f", "--noconfirm", "--noextract", "--noprepare", "--holdver", "-c"),
        (
            "-f",
            "--noconfirm",
            "--noextract",
            "--noprepare",
            "--holdver",
            "--ignorearch",
            "-c",
        ),
    }
    if tuple(flags) not in allowed_invocations:
        raise MakepkgGuardError(f"Unexpected makepkg invocation shape from yay: {' '.join(flags)}")
    return expected_config, Path(expected_pkgdest).resolve(strict=True)


def run_guarded_makepkg(arguments: list[str]) -> int:
    real_makepkg = os.environ.get(REAL_MAKEPKG_ENV, "")
    if not real_makepkg or not Path(real_makepkg).is_absolute():
        raise MakepkgGuardError("Missing trusted makepkg path from guarded-yay session")
    config, package_destination = _validate_makepkg_arguments(arguments)
    try:
        verify_receipt(Path.cwd())
    except ReceiptError as error:
        raise MakepkgGuardError(str(error)) from error
    try:
        result = subprocess.run(
            [real_makepkg, *arguments],
            check=False,
            env=sanitized_child_environment(),
        )
    except OSError as error:
        raise MakepkgGuardError(f"Could not run makepkg: {error}") from error
    if result.returncode != 0 or not _expects_package(arguments):
        return result.returncode
    try:
        verify_receipt(Path.cwd())
    except ReceiptError as error:
        raise MakepkgGuardError(str(error)) from error
    for package in _package_list(real_makepkg, config):
        try:
            parent = package.parent.resolve(strict=True)
        except OSError as error:
            raise MakepkgGuardError(f"Cannot resolve package destination: {error}") from error
        if parent != package_destination:
            raise MakepkgGuardError(
                f"Package escaped the private transaction destination: {package}"
            )
        inspect_package(package)
    return 0


def makepkg_main(argv: Sequence[str] | None = None) -> int:
    try:
        return run_guarded_makepkg(list(argv) if argv is not None else sys.argv[1:])
    except MakepkgGuardError as error:
        print(f"error: AUR Codex Guard blocked makepkg: {error}", file=sys.stderr)
        return 3
