from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path, PurePosixPath

from .receipts import REAL_MAKEPKG_ENV, ReceiptError, sanitized_child_environment, verify_receipt
from .scanner import _scan_content

PACKAGE_SUFFIX = re.compile(r"\.pkg\.tar\.(?:zst|xz|gz|bz2|lz4|lrz|lzo|Z)$")
NO_PACKAGE_OPTIONS = {
    "--allsource",
    "--clean",
    "--geninteg",
    "--nobuild",
    "--packagelist",
    "--printsrcinfo",
    "--source",
    "--verifysource",
}


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
    for name in entries:
        path = PurePosixPath(name)
        if not name or name.startswith("/") or ".." in path.parts or any(ord(c) < 32 for c in name):
            raise MakepkgGuardError(f"Unsafe path in package archive {archive}: {name!r}")
    for line in verbose:
        mode = line.split(maxsplit=1)[0] if line else ""
        if len(mode) >= 10:
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
            target = line.rsplit(" link to ", 1)[1]
            target_path = PurePosixPath(target)
            if target.startswith("/") or ".." in target_path.parts:
                raise MakepkgGuardError(
                    f"Unsafe hardlink target in package archive {archive}: {target!r}"
                )


def _inspect_metadata(bsdtar: str, archive: Path, entries: list[str]) -> None:
    for metadata_name in (".INSTALL", ".PKGINFO"):
        candidates = [name for name in entries if name.lstrip("./") == metadata_name]
        for candidate in candidates:
            result = _run_checked([bsdtar, "-xOf", str(archive), candidate])
            if result.returncode != 0 or len(result.stdout.encode("utf-8")) > 1024 * 1024:
                raise MakepkgGuardError(f"Cannot safely inspect {metadata_name} in {archive}")
            findings = _scan_content(f"{archive.name}/{metadata_name}", result.stdout)
            dangerous = [item for item in findings if item.severity in {"high", "critical"}]
            if dangerous:
                rules = ", ".join(sorted({item.rule_id for item in dangerous}))
                raise MakepkgGuardError(f"Dangerous built-package metadata in {archive}: {rules}")


def inspect_package(archive: Path) -> None:
    try:
        metadata = archive.lstat()
    except OSError as error:
        raise MakepkgGuardError(f"Expected package archive is missing: {archive}") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise MakepkgGuardError(f"Package archive is not a regular file: {archive}")
    bsdtar = shutil.which("bsdtar")
    if not bsdtar:
        raise MakepkgGuardError("bsdtar is required for built-package inspection")
    entries, verbose = _archive_entries(bsdtar, archive)
    _validate_archive_paths(archive, entries, verbose)
    _inspect_metadata(bsdtar, archive, entries)


def _package_list(real_makepkg: str, arguments: list[str]) -> list[Path]:
    config_arguments: list[str] = []
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument in {"--config", "--builddir"} and index + 1 < len(arguments):
            config_arguments.extend((argument, arguments[index + 1]))
            index += 2
            continue
        if argument.startswith(("--config=", "--builddir=")):
            config_arguments.append(argument)
        index += 1
    result = _run_checked([real_makepkg, *config_arguments, "--packagelist"])
    if result.returncode != 0:
        raise MakepkgGuardError("makepkg --packagelist failed after the build")
    packages = [Path(line).expanduser() for line in result.stdout.splitlines() if line.strip()]
    if not packages or any(not PACKAGE_SUFFIX.search(path.name) for path in packages):
        raise MakepkgGuardError("makepkg returned an invalid or empty package list")
    return packages


def _expects_package(arguments: list[str]) -> bool:
    return not any(argument in NO_PACKAGE_OPTIONS for argument in arguments)


def run_guarded_makepkg(arguments: list[str]) -> int:
    real_makepkg = os.environ.get(REAL_MAKEPKG_ENV, "")
    if not real_makepkg or not Path(real_makepkg).is_absolute():
        raise MakepkgGuardError("Missing trusted makepkg path from guarded-yay session")
    if "--install" in arguments or "-i" in arguments:
        raise MakepkgGuardError(
            "Refusing makepkg --install; yay must perform installation after inspection"
        )
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
    for package in _package_list(real_makepkg, arguments):
        inspect_package(package)
    return 0


def makepkg_main(argv: Sequence[str] | None = None) -> int:
    try:
        return run_guarded_makepkg(list(argv) if argv is not None else sys.argv[1:])
    except MakepkgGuardError as error:
        print(f"error: AUR Codex Guard blocked makepkg: {error}", file=sys.stderr)
        return 3
