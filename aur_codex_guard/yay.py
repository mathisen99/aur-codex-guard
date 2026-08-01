from __future__ import annotations

import fcntl
import os
import secrets
import shlex
import stat
import subprocess
import tempfile
from pathlib import Path

from .audit import AuditError, write_transaction_event
from .executables import ExecutableTrustError, resolve_trusted_executable
from .receipts import (
    ACTIVE_ENV,
    MAKEPKG_CONFIG_ENV,
    PKGDEST_ENV,
    REAL_MAKEPKG_ENV,
    RECEIPT_DIR_ENV,
    SESSION_KEY_ENV,
)

TESTED_YAY_VERSION = "13.0.1"

PROTECTED_YAY_OPTIONS = {
    "--answerclean",
    "--answeredit",
    "--cleanmenu",
    "--combinedupgrade",
    "--editor",
    "--editorflags",
    "--editmenu",
    "--git",
    "--gitflags",
    "--makepkg",
    "--makepkgconf",
    "--mflags",
    "--noanswerclean",
    "--noansweredit",
    "--nocleanmenu",
    "--nocombinedupgrade",
    "--noeditmenu",
    "--nomakepkgconf",
    "--noredownload",
    "--norebuild",
    "--pacman",
    "--redownload",
    "--redownloadall",
    "--rebuild",
    "--rebuildall",
    "--rebuildtree",
    "--keepsrc",
    "--save",
    "--sudo",
    "--sudoflags",
}
UNSUPPORTED_SYNC_OPTIONS = {
    "--clean",
    "--config",
    "--dbpath",
    "--downloadonly",
    "--gpgdir",
    "--groups",
    "--hookdir",
    "--info",
    "--list",
    "--print",
    "--root",
    "--search",
    "--sysroot",
}
OTHER_OPERATIONS = {"B", "D", "F", "G", "P", "Q", "R", "T", "U", "W", "Y"}


class YayIntegrationError(RuntimeError):
    pass


def find_real_yay(explicit: str | None = None) -> str:
    candidate = explicit or "yay"
    try:
        return resolve_trusted_executable(candidate, "yay")
    except ExecutableTrustError as error:
        raise YayIntegrationError(str(error)) from error


def hook_executable() -> str:
    repo_hook = Path(__file__).resolve().parent.parent / "scripts" / "aur-codex-guard-hook"
    candidate = str(repo_hook) if repo_hook.is_file() else "aur-codex-guard-hook"
    try:
        return resolve_trusted_executable(candidate, "guard hook")
    except ExecutableTrustError as error:
        raise YayIntegrationError(
            "Could not find an executable aur-codex-guard hook. Run from the project checkout or install it later."
        ) from error


def makepkg_executable() -> str:
    repo_wrapper = Path(__file__).resolve().parent.parent / "scripts" / "aur-codex-guard-makepkg"
    candidate = str(repo_wrapper) if repo_wrapper.is_file() else "aur-codex-guard-makepkg"
    try:
        return resolve_trusted_executable(candidate, "guarded makepkg wrapper")
    except ExecutableTrustError as error:
        raise YayIntegrationError(
            "Could not find the executable guarded makepkg wrapper"
        ) from error


def find_real_makepkg() -> str:
    try:
        return resolve_trusted_executable("makepkg", "makepkg")
    except ExecutableTrustError as error:
        raise YayIntegrationError(str(error)) from error


def validate_yay_support(yay_binary: str) -> None:
    try:
        version = subprocess.run(
            [yay_binary, "--version"],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise YayIntegrationError(f"Could not inspect yay version: {error}") from error
    first_line = version.stdout.splitlines()[:1]
    if (
        version.returncode != 0
        or not first_line
        or not first_line[0].startswith(f"yay v{TESTED_YAY_VERSION} ")
    ):
        raise YayIntegrationError(
            f"Unsupported yay version; this release is pinned to yay {TESTED_YAY_VERSION}"
        )
    try:
        result = subprocess.run(
            [yay_binary, "--help"],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise YayIntegrationError(f"Could not inspect yay: {error}") from error
    help_text = result.stdout + result.stderr
    required = (
        "--editmenu",
        "--answeredit",
        "--editor",
        "--redownloadall",
        "--rebuildall",
        "--makepkg",
    )
    missing = [option for option in required if option not in help_text]
    if result.returncode != 0 or missing:
        raise YayIntegrationError(
            "Installed yay does not provide the required pre-build editor interface"
        )
    try:
        combined = subprocess.run(
            [yay_binary, "--combinedupgrade", "--help"],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise YayIntegrationError(f"Could not verify combined-upgrade support: {error}") from error
    if combined.returncode != 0:
        raise YayIntegrationError("Installed yay does not support --combinedupgrade")


def build_yay_command(
    yay_binary: str,
    hook: str,
    makepkg_wrapper: str,
    makepkg_config: str,
    arguments: list[str],
) -> list[str]:
    # yay uses the first occurrence of repeated settings. Put guard-owned values
    # first and reject conflicts before command construction.
    return [
        yay_binary,
        "--cleanmenu",
        "--answerclean",
        "All",
        "--editmenu",
        "--answeredit",
        "All",
        "--editor",
        hook,
        "--editorflags",
        "",
        "--redownloadall",
        "--rebuildall",
        "--combinedupgrade",
        "--makepkg",
        makepkg_wrapper,
        "--mflags",
        "",
        "--makepkgconf",
        makepkg_config,
        *arguments,
    ]


def validate_yay_arguments(arguments: list[str]) -> None:
    if not arguments:
        raise YayIntegrationError("An explicit yay sync operation is required")
    sync_operation = False
    positional_only = False
    for argument in arguments:
        if argument == "--":
            positional_only = True
            continue
        if positional_only:
            continue
        option = argument.split("=", 1)[0]
        if option in PROTECTED_YAY_OPTIONS:
            raise YayIntegrationError(f"Refusing guard-controlled yay option: {option}")
        if option in UNSUPPORTED_SYNC_OPTIONS or option.startswith("--disable-sandbox"):
            raise YayIntegrationError(f"Unsupported non-installing or unsafe yay option: {option}")
        if option == "--sync":
            sync_operation = True
            continue
        if option.startswith("--"):
            continue
        if option.startswith("-") and option != "-":
            letters = option[1:]
            if any(letter in OTHER_OPERATIONS for letter in letters):
                raise YayIntegrationError("Only yay's sync/install operation is supported")
            if "S" in letters:
                sync_operation = True
            if any(letter in "bcgilprsw" for letter in letters):
                raise YayIntegrationError(
                    "Search, query, clean, print, and download-only sync modes are unsupported"
                )
    if not sync_operation:
        raise YayIntegrationError("Only an explicit yay -S/--sync transaction is supported")


def _write_makepkg_config(session_path: Path) -> tuple[Path, Path]:
    system_config = Path("/etc/makepkg.conf")
    try:
        metadata = system_config.stat()
    except OSError as error:
        raise YayIntegrationError(f"Cannot inspect /etc/makepkg.conf: {error}") from error
    if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) & 0o022:
        raise YayIntegrationError("Unsafe /etc/makepkg.conf")
    destinations = {
        "PKGDEST": session_path / "packages",
        "SRCDEST": session_path / "sources",
        "SRCPKGDEST": session_path / "source-packages",
        "BUILDDIR": session_path / "build",
        "LOGDEST": session_path / "logs",
    }
    for path in destinations.values():
        path.mkdir(mode=0o700)
    config = session_path / "makepkg.conf"
    lines = [f"source {shlex.quote(str(system_config))}"]
    lines.extend(f"{key}={shlex.quote(str(path))}" for key, path in destinations.items())
    descriptor = os.open(config, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    try:
        os.write(descriptor, ("\n".join(lines) + "\n").encode("utf-8"))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return config, destinations["PKGDEST"]


def _lock_file() -> int:
    runtime = os.environ.get("XDG_RUNTIME_DIR")
    directory = Path(runtime) if runtime else Path("/tmp")
    try:
        metadata = directory.stat()
    except OSError as error:
        raise YayIntegrationError(f"Cannot access lock directory: {error}") from error
    if not stat.S_ISDIR(metadata.st_mode):
        raise YayIntegrationError("Unsafe lock directory")
    if runtime:
        if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
            raise YayIntegrationError("Unsafe XDG runtime directory")
    elif metadata.st_uid != 0 or not metadata.st_mode & stat.S_ISVTX:
        raise YayIntegrationError("System temporary directory is not root-owned and sticky")
    path = directory / f"aur-codex-guard-{os.getuid()}.lock"
    descriptor: int | None = None
    try:
        descriptor = os.open(
            path,
            os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
        )
        if os.fstat(descriptor).st_uid != os.getuid():
            raise YayIntegrationError("Transaction lock is not owned by the current user")
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as error:
        if descriptor is not None:
            os.close(descriptor)
        raise YayIntegrationError("Another guarded yay transaction is already running") from error
    except YayIntegrationError:
        if descriptor is not None:
            os.close(descriptor)
        raise
    except OSError as error:
        if descriptor is not None:
            os.close(descriptor)
        raise YayIntegrationError(f"Could not acquire transaction lock: {error}") from error
    if descriptor is None:
        raise YayIntegrationError("Could not acquire transaction lock")
    return descriptor


def run_guarded_yay(arguments: list[str], *, yay_binary: str | None = None) -> int:
    if os.environ.get(ACTIVE_ENV) == "1":
        raise YayIntegrationError("Refusing recursive guarded-yay invocation")
    validate_yay_arguments(arguments)
    real_yay = find_real_yay(yay_binary)
    validate_yay_support(real_yay)
    hook = hook_executable()
    makepkg_wrapper = makepkg_executable()
    real_makepkg = find_real_makepkg()
    lock_descriptor = _lock_file()
    try:
        with tempfile.TemporaryDirectory(prefix="aur-codex-guard-session-") as session:
            session_path = Path(session)
            os.chmod(session_path, 0o700)
            receipt_dir = session_path / "receipts"
            receipt_dir.mkdir(mode=0o700)
            makepkg_config, package_destination = _write_makepkg_config(session_path)
            xdg_config = session_path / "xdg-config"
            xdg_cache = session_path / "xdg-cache"
            xdg_config.mkdir(mode=0o700)
            xdg_cache.mkdir(mode=0o700)
            environment = {
                key: value
                for key, value in os.environ.items()
                if not key.startswith("AUR_CODEX_GUARD_")
            }
            environment[ACTIVE_ENV] = "1"
            environment[SESSION_KEY_ENV] = secrets.token_hex(32)
            environment[RECEIPT_DIR_ENV] = str(receipt_dir)
            environment[REAL_MAKEPKG_ENV] = real_makepkg
            environment[MAKEPKG_CONFIG_ENV] = str(makepkg_config)
            environment[PKGDEST_ENV] = str(package_destination)
            environment["XDG_CONFIG_HOME"] = str(xdg_config)
            environment["XDG_CACHE_HOME"] = str(xdg_cache)
            try:
                result = subprocess.run(
                    build_yay_command(
                        real_yay,
                        hook,
                        makepkg_wrapper,
                        str(makepkg_config),
                        arguments,
                    ),
                    check=False,
                    env=environment,
                )
            except OSError as error:
                raise YayIntegrationError(f"Could not run yay: {error}") from error
            try:
                write_transaction_event(arguments, result.returncode)
            except AuditError as error:
                raise YayIntegrationError(
                    f"yay exited {result.returncode}, but the terminal audit event failed: {error}"
                ) from error
            return result.returncode
    finally:
        os.close(lock_descriptor)
