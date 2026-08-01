from __future__ import annotations

import fcntl
import os
import secrets
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path

from .receipts import ACTIVE_ENV, REAL_MAKEPKG_ENV, RECEIPT_DIR_ENV, SESSION_KEY_ENV


class YayIntegrationError(RuntimeError):
    pass


def find_real_yay(explicit: str | None = None) -> str:
    candidate = explicit or "yay"
    resolved = shutil.which(candidate)
    if not resolved:
        raise YayIntegrationError(f"Could not find yay executable: {candidate}")
    return resolved


def hook_executable() -> str:
    repo_hook = Path(__file__).resolve().parent.parent / "scripts" / "aur-codex-guard-hook"
    installed_hook = shutil.which("aur-codex-guard-hook")
    path = repo_hook if repo_hook.is_file() else Path(installed_hook or "")
    if not path.is_file() or not os.access(path, os.X_OK):
        raise YayIntegrationError(
            "Could not find an executable aur-codex-guard hook. Run from the project checkout or install it later."
        )
    return str(path)


def makepkg_executable() -> str:
    repo_wrapper = Path(__file__).resolve().parent.parent / "scripts" / "aur-codex-guard-makepkg"
    installed_wrapper = shutil.which("aur-codex-guard-makepkg")
    path = repo_wrapper if repo_wrapper.is_file() else Path(installed_wrapper or "")
    if not path.is_file() or not os.access(path, os.X_OK):
        raise YayIntegrationError("Could not find the executable guarded makepkg wrapper")
    return str(path)


def find_real_makepkg() -> str:
    resolved = shutil.which("makepkg")
    if not resolved:
        raise YayIntegrationError("Could not find makepkg")
    return str(Path(resolved).resolve())


def validate_yay_support(yay_binary: str) -> None:
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
    arguments: list[str],
) -> list[str]:
    # Guard flags are appended so a user-supplied --noeditmenu or alternate editor
    # cannot silently bypass the gate.
    return [
        yay_binary,
        *arguments,
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
    ]


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
    if "--save" in arguments:
        raise YayIntegrationError(
            "Refusing --save because it would persist the guard's temporary yay editor settings"
        )
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
            environment = {
                key: value
                for key, value in os.environ.items()
                if not key.startswith("AUR_CODEX_GUARD_")
            }
            environment[ACTIVE_ENV] = "1"
            environment[SESSION_KEY_ENV] = secrets.token_hex(32)
            environment[RECEIPT_DIR_ENV] = str(receipt_dir)
            environment[REAL_MAKEPKG_ENV] = real_makepkg
            try:
                return subprocess.run(
                    build_yay_command(real_yay, hook, makepkg_wrapper, arguments),
                    check=False,
                    env=environment,
                ).returncode
            except OSError as error:
                raise YayIntegrationError(f"Could not run yay: {error}") from error
    finally:
        os.close(lock_descriptor)
