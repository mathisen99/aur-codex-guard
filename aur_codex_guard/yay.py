from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path


class YayIntegrationError(RuntimeError):
    pass


def find_real_yay(explicit: str | None = None) -> str:
    candidate = explicit or os.environ.get("AUR_CODEX_GUARD_REAL_YAY") or "yay"
    resolved = shutil.which(candidate)
    if not resolved:
        raise YayIntegrationError(f"Could not find yay executable: {candidate}")
    return resolved


def hook_executable() -> str:
    override = os.environ.get("AUR_CODEX_GUARD_HOOK")
    if override:
        path = Path(override).expanduser().resolve()
    else:
        repo_hook = Path(__file__).resolve().parent.parent / "scripts" / "aur-codex-guard-hook"
        installed_hook = shutil.which("aur-codex-guard-hook")
        path = repo_hook if repo_hook.is_file() else Path(installed_hook or "")
    if not path.is_file() or not os.access(path, os.X_OK):
        raise YayIntegrationError(
            "Could not find an executable aur-codex-guard hook. Run from the project checkout or install it later."
        )
    return str(path)


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
    )
    missing = [option for option in required if option not in help_text]
    if result.returncode != 0 or missing:
        raise YayIntegrationError(
            "Installed yay does not provide the required pre-build editor interface"
        )


def build_yay_command(yay_binary: str, hook: str, arguments: list[str]) -> list[str]:
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
    ]


def run_guarded_yay(arguments: list[str], *, yay_binary: str | None = None) -> int:
    if os.environ.get("AUR_CODEX_GUARD_ACTIVE") == "1":
        raise YayIntegrationError("Refusing recursive guarded-yay invocation")
    if "--save" in arguments:
        raise YayIntegrationError(
            "Refusing --save because it would persist the guard's temporary yay editor settings"
        )
    real_yay = find_real_yay(yay_binary)
    validate_yay_support(real_yay)
    hook = hook_executable()
    environment = os.environ.copy()
    environment["AUR_CODEX_GUARD_ACTIVE"] = "1"
    try:
        return subprocess.run(
            build_yay_command(real_yay, hook, arguments),
            check=False,
            env=environment,
        ).returncode
    except OSError as error:
        raise YayIntegrationError(f"Could not run yay: {error}") from error
