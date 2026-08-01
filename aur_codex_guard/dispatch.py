from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Literal

from .yay import YayIntegrationError, find_real_yay, run_guarded_yay

SYSTEM_YAY = "/usr/bin/yay"
PASSTHROUGH_SYNC_LONG_OPTIONS = {
    "--clean",
    "--groups",
    "--info",
    "--list",
    "--print",
    "--search",
}
PASSTHROUGH_SYNC_SHORT_OPTIONS = frozenset("cgilps")
LONG_OPERATIONS = {
    "--build": "B",
    "--database": "D",
    "--files": "F",
    "--getpkgbuild": "G",
    "--query": "Q",
    "--remove": "R",
    "--show": "P",
    "--sync": "S",
    "--deptest": "T",
    "--upgrade": "U",
    "--web": "W",
    "--yay": "Y",
    "--help": "h",
    "--version": "V",
}
OPTIONS_WITH_SEPARATE_VALUES = {
    "--arch",
    "--aururl",
    "--aurrpcurl",
    "--builddir",
    "--cachedir",
    "--color",
    "--completioninterval",
    "--config",
    "--dbpath",
    "--editor",
    "--editorflags",
    "--gpg",
    "--gpgdir",
    "--gpgflags",
    "--hookdir",
    "--ignore",
    "--ignoregroup",
    "--logfile",
    "--makepkg",
    "--makepkgconf",
    "--mflags",
    "--overwrite",
    "--pacman",
    "--print-format",
    "--requestsplitn",
    "--searchby",
    "--sortby",
    "--sudo",
    "--sudoflags",
}


@dataclass(frozen=True)
class DispatchDecision:
    mode: Literal["guard", "passthrough", "block"]
    arguments: list[str]
    reason: str = ""


def _explicit_operation(arguments: list[str]) -> str | None:
    positional_only = False
    for argument in arguments:
        if argument == "--":
            positional_only = True
            continue
        if positional_only:
            continue
        option = argument.split("=", 1)[0]
        if option in LONG_OPERATIONS:
            return LONG_OPERATIONS[option]
        if option.startswith("--") or not option.startswith("-"):
            continue
        for letter in option[1:]:
            if letter in "BDFGQRSTUWYVhS":
                return letter
    return None


def _sync_is_non_installing(arguments: list[str]) -> bool:
    for argument in arguments:
        option = argument.split("=", 1)[0]
        if option in PASSTHROUGH_SYNC_LONG_OPTIONS:
            return True
        if (
            option.startswith("-")
            and not option.startswith("--")
            and any(letter in PASSTHROUGH_SYNC_SHORT_OPTIONS for letter in option[1:])
        ):
            return True
    return False


def _has_positional_target(arguments: list[str]) -> bool:
    consume_value = False
    positional_only = False
    for argument in arguments:
        if consume_value:
            consume_value = False
            continue
        if argument == "--":
            positional_only = True
            continue
        if positional_only:
            return True
        if argument.startswith("--"):
            option, separator, _value = argument.partition("=")
            if not separator and option in OPTIONS_WITH_SEPARATE_VALUES:
                consume_value = True
            continue
        if argument.startswith("-"):
            continue
        return True
    return False


def decide_yay_dispatch(arguments: list[str]) -> DispatchDecision:
    operation = _explicit_operation(arguments)
    if operation == "S":
        if _sync_is_non_installing(arguments):
            return DispatchDecision("passthrough", arguments)
        return DispatchDecision("guard", arguments)
    if operation in {"B", "U"}:
        return DispatchDecision(
            "block",
            arguments,
            "This operation can execute local build metadata or install a local archive "
            "without the guarded AUR sync path, so the system shim refuses it.",
        )
    if operation == "Y" and _has_positional_target(arguments):
        return DispatchDecision(
            "block",
            arguments,
            "Interactive yay target selection can transition into an unguarded installation. "
            "Use `yay -S package-name` for installs.",
        )
    if operation is not None:
        return DispatchDecision("passthrough", arguments)
    if _has_positional_target(arguments):
        return DispatchDecision(
            "block",
            arguments,
            "The target-only interactive search form can install a selection without an "
            "explicit sync transaction. Use `yay -S package-name` so AUR packages are guarded.",
        )
    return DispatchDecision("guard", ["-Syu", *arguments])


def dispatch_yay(arguments: list[str], *, yay_binary: str = SYSTEM_YAY) -> int:
    decision = decide_yay_dispatch(arguments)
    if decision.mode == "block":
        raise YayIntegrationError(decision.reason)
    if decision.mode == "guard":
        return run_guarded_yay(decision.arguments, yay_binary=yay_binary)

    real_yay = find_real_yay(yay_binary)
    try:
        os.execv(real_yay, [real_yay, *decision.arguments])
    except OSError as error:
        raise YayIntegrationError(f"Could not run the real yay: {error}") from error
    raise YayIntegrationError("The real yay unexpectedly returned without executing")
