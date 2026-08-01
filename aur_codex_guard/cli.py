from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence
from dataclasses import replace

from . import __version__
from .audit import AuditError, write_audit_event
from .doctor import print_doctor, run_doctor
from .gate import review_packages
from .receipts import ReceiptError, write_receipts
from .reporting import (
    print_human,
    print_json,
    print_review_start,
    print_warning_decision,
    prompt_warning_approval,
)
from .yay import YayIntegrationError, run_guarded_yay

EXIT_ALLOW = 0
EXIT_BLOCK = 2
EXIT_ERROR = 3


def _scan_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = subparsers.add_parser(
        "scan", help="Review one or more downloaded AUR build directories"
    )
    parser.add_argument("paths", nargs="+", help="PKGBUILD files or their directories")
    parser.add_argument(
        "--deterministic-only",
        action="store_true",
        help="Skip Codex (diagnostic use only; guarded yay never enables this)",
    )
    parser.add_argument("--json", action="store_true", help="Print a JSON report")
    parser.add_argument("--timeout", type=int, default=240, help="Codex timeout in seconds")
    parser.add_argument("--codex", default="codex", help="Codex CLI executable")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aur-codex-guard",
        description="Fail-closed pre-build review gate for AUR packages",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)
    _scan_parser(subparsers)
    doctor_parser = subparsers.add_parser(
        "doctor", help="Check local yay, Arch tooling, and Codex compatibility"
    )
    doctor_parser.add_argument(
        "--live",
        action="store_true",
        help="Run the harmless structured-output Codex canary if it is not cached",
    )
    doctor_parser.add_argument(
        "--refresh",
        action="store_true",
        help="Force a fresh live Codex canary (requires --live)",
    )
    doctor_parser.add_argument("--timeout", type=int, default=240, help="Canary timeout in seconds")
    doctor_parser.add_argument("--json", action="store_true", help="Print machine-readable output")
    yay_parser = subparsers.add_parser(
        "yay", help="Run yay with the AUR pre-build review gate enforced"
    )
    yay_parser.add_argument("yay_args", nargs=argparse.REMAINDER)
    return parser


def _run_scan(args: argparse.Namespace) -> int:
    if args.timeout <= 0:
        print("error: --timeout must be positive", file=sys.stderr)
        return EXIT_ERROR
    try:
        report = review_packages(
            args.paths,
            deterministic_only=args.deterministic_only,
            timeout_seconds=args.timeout,
            codex_binary=args.codex,
        )
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_ERROR
    if args.json:
        print_json(report)
    else:
        print_human(report)
    return EXIT_ALLOW if report.allowed else EXIT_BLOCK


def _run_doctor(args: argparse.Namespace) -> int:
    if args.timeout <= 0:
        print("error: --timeout must be positive", file=sys.stderr)
        return EXIT_ERROR
    if args.refresh and not args.live:
        print("error: --refresh requires --live", file=sys.stderr)
        return EXIT_ERROR
    checks = run_doctor(live=args.live, refresh=args.refresh, timeout_seconds=args.timeout)
    print_doctor(checks, json_output=args.json)
    return EXIT_ERROR if any(check.status == "blocked" for check in checks) else EXIT_ALLOW


def main(argv: Sequence[str] | None = None) -> int:
    raw_arguments = list(argv) if argv is not None else sys.argv[1:]
    # yay accepts a large, evolving option surface. Dispatch it before argparse
    # so flags such as -S and --noconfirm are forwarded byte-for-byte.
    if raw_arguments[:1] == ["yay"]:
        arguments = raw_arguments[1:]
        if arguments[:1] == ["--"]:
            arguments = arguments[1:]
        try:
            return run_guarded_yay(arguments)
        except YayIntegrationError as error:
            print(f"error: {error}", file=sys.stderr)
            return EXIT_ERROR

    args = build_parser().parse_args(raw_arguments)
    if args.command == "scan":
        return _run_scan(args)
    if args.command == "doctor":
        return _run_doctor(args)
    return EXIT_ERROR


def hook_main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="aur-codex-guard-hook",
        description="Internal yay editor hook",
    )
    parser.add_argument("pkgbuilds", nargs="+")
    parser.add_argument("--timeout", type=int, default=240)
    args = parser.parse_args(argv)
    if os.environ.get("AUR_CODEX_GUARD_ACTIVE") != "1":
        print(
            "error: hook must be invoked by the guarded yay wrapper",
            file=sys.stderr,
        )
        return EXIT_ERROR
    print_review_start(args.pkgbuilds)
    try:
        report = review_packages(args.pkgbuilds, timeout_seconds=args.timeout)
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_ERROR
    if report.verdict == "warn":
        print_human(report)
        if not prompt_warning_approval():
            try:
                write_audit_event(report)
            except AuditError as error:
                print(f"warning: could not record warned review: {error}", file=sys.stderr)
            print_warning_decision(False)
            return EXIT_BLOCK
        report = replace(
            report,
            verdict="allow",
            reason="A human explicitly accepted the complete Codex review concerns.",
            human_override=True,
        )
        try:
            write_receipts(report.deterministic)
            write_audit_event(report)
        except (OSError, AuditError, ReceiptError) as error:
            print(f"error: fail-closed finalization error: {error}", file=sys.stderr)
            return EXIT_ERROR
        print_warning_decision(True)
        return EXIT_ALLOW
    if report.allowed:
        try:
            write_receipts(report.deterministic)
            write_audit_event(report)
        except (OSError, AuditError, ReceiptError) as error:
            print(f"error: fail-closed finalization error: {error}", file=sys.stderr)
            return EXIT_ERROR
    else:
        try:
            write_audit_event(report)
        except AuditError as error:
            print(f"warning: could not record blocked review: {error}", file=sys.stderr)
    print_human(report)
    return EXIT_ALLOW if report.allowed else EXIT_BLOCK


if __name__ == "__main__":
    raise SystemExit(main())
