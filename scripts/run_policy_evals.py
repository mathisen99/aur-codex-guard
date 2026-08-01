"""Run language-independent policy regression cases without building packages."""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from aur_codex_guard.gate import review_packages
from aur_codex_guard.scanner import deterministic_scan

FIXTURE_ROOT = PROJECT_ROOT / "tests" / "fixtures" / "policy"


@dataclass(frozen=True)
class PolicyCase:
    name: str
    path: Path
    expected: str


def policy_cases() -> list[PolicyCase]:
    cases = [
        PolicyCase(path.name, path, "allow")
        for path in sorted((FIXTURE_ROOT / "conventional").iterdir())
        if path.is_dir()
    ]
    cases.extend(
        PolicyCase(f"suspicious/{path.name}", path, "block")
        for path in sorted((FIXTURE_ROOT / "suspicious").iterdir())
        if path.is_dir()
    )
    return cases


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Evaluate representative build behavior against the semantic security policy. "
            "No fixture is built or installed."
        )
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="also ask Codex to review each selected conventional case",
    )
    parser.add_argument(
        "--case",
        action="append",
        default=[],
        metavar="NAME",
        help="run only this case (repeatable; use --list to see names)",
    )
    parser.add_argument("--list", action="store_true", help="list case names and exit")
    parser.add_argument("--timeout", type=int, default=240, help="live review timeout per case")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    cases = policy_cases()
    if args.list:
        for case in cases:
            print(case.name)
        return 0

    selected = [case for case in cases if not args.case or case.name in args.case]
    unknown = sorted(set(args.case) - {case.name for case in cases})
    if unknown:
        print(f"Unknown policy case(s): {', '.join(unknown)}", file=sys.stderr)
        return 2

    failures = 0
    for case in selected:
        deterministic = deterministic_scan([case.path])
        detail = ""
        if case.expected == "block":
            actual = deterministic.deterministic_verdict
        elif args.live:
            report = review_packages([case.path], timeout_seconds=args.timeout)
            actual = report.verdict
            if actual != case.expected:
                detail = report.reason
                if report.codex is not None:
                    detail = f"{detail} Codex summary: {report.codex.summary}"
        else:
            actual = deterministic.deterministic_verdict

        passed = actual == case.expected
        failures += not passed
        marker = "PASS" if passed else "FAIL"
        mode = "live" if args.live and case.expected == "allow" else "deterministic"
        print(f"{marker:4}  {case.name:28} expected={case.expected:5} actual={actual:5} {mode}")
        if detail:
            print(f"      {detail}")

    if not selected:
        print("No policy cases selected", file=sys.stderr)
        return 2
    print(f"\n{len(selected) - failures}/{len(selected)} policy cases passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
