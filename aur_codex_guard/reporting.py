from __future__ import annotations

import json
import sys

from .codex_review import REQUIRED_MODEL, REQUIRED_REASONING_EFFORT
from .models import GateReport


def print_human(report: GateReport) -> None:
    icon = {"allow": "ALLOW", "warn": "WARN", "block": "BLOCK"}[report.verdict]
    print(f"\nAUR Codex Guard: {icon}", file=sys.stderr)
    print(report.reason, file=sys.stderr)

    findings = report.deterministic.findings
    if findings:
        print("\nDeterministic findings:", file=sys.stderr)
        for finding in findings:
            location = finding.file
            if finding.line is not None:
                location += f":{finding.line}"
            print(
                f"  [{finding.severity.upper()}] {finding.rule_id} at {location}: {finding.message}",
                file=sys.stderr,
            )
            if finding.evidence:
                print(f"    Evidence: {finding.evidence}", file=sys.stderr)

    if report.codex:
        print(
            f"\nCodex {REQUIRED_MODEL} ({REQUIRED_REASONING_EFFORT} reasoning): "
            f"{report.codex.verdict.upper()} ({report.codex.confidence} confidence)",
            file=sys.stderr,
        )
        print(f"  {report.codex.summary}", file=sys.stderr)
        for codex_finding in report.codex.findings:
            severity = str(codex_finding.get("severity", "unknown")).upper()
            path = str(codex_finding.get("file", "unknown"))
            line = codex_finding.get("line")
            if line:
                path += f":{line}"
            title = codex_finding.get("title", "Finding")
            print(f"  [{severity}] {path}: {title}", file=sys.stderr)
        for limitation in report.codex.limitations:
            print(f"  Limitation: {limitation}", file=sys.stderr)
    print(file=sys.stderr)


def print_json(report: GateReport) -> None:
    print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
