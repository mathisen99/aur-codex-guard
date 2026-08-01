from __future__ import annotations

import json
import os
import shutil
import sys
import textwrap
from collections.abc import Mapping
from pathlib import Path
from typing import TextIO

from .codex_review import REQUIRED_MODEL, REQUIRED_REASONING_EFFORT
from .models import GateReport

RESET = "\x1b[0m"
BOLD = "\x1b[1m"
DIM = "\x1b[2m"
RED = "\x1b[31m"
GREEN = "\x1b[32m"
YELLOW = "\x1b[33m"
CYAN = "\x1b[36m"

VERDICT_COLORS = {"allow": GREEN, "warn": YELLOW, "block": RED}
VERDICT_LABELS = {"allow": "PASS", "warn": "REVIEW", "block": "BLOCK"}
SEVERITY_COLORS: Mapping[str, str] = {
    "info": CYAN,
    "low": CYAN,
    "medium": YELLOW,
    "high": RED,
    "critical": RED,
}


def _color_enabled(stream: TextIO) -> bool:
    if "NO_COLOR" in os.environ or os.environ.get("TERM", "") == "dumb":
        return False
    return bool(getattr(stream, "isatty", lambda: False)())


def _styled(value: str, *styles: str, enabled: bool) -> str:
    if not enabled:
        return value
    return f"{''.join(styles)}{value}{RESET}"


def _output_width() -> int:
    return max(64, min(shutil.get_terminal_size(fallback=(88, 24)).columns, 120))


def _field(
    stream: TextIO,
    label: str,
    value: str,
    *,
    color: bool,
    value_style: tuple[str, ...] = (),
) -> None:
    prefix = f"    {label:<10}"
    available = max(20, _output_width() - len(prefix))
    lines = textwrap.wrap(
        value.strip(),
        width=available,
        break_long_words=False,
        break_on_hyphens=False,
    ) or [""]
    styled_label = _styled(label, BOLD, enabled=color)
    print(
        f"    {styled_label}{' ' * (10 - len(label))}{_styled(lines[0], *value_style, enabled=color)}",
        file=stream,
    )
    continuation = " " * len(prefix)
    for line in lines[1:]:
        print(f"{continuation}{_styled(line, *value_style, enabled=color)}", file=stream)


def _finding(
    stream: TextIO,
    *,
    severity: str,
    location: str,
    title: str,
    color: bool,
) -> None:
    badge = f"[{severity.upper()}]"
    badge_color = SEVERITY_COLORS.get(severity.lower(), YELLOW)
    prefix = f"      {_styled(badge, BOLD, badge_color, enabled=color)} "
    available = max(20, _output_width() - len(f"      {badge} "))
    lines = textwrap.wrap(
        f"{location}: {title}",
        width=available,
        break_long_words=False,
        break_on_hyphens=False,
    ) or [""]
    print(f"{prefix}{lines[0]}", file=stream)
    continuation = " " * len(f"      {badge} ")
    for line in lines[1:]:
        print(f"{continuation}{line}", file=stream)


def print_review_start(
    package_paths: list[str],
    *,
    stream: TextIO | None = None,
    color: bool | None = None,
) -> None:
    output = stream or sys.stderr
    use_color = _color_enabled(output) if color is None else color
    package_names: set[str] = set()
    for value in package_paths:
        path = Path(value)
        package_names.add(path.parent.name if path.name == "PKGBUILD" else path.name)
    packages = sorted(package_names)
    print(file=output)
    print(
        f"{_styled('==>', BOLD, CYAN, enabled=use_color)} "
        f"{_styled('Running AUR Codex Guard security review', BOLD, enabled=use_color)}",
        file=output,
    )
    _field(
        output,
        "Package" if len(packages) == 1 else "Packages",
        ", ".join(packages) or "unknown",
        color=use_color,
    )
    _field(
        output,
        "Reviewer",
        f"{REQUIRED_MODEL} · {REQUIRED_REASONING_EFFORT} reasoning",
        color=use_color,
    )
    _field(
        output,
        "Status",
        "Analyzing build metadata; this can take a few minutes.",
        color=use_color,
        value_style=(DIM,),
    )
    print(file=output, flush=True)


def print_canary_start(
    codex_version: str,
    *,
    stream: TextIO | None = None,
    color: bool | None = None,
) -> None:
    output = stream or sys.stderr
    use_color = _color_enabled(output) if color is None else color
    print(file=output)
    print(
        f"{_styled('==>', BOLD, CYAN, enabled=use_color)} "
        f"{_styled('Running one-time AUR Codex Guard compatibility check', BOLD, enabled=use_color)}",
        file=output,
    )
    _field(output, "Codex", codex_version, color=use_color)
    _field(
        output,
        "Status",
        "Validating the updated Codex CLI; this can take a few minutes.",
        color=use_color,
        value_style=(DIM,),
    )
    print(file=output, flush=True)


def prompt_warning_approval(
    *,
    input_stream: TextIO | None = None,
    output_stream: TextIO | None = None,
    color: bool | None = None,
) -> bool:
    source = input_stream or sys.stdin
    output = output_stream or sys.stderr
    use_color = _color_enabled(output) if color is None else color
    if not bool(getattr(source, "isatty", lambda: False)()):
        print(
            f"{_styled('==>', BOLD, YELLOW, enabled=use_color)} "
            "Interactive approval is unavailable; the package remains blocked.",
            file=output,
            flush=True,
        )
        return False
    print(
        f"{_styled('::', BOLD, CYAN, enabled=use_color)} "
        f"{_styled('Proceed after reviewing these concerns?', BOLD, enabled=use_color)} [y/N] ",
        file=output,
        end="",
        flush=True,
    )
    try:
        response = source.readline()
    except OSError:
        return False
    return response.strip().lower() in {"y", "yes"}


def print_warning_decision(
    accepted: bool,
    *,
    stream: TextIO | None = None,
    color: bool | None = None,
) -> None:
    output = stream or sys.stderr
    use_color = _color_enabled(output) if color is None else color
    if accepted:
        message = "Review explicitly accepted; continuing the guarded build."
        style = YELLOW
    else:
        message = "Review not accepted; installation remains blocked."
        style = RED
    print(
        f"{_styled('==>', BOLD, style, enabled=use_color)} "
        f"{_styled(message, BOLD, enabled=use_color)}",
        file=output,
        flush=True,
    )


def print_human(
    report: GateReport,
    *,
    stream: TextIO | None = None,
    color: bool | None = None,
) -> None:
    output = stream or sys.stderr
    use_color = _color_enabled(output) if color is None else color
    verdict = VERDICT_LABELS[report.verdict]
    print(file=output)
    print(
        f"{_styled('==>', BOLD, CYAN, enabled=use_color)} "
        f"{_styled('AUR Codex Guard', BOLD, enabled=use_color)}",
        file=output,
    )
    _field(
        output,
        "Result",
        verdict,
        color=use_color,
        value_style=(BOLD, VERDICT_COLORS[report.verdict]),
    )
    _field(output, "Gate", report.reason, color=use_color)

    findings = report.deterministic.findings
    if findings:
        print(f"\n    {_styled('Deterministic findings', BOLD, enabled=use_color)}", file=output)
        for finding in findings:
            location = finding.file
            if finding.line is not None:
                location += f":{finding.line}"
            _finding(
                output,
                severity=finding.severity,
                location=location,
                title=f"{finding.rule_id} — {finding.message}",
                color=use_color,
            )
            if finding.evidence:
                _field(output, "Evidence", finding.evidence, color=use_color)

    if report.codex:
        codex_verdict = VERDICT_LABELS[report.codex.verdict]
        reviewer = (
            f"{REQUIRED_MODEL} · {REQUIRED_REASONING_EFFORT} reasoning · "
            f"{codex_verdict} · {report.codex.confidence} confidence"
        )
        print(f"\n    {_styled('Codex review', BOLD, enabled=use_color)}", file=output)
        _field(output, "Reviewer", reviewer, color=use_color)
        _field(output, "Summary", report.codex.summary, color=use_color)
        for codex_finding in report.codex.findings:
            severity = str(codex_finding.get("severity", "unknown"))
            path = str(codex_finding.get("file", "unknown"))
            line = codex_finding.get("line")
            if line:
                path += f":{line}"
            title = str(codex_finding.get("title", "Finding"))
            _finding(
                output,
                severity=severity,
                location=path,
                title=title,
                color=use_color,
            )
        for limitation in report.codex.limitations:
            _field(
                output,
                "Limitation",
                limitation,
                color=use_color,
                value_style=(YELLOW,),
            )
    print(file=output)


def print_json(report: GateReport) -> None:
    print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
