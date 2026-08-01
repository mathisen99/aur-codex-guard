from __future__ import annotations

import hashlib
import os
import re
import stat
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from re import Pattern

from .models import DeterministicReport, Finding, ReviewedFile, Severity

MAX_FILE_BYTES = 512 * 1024
MAX_PACKAGE_BYTES = 2 * 1024 * 1024
MAX_DIFF_BYTES = 512 * 1024

IGNORED_DIRECTORIES = {".git", "pkg", "src", "__pycache__"}


@dataclass(frozen=True)
class Rule:
    rule_id: str
    severity: Severity
    pattern: Pattern[str]
    message: str
    recommendation: str
    applies: Callable[[str], bool] = lambda _path: True


def _is_install_script(path: str) -> bool:
    return path.lower().endswith(".install")


RULES = (
    Rule(
        "network-pipe-shell",
        "critical",
        re.compile(r"\b(?:curl|wget)\b[^\n|]{0,500}\|\s*(?:ba|da|z|k)?sh\b", re.IGNORECASE),
        "Network response is piped directly into a shell.",
        "Download a pinned artifact, verify its checksum, and inspect it before execution.",
    ),
    Rule(
        "encoded-shell-execution",
        "critical",
        re.compile(
            r"\b(?:base64\s+(?:-d|--decode)|xxd\s+-r)\b[^\n|]{0,500}\|\s*(?:eval|(?:ba|z|k)?sh)\b",
            re.IGNORECASE,
        ),
        "Decoded data is executed as shell code.",
        "Reject opaque code execution and require readable, reviewable commands.",
    ),
    Rule(
        "reverse-shell",
        "critical",
        re.compile(
            r"(?:/dev/(?:tcp|udp)/|\bnc\b[^\n]{0,200}\s-e\s|\bsocat\b[^\n]{0,200}\bexec:)",
            re.IGNORECASE,
        ),
        "Possible reverse-shell or raw network-shell behavior.",
        "Reject the package unless this behavior has a compelling, independently verified purpose.",
    ),
    Rule(
        "destructive-root-operation",
        "critical",
        re.compile(
            r"\brm\s+(?:-[A-Za-z]*r[A-Za-z]*f[A-Za-z]*|-[A-Za-z]*f[A-Za-z]*r[A-Za-z]*)\s+(?:--\s+)?/(?:\s|$|[;|&])"
        ),
        "Destructive recursive removal targets the filesystem root.",
        "Reject the package.",
    ),
    Rule(
        "network-in-install-script",
        "critical",
        re.compile(
            r"\b(?:curl|wget|aria2c|npm\s+(?:i|install)|bun\s+(?:add|install)|pipx?\s+install|gem\s+install)\b",
            re.IGNORECASE,
        ),
        "Install script performs a network fetch or installs a second package ecosystem dependency.",
        "All payloads should be pinned in source=() and verified before package installation.",
        _is_install_script,
    ),
    Rule(
        "privilege-escalation",
        "high",
        re.compile(r"(?:^|[;&|]\s*)\b(?:sudo|doas|pkexec|su)\b", re.IGNORECASE),
        "Build metadata invokes a privilege-escalation command.",
        "AUR builds must not request additional privileges from build or install scripts.",
    ),
    Rule(
        "dynamic-shell",
        "high",
        re.compile(r"\b(?:eval\s+|(?:ba|da|z|k)?sh\s+-c\s+)", re.IGNORECASE),
        "Code is dynamically evaluated by a shell.",
        "Replace dynamic evaluation with explicit commands that can be reviewed statically.",
    ),
    Rule(
        "credential-access",
        "high",
        re.compile(
            r"(?:\.ssh/|\.aws/|\.config/gcloud|Login Data|Cookies(?:-journal)?|keyrings?|credentials?|discord|slack)",
            re.IGNORECASE,
        ),
        "Script references credential, browser-session, or messaging-client data.",
        "Reject credential access unless it is unquestionably required and independently audited.",
    ),
    Rule(
        "persistence-change",
        "high",
        re.compile(
            r"(?:\bsystemctl\s+(?:enable|start)|\bcrontab\b|\.config/autostart|/etc/(?:cron|systemd))",
            re.IGNORECASE,
        ),
        "Script attempts to create persistence or activate a service directly.",
        "Package files may declare services, but activation should remain an explicit administrator action.",
    ),
    Rule(
        "runtime-package-install",
        "medium",
        re.compile(
            r"\b(?:npm\s+(?:i|install)|bun\s+(?:add|install)|pipx?\s+install|gem\s+install|cargo\s+install)\b",
            re.IGNORECASE,
        ),
        "Build instructions invoke another ecosystem's package installer.",
        "Verify that dependencies are pinned, checksummed, expected, and confined to the build directory.",
    ),
    Rule(
        "checksum-skip",
        "medium",
        re.compile(
            r"(?:sha(?:224|256|384|512)|b2|md5)sums\s*=\s*\([^)]*['\"]SKIP['\"]",
            re.IGNORECASE | re.DOTALL,
        ),
        "At least one source bypasses checksum verification.",
        "Use a cryptographic checksum where possible; carefully verify VCS source pinning otherwise.",
        lambda path: path.endswith("/PKGBUILD") or path == "PKGBUILD",
    ),
    Rule(
        "opaque-encoded-blob",
        "high",
        re.compile(r"[A-Za-z0-9+/]{400,}={0,2}"),
        "A long encoded-looking blob makes behavior difficult to review.",
        "Require the content to be decoded and reviewed before installation.",
    ),
)

BIDI_OR_INVISIBLE = re.compile("[\u200b\u200c\u200d\u202a-\u202e\u2066-\u2069\ufeff]")


def package_roots_from_inputs(inputs: list[str | os.PathLike[str]]) -> list[Path]:
    roots: list[Path] = []
    seen: set[Path] = set()
    for raw in inputs:
        path = Path(raw).expanduser()
        if path.name == "PKGBUILD" and path.is_file():
            root = path.parent
        elif path.is_dir() and (path / "PKGBUILD").is_file():
            root = path
        else:
            raise ValueError(f"Not an AUR build directory or PKGBUILD: {path}")
        resolved = root.resolve(strict=True)
        root_metadata = resolved.stat()
        if root_metadata.st_uid != os.getuid() or stat.S_IMODE(root_metadata.st_mode) & 0o022:
            raise ValueError(
                f"AUR build directory is not privately writable by this user: {resolved}"
            )
        if resolved not in seen:
            roots.append(resolved)
            seen.add(resolved)
    if not roots:
        raise ValueError("No PKGBUILD inputs were provided")
    names = [root.name for root in roots]
    if len(names) != len(set(names)):
        raise ValueError("Package directory names must be unique within one review")
    return roots


def _display_package(root: Path) -> str:
    return root.name or "aur-package"


def _git_diff(root: Path) -> str:
    env = os.environ.copy()
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_CONFIG_GLOBAL"] = os.devnull
    command = [
        "git",
        "-C",
        str(root),
        "--no-pager",
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--unified=40",
        "HEAD^",
        "HEAD",
        "--",
    ]
    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
            env=env,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    if result.returncode != 0:
        return ""
    encoded = result.stdout.encode("utf-8", errors="replace")
    if len(encoded) > MAX_DIFF_BYTES:
        return encoded[:MAX_DIFF_BYTES].decode("utf-8", errors="replace") + "\n[diff truncated]"
    return result.stdout


def _scan_content(display_path: str, content: str) -> list[Finding]:
    findings: list[Finding] = []
    for match in BIDI_OR_INVISIBLE.finditer(content):
        line = content.count("\n", 0, match.start()) + 1
        findings.append(
            Finding(
                "invisible-control-character",
                "critical",
                display_path,
                line,
                "Invisible or bidirectional Unicode control character detected.",
                repr(match.group(0)),
                "Remove the hidden character and review the surrounding text as potentially deceptive.",
            )
        )

    for rule in RULES:
        if not rule.applies(display_path):
            continue
        for match in rule.pattern.finditer(content):
            line = content.count("\n", 0, match.start()) + 1
            evidence = match.group(0).replace("\n", " ")[:240]
            findings.append(
                Finding(
                    rule.rule_id,
                    rule.severity,
                    display_path,
                    line,
                    rule.message,
                    evidence,
                    rule.recommendation,
                )
            )
    return findings


def deterministic_scan(inputs: list[str | os.PathLike[str]]) -> DeterministicReport:
    roots = package_roots_from_inputs(inputs)
    report = DeterministicReport(package_roots=[str(root) for root in roots])
    for root in roots:
        package_bytes = 0
        package = _display_package(root)
        report.diffs[package] = _git_diff(root)
        for path in sorted(root.rglob("*")):
            relative = path.relative_to(root)
            if any(part in IGNORED_DIRECTORIES for part in relative.parts[:-1]):
                continue
            display_path = f"{package}/{relative.as_posix()}"
            try:
                metadata = path.lstat()
            except OSError as error:
                report.findings.append(
                    Finding("unreadable-file", "high", display_path, None, str(error))
                )
                continue
            if stat.S_ISLNK(metadata.st_mode):
                report.findings.append(
                    Finding(
                        "symlink-in-build-metadata",
                        "high",
                        display_path,
                        None,
                        "Symlink in AUR build metadata is not followed.",
                        os.readlink(path),
                        "Replace the symlink with an ordinary reviewed file.",
                    )
                )
                continue
            if stat.S_ISDIR(metadata.st_mode):
                continue
            if not stat.S_ISREG(metadata.st_mode):
                report.findings.append(
                    Finding(
                        "special-build-metadata-file",
                        "high",
                        display_path,
                        None,
                        "A non-regular file exists in AUR build metadata.",
                        recommendation="Replace it with an ordinary reviewable file.",
                    )
                )
                continue
            if metadata.st_size > MAX_FILE_BYTES:
                report.skipped_files.append(display_path)
                report.findings.append(
                    Finding(
                        "file-scan-limit",
                        "high",
                        display_path,
                        None,
                        f"Reviewable file exceeds {MAX_FILE_BYTES} bytes.",
                        recommendation="Review the oversized file manually or raise the limit explicitly in a future policy.",
                    )
                )
                continue
            package_bytes += metadata.st_size
            if package_bytes > MAX_PACKAGE_BYTES:
                report.skipped_files.append(display_path)
                report.findings.append(
                    Finding(
                        "total-scan-limit",
                        "high",
                        display_path,
                        None,
                        f"Package review input exceeds {MAX_PACKAGE_BYTES} bytes.",
                        recommendation="Review the oversized package manually.",
                    )
                )
                continue
            try:
                descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
                try:
                    opened_metadata = os.fstat(descriptor)
                    raw = b""
                    while chunk := os.read(descriptor, 128 * 1024):
                        raw += chunk
                    finished_metadata = os.fstat(descriptor)
                finally:
                    os.close(descriptor)
            except OSError as error:
                report.findings.append(
                    Finding("unreadable-file", "high", display_path, None, str(error))
                )
                continue
            if (
                opened_metadata.st_dev != metadata.st_dev
                or opened_metadata.st_ino != metadata.st_ino
                or opened_metadata.st_size != metadata.st_size
                or opened_metadata.st_mtime_ns != metadata.st_mtime_ns
                or finished_metadata.st_size != opened_metadata.st_size
                or finished_metadata.st_mtime_ns != opened_metadata.st_mtime_ns
                or finished_metadata.st_ctime_ns != opened_metadata.st_ctime_ns
            ):
                report.findings.append(
                    Finding(
                        "metadata-changed-during-scan",
                        "critical",
                        display_path,
                        None,
                        "File identity or contents changed while it was being scanned.",
                        recommendation="Abort and retry from a trusted checkout.",
                    )
                )
                continue
            if b"\x00" in raw:
                report.skipped_files.append(display_path)
                report.findings.append(
                    Finding(
                        "binary-build-metadata",
                        "high",
                        display_path,
                        None,
                        "Binary content was found among AUR build metadata.",
                        recommendation="Inspect the binary independently before continuing.",
                    )
                )
                continue
            try:
                content = raw.decode("utf-8")
            except UnicodeDecodeError as error:
                report.skipped_files.append(display_path)
                report.findings.append(
                    Finding(
                        "invalid-utf8-build-metadata",
                        "high",
                        display_path,
                        None,
                        f"Build metadata is not valid UTF-8: {error}",
                        recommendation="Convert the file to reviewable UTF-8 text or inspect it manually.",
                    )
                )
                continue
            reviewed = ReviewedFile(
                package,
                str(root),
                relative.as_posix(),
                content,
                hashlib.sha256(raw).hexdigest(),
                stat.S_IMODE(opened_metadata.st_mode),
            )
            report.reviewed_files.append(reviewed)
            report.findings.extend(_scan_content(reviewed.display_path, content))

    if not any(item.relative_path == "PKGBUILD" for item in report.reviewed_files):
        report.findings.append(
            Finding(
                "pkgbuild-not-reviewed",
                "critical",
                "PKGBUILD",
                None,
                "No readable PKGBUILD reached the scanner.",
                recommendation="Abort the operation.",
            )
        )
    return report
