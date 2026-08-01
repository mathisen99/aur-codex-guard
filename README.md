# AUR Codex Guard

AUR Codex Guard is a fail-closed security gate for [`yay`](https://github.com/Jguer/yay). It intercepts AUR packages after `yay` downloads their build metadata and before `makepkg` executes anything, then combines deterministic checks with a non-interactive Codex review.

This repository is currently a development checkout. **Nothing here installs itself, changes `yay` configuration, creates aliases, or modifies system files.**

## Why this boundary

Pacman hooks are too late for this job: an AUR package has already run its build functions before Pacman sees the resulting package. `yay` 13 exposes an edit stage after AUR metadata is downloaded and before the build. The guarded wrapper forces that stage to invoke AUR Codex Guard for every selected AUR package.

Official repository packages do not have PKGBUILDs in this stage, so they do not trigger the review. Mixed repository/AUR transactions review only the AUR portion.

```text
yay resolves transaction
        |
        v
downloads AUR git metadata
        |
        v
forced editor hook ──> deterministic scan ──> Codex read-only review
        |                        |                      |
        |                        +-- high/critical -----+-- warn/error/timeout
        |                                                   |
        +---------------- ALLOW only <-----------------------+
        |
        v
yay may proceed to makepkg and installation
```

## Current behavior

- Scans the entire AUR metadata directory, not only the `PKGBUILD` path passed by `yay`.
- Forces AUR metadata re-download and rebuild so a cached package cannot bypass review.
- Includes `.install`, shell, patch, systemd, desktop, and common configuration/script files.
- Never sources or executes package content.
- Detects direct network-to-shell execution, encoded execution, reverse shells, install-time package-manager calls, privilege escalation, credential access, persistence, hidden Unicode, symlinks, oversized inputs, and checksum bypasses.
- Supplies current files, deterministic findings, and the previous Git commit diff to Codex as explicitly untrusted data.
- Runs `codex exec` ephemerally, read-only, with user instructions, rules, hooks, apps, web search, and inherited tool environment disabled.
- Blocks on static high/critical findings, Codex `warn`/`block`, low-confidence approval, malformed output, timeout, or any operational failure.
- Refuses `yay --save` so temporary editor-hook settings cannot be persisted accidentally.

## Development-only usage

These commands run directly from this checkout and do not install anything:

```bash
./aur-codex-guard scan tests/fixtures/benign --deterministic-only
./aur-codex-guard scan /path/to/downloaded/aur/package
./aur-codex-guard yay -S package-name
```

The final command is the real integration path and **can install packages through `yay`**. Do not use it until you intentionally reach the installation/testing stage.

Run the local unit tests without installing dependencies:

```bash
python3 -m unittest discover -s tests -v
```

## Exit codes

| Code | Meaning |
| ---: | --- |
| `0` | Explicitly allowed |
| `2` | Security gate closed |
| `3` | Usage or operational error |

When the editor hook exits nonzero, `yay` treats the editor as failed and aborts before building.

## Security limits

This tool reduces risk; it does not prove that software is harmless. Static review can miss malicious upstream source code, build-tool exploits, delayed payloads, environment-dependent behavior, or sufficiently disguised logic. Model review is also fallible and untrusted content may attempt prompt injection.

Use this gate together with package diffs, isolated clean-chroot builds, least privilege, trusted upstream signatures/checksums, and manual review for sensitive packages. See [Threat model](docs/threat-model.md).

## Project status

Alpha. The scanner, fail-closed policy, `yay` command construction, and incident-style fixtures are covered by local tests. Installation and live AUR transaction testing are intentionally deferred.
