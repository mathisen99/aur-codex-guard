# Changelog

## 0.5.1 - 2026-08-01

- Fixed built-package inspection falsely treating the conventional `lrwxrwxrwx` display mode of symlinks as a world-writable file.
- Accepted absolute package symlinks and relative parent segments only when their lexical target remains inside the installed filesystem tree, while rejecting archive entries nested beneath a symlink.
- Allowed an update to preserve setuid/setgid bits already present on the same installed regular-file path; packages that introduce a new privileged executable remain blocked.
- Added regression coverage and validated the corrected inspector against cached archives for Chrome, VS Code, Zen Browser, Pi, and both normal and debug FVS2 packages.
- Completed a real guarded FVS2 update from metadata download through Codex review, build, archive inspection, and successful Pacman installation.
- Simplified the README, added project artwork and a real terminal screenshot, made the package version single-source, and tightened CI and maintainer guidance.
- Fixed the checkout-only makepkg launcher so it imports reliably when yay invokes it from an external build directory.

## 0.5.0 - 2026-08-01

- Added an explicit root-owned `/usr/local` installer that leaves `/usr/bin/yay` package-managed and places a transparent `yay` dispatcher earlier in normal system `PATH` resolution.
- Guarded plain `yay`, `yay -S`, and `yay -Syu`; passed read-only and unrelated operations to the real yay; and refused ambiguous interactive selection, local build/archive, and download-only execution shapes.
- Added staged install, collision refusal, uninstall, dispatcher, command-resolution, and bypass-classification tests.
- Replaced false-positive keyword checks with contextual credential paths and host actions, distinguished `$pkgdir` staging from live-system mutation, and treated zero-width characters in localized desktop display text as informational while retaining hard blocks in executable metadata.
- Completed a live five-package pending-update review with high-confidence passes and aborted before installation.

## 0.4.0 - 2026-08-01

- Replaced brittle exact Codex pinning with minimum-version, CLI-capability, and disabled-feature checks.
- Added a harmless structured-output canary before yay starts, cached by Codex executable hash and compatibility-contract version.
- Added `doctor`, JSON diagnostics, live/forced canary modes, and fail-closed preflight reporting.
- Accepted compatible yay 13.x, makepkg 7.x, and bsdtar 3.x updates while retaining major-version gates and strict invocation checks.
- Added TTY-aware colored, aligned, and wrapped human reports with plain redirected output and `NO_COLOR` support.
- Added immediate package/canary progress messages and explicit interactive acceptance for complete, limitation-free Codex warnings; hard or non-interactive cases still fail closed and overrides are audited.
- Replaced ecosystem-specific dependency warnings with a language-independent policy based on build phase, destination, side effects, and crossed trust boundaries; added representative and intentionally unfamiliar toolchain policy evaluations while retaining hard blocks for concrete dangerous behavior.
- Replaced alarming user-facing `ALLOW/WARN` labels with `PASS/REVIEW` while retaining the internal fail-closed verdicts.
- Added compatibility and canary regression tests plus a scheduled latest-Arch compatibility workflow.

## 0.3.0 - 2026-08-01

- Closed yay's first-value option-precedence bypass and rejected protected `--option=value` forms.
- Restricted the wrapper to explicit sync/install operations and pinned the audited yay/Codex interfaces.
- Added private per-transaction makepkg configuration and fresh artifact/source/build destinations.
- Added a strict yay 13.0.1 makepkg argument allowlist and cached/no-build archive inspection.
- Disabled Codex shell, unified-exec, multi-agent, project-instruction, and approval surfaces.
- Failed closed on inconsistent `allow` responses containing findings.
- Fixed `.INSTALL` matching and expanded archive checks to duplicates, special files, hardlinks, and privileged control data.
- Hardened receipt traversal against intermediate symlink substitution.
- Added terminal transaction audit events, bounded log rotation, integration-style fakes, timeout coverage, real archive tests, mypy, and wheel builds.

## 0.2.0 - Unreleased

- Pin Codex review to `gpt-5.6-sol` with high reasoning and strict configuration.
- Require high-confidence, complete, exact-manifest, limitation-free model approval.
- Review and hash every regular metadata file regardless of extension.
- Add process-group timeout cleanup, per-package Codex review batches, and fail-closed audit logging.
- Force combined upgrades and serialize guarded `yay` transactions.
- Add authenticated file receipts and a guarded `makepkg` wrapper to detect post-review changes.
- Inspect built archives for dangerous paths, permissions, symlinks, and install metadata.
- Add CI, public-contribution guidance, and a more precise threat model.

## 0.1.0

- Initial deterministic scanner, Codex review gate, and forced `yay` editor integration.
