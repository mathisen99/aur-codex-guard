# Changelog

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
