# Changelog

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
