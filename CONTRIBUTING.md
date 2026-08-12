# Contributing

This is a public project. Use GitHub issues and pull requests for normal bugs, documentation, and code changes. Report suspected security bypasses privately as described in [SECURITY.md](SECURITY.md).

Keep changes fail-closed and avoid executing fixture content. Security fixtures must be inert text that demonstrates a pattern without contacting a network, changing the host, or containing live malware.

Before submitting a change, run:

```bash
python3 -m unittest discover -s tests -v
python3 scripts/run_policy_evals.py
ruff check .
ruff format --check .
mypy aur_codex_guard
shellcheck scripts/*.sh packaging/system/*
```

Changes to the `yay` or `makepkg` integration should include a regression test and an update to the threat model when they alter a guarantee or trust boundary. Never weaken a blocking condition merely to make a real package pass; document and design a narrow policy exception instead.

## Release checklist

1. Update `aur_codex_guard/__init__.py` and `CHANGELOG.md`. The build reads its version from that single source.
2. Run the complete checks above and `python3 -m build --wheel`.
3. Test `./aur-codex-guard doctor --live` on current Arch.
4. Install from the checkout and complete one intentional AUR upgrade through plain `yay`.
5. Commit and push, then require both CI and Rolling compatibility to pass before tagging or publishing.
