# AUR Codex Guard

AUR Codex Guard is a conservative, fail-closed security gate for [`yay`](https://github.com/Jguer/yay). It reviews AUR build metadata after `yay` downloads it and before `makepkg` runs, then verifies that the reviewed files remain unchanged through the build.

This is currently a development checkout. **Nothing here installs itself, changes `yay` configuration, creates aliases, or modifies system files.**

## What it enforces

- Forces yay to clean the checkout, then reads every regular file outside `.git`; pre-existing `src`, `pkg`, `__pycache__`, and unknown extensions are not silently skipped.
- Rejects symlinks, special files, binary/non-UTF-8 data, invisible Unicode, unreadable data, and oversized review inputs.
- Applies deterministic rules for network-to-shell execution, encoded payloads, reverse shells, privilege escalation, credential access, persistence, destructive commands, install-time downloads, and other high-risk behavior.
- Reviews one AUR package at a time with `codex exec`, explicitly pinned to `gpt-5.6-sol` and `high` reasoning.
- Applies one language-independent policy based on build phase, destination, side effects, and crossed trust boundaries. Build-local dependency resolution, compilation, testing, and staging are baseline behavior regardless of tool name; secrets, host mutation, privilege, persistence, integrity bypass, and unexplained remote execution are escalated.
- Checks Codex's [documented non-interactive capabilities](https://learn.chatgpt.com/docs/non-interactive-mode) instead of pinning one fast-moving CLI patch version. A changed Codex executable must pass a harmless live structured-output canary before `yay` starts; successful canaries are cached by executable SHA-256 and compatibility-contract version.
- Runs Codex ephemerally in a fresh directory with a read-only sandbox, approval prompts disabled, and shell, unified-exec, multi-agent, hooks, apps, web search, project instructions, and inherited tool environment disabled.
- Requires an exact file manifest and `coverage_complete: true`. Only a finding-free, limitation-free, high-confidence `allow` opens automatically; every error or inconsistent response blocks.
- Treats a complete Codex `warn` with no limitations and at least medium confidence as a human decision: the interactive hook displays the findings and requires an explicit `y`/`yes`. Codex `block`, low confidence, incomplete coverage, limitations, malformed output, or non-interactive warning review remains blocked, and `--noconfirm` never auto-accepts a warning.
- Accepts only explicit `yay -S`/`--sync` installation transactions. It rejects guard-controlled options in both `--option value` and `--option=value` forms, then places enforced settings first to match yay's first-value precedence.
- Forces `yay --combinedupgrade`, metadata re-download, rebuild, the editor hook, an empty makepkg flag override, and the guarded `makepkg` wrapper.
- Gives yay fresh private XDG config/cache directories, preventing persisted yay settings or Lua hooks from joining the transaction. A private makepkg configuration and fresh `PKGDEST`, `SRCDEST`, `SRCPKGDEST`, `BUILDDIR`, and `LOGDEST` prevent pre-existing package archives from satisfying cache checks.
- Creates an authenticated, per-transaction receipt over each reviewed file's path, SHA-256 hash, and mode. Every `makepkg` call verifies it before execution and final builds verify it again afterward.
- Inspects built package archives for duplicate/traversal paths, unsafe links, special files, setuid/setgid entries, unsafe world-writable entries, and dangerous `.INSTALL`, Pacman hook, preset, tmpfiles, sysusers, udev, and sudoers control data.
- Serializes guarded transactions and records content-free review and terminal-result JSONL audit events under `${XDG_STATE_HOME:-~/.local/state}/aur-codex-guard/audit.jsonl` with mode `0600`; the log rotates at 5 MiB.
- Prints a colored, aligned terminal report when attached to a TTY, automatically falls back to plain text for redirection, and respects the standard `NO_COLOR` environment variable.
- Presents the user-facing outcomes as `PASS`, `REVIEW`, and `BLOCK`. `PASS` means no suspicious behavior was detected in the reviewed metadata, not that absolute safety is guaranteed; `REVIEW` means a concrete unusual behavior needs a decision and does not itself imply malware.
- Prints an immediate progress header before both a package review and any one-time post-update Codex compatibility canary, including that the model call may take a few minutes.

```text
yay resolves transaction
        |
        v
downloads AUR git metadata
        |
        v
forced editor hook -> deterministic scan -> Codex gpt-5.6-sol/high
        |                    |                       |
        |                    +-- high/critical -----+-- anything but complete,
        |                                               high-confidence ALLOW
        v
signed file receipt
        |
        v
guarded makepkg -> argument/receipt checks -> build -> receipt check -> archive check
        |
        v
yay may install
```

## Failure behavior

For a transaction containing an AUR target, a deterministic block or Codex failure happens before package installation. `--combinedupgrade` prevents `yay -Syu` from installing repository upgrades before that AUR review completes. Authentication errors, an unavailable model, loss of network access, rate limits, malformed output, timeouts, receipt errors, and pre-build audit-log errors all close the gate. If writing the terminal audit event fails after yay exits, the wrapper reports an operational error but cannot undo an already completed transaction.

The Codex canary contains only a bundled harmless fixture. It runs before `yay` whenever the Codex executable or compatibility contract changes, so an incompatible update fails before AUR metadata is downloaded. Every package still receives its own independent review; the cache never substitutes for reviewing package content.

A complete `WARN` is not installed automatically and is not treated as harmless. In an interactive guarded-yay transaction, the user can explicitly accept that warning after reading its findings. The audit entry preserves the original Codex verdict and records `human_override: true`. Pressing Enter, answering no, losing the terminal, or running non-interactively keeps the gate closed. Hard blocks cannot be overridden.

The guarantee is deliberately narrower than “the machine is unchanged”:

- Pacman sync databases and `yay` metadata/cache may be refreshed before a review fails.
- A repository-only transaction has no AUR metadata and therefore does not invoke Codex.
- A failure after an approved build starts can leave downloaded sources, build directories, package artifacts, or build dependencies. A post-build inspection failure prevents the target AUR archive from being handed back as successful, but it cannot undo earlier build-side effects safely.
- Direct `yay`, `makepkg`, another AUR helper, or `pacman -U` bypasses this wrapper. The wrapper itself rejects `yay -U`, search/query/clean/download-only modes, alternate makepkg recipes/configuration, and integrity-bypass flags.

The project does not attempt risky rollback of Pacman databases or installed dependencies.

## Development usage

These commands run from the checkout and do not install the project:

```bash
./aur-codex-guard scan tests/fixtures/benign --deterministic-only
./aur-codex-guard scan /path/to/downloaded/aur/package
./aur-codex-guard doctor
./aur-codex-guard doctor --live
python3 -m unittest discover -s tests -v
python3 scripts/run_policy_evals.py
ruff check .
ruff format --check .
```

The policy evaluation matrix includes representative native, Rust, Node, Python, JVM, .NET, Haskell, Ruby, and Go builds, plus an intentionally unfamiliar fictional toolchain. These cases are regression examples, not a command or language allowlist. Suspicious cases assert that concrete secret-access, persistence, and unverified-remote-execution boundaries remain blocked.

The default evaluation is offline and deterministic. A live evaluation sends each selected conventional fixture to Codex, but still never builds or installs it:

```bash
python3 scripts/run_policy_evals.py --live
python3 scripts/run_policy_evals.py --live --case unfamiliar_toolchain
```

The real integration path is shown below, but it **can install packages through `yay`** and should only be used during an intentional installation test:

```bash
./aur-codex-guard yay -S package-name
```

## Exit codes

| Code | Meaning |
| ---: | --- |
| `0` | Explicitly allowed |
| `2` | Security policy closed the gate |
| `3` | Usage, integrity, or operational failure |

## Security limits

An `allow` is not proof that a package is harmless. After approval, `makepkg` sources the `PKGBUILD`, downloads upstream sources, and executes build functions as the user. Malicious upstream code, compiler/build-tool exploits, compromised dependencies, delayed payloads, prompt injection, or sufficiently disguised logic can still evade this design and cause harm before Pacman installation.

For sensitive software, combine this gate with manual diff review, pinned signatures/checksums, trusted upstreams, and isolated clean-chroot builds. Read the full [threat model](docs/threat-model.md) before relying on it.

## Compatibility policy

Compatibility is based on narrow version families plus runtime capabilities:

- Codex CLI must be at least `0.145.0`, must not be denylisted, and must expose every isolation, strict-configuration, structured-output, and feature-disable interface required by the guard. There is no patch/minor upper pin because a changed executable must pass the live canary and the real review remains fail-closed.
- `yay` must be `>=13.0.1,<14.0.0` and pass editor, rebuild, re-download, makepkg-wrapper, and combined-upgrade capability checks. A new major release is blocked until its transaction behavior and makepkg invocation shapes are reviewed.
- `makepkg` must be `>=7.1.0,<8.0.0`; `bsdtar` must be `>=3.8.0,<4.0.0`. Their required behavior is also exercised by integration and archive tests.

`doctor` performs local checks without contacting the model. `doctor --live` also runs the canary, while `doctor --live --refresh` ignores a valid cache and runs it again. The cache is advisory only: corruption or deletion causes another canary, and a successful cache entry never opens the package gate.

## Project status

Version 0.4.0 is pre-release software. Unit tests and CI cover option-bypass regressions, compatibility ranges and capabilities, canary caching, language-independent trust-boundary policy cases, terminal progress/color/plain-text behavior, explicit review acceptance and rejection, a fake yay/makepkg transaction path, the fail-closed model policy, timeout handling, receipts, and real archive fixtures. A real AUR installation has intentionally not been completed from this checkout yet.
