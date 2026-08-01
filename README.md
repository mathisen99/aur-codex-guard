# AUR Codex Guard

AUR Codex Guard is a conservative, fail-closed security gate for [`yay`](https://github.com/Jguer/yay). It reviews AUR build metadata after `yay` downloads it and before `makepkg` runs, then verifies that the reviewed files remain unchanged through the build.

This is currently a development checkout. **Nothing here installs itself, changes `yay` configuration, creates aliases, or modifies system files.**

## What it enforces

- Reads every regular metadata file outside `.git`, `src`, and `pkg`; unknown extensions are not silently skipped.
- Rejects symlinks, special files, binary/non-UTF-8 data, invisible Unicode, unreadable data, and oversized review inputs.
- Applies deterministic rules for network-to-shell execution, encoded payloads, reverse shells, privilege escalation, credential access, persistence, destructive commands, install-time downloads, and other high-risk behavior.
- Reviews one AUR package at a time with `codex exec`, explicitly pinned to `gpt-5.6-sol` and `high` reasoning.
- Runs Codex ephemerally in a fresh directory with a read-only sandbox, strict configuration, user rules/instructions, hooks, apps, web search, and inherited tool environment disabled.
- Requires an exact file manifest, `coverage_complete: true`, an empty limitation list, and a high-confidence `allow`. Every error or weaker result blocks.
- Forces `yay --combinedupgrade`, metadata re-download, rebuild, the editor hook, and a guarded `makepkg` wrapper. User-supplied conflicting flags appear earlier and cannot silently replace these settings.
- Creates an authenticated, per-transaction receipt over each reviewed file's path, SHA-256 hash, and mode. Every `makepkg` call verifies it before execution and final builds verify it again afterward.
- Inspects built package archives for traversal paths, unsafe symlinks, setuid/setgid entries, unsafe world-writable entries, and dangerous generated `.INSTALL` metadata.
- Serializes guarded transactions and records content-free JSONL audit events under `${XDG_STATE_HOME:-~/.local/state}/aur-codex-guard/audit.jsonl` with mode `0600`.

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
guarded makepkg -> receipt check -> build -> receipt check -> archive check
        |
        v
yay may install
```

## Failure behavior

For a transaction containing an AUR target, a deterministic block or Codex failure happens before package installation. `--combinedupgrade` prevents `yay -Syu` from installing repository upgrades before that AUR review completes. Authentication errors, an unavailable model, loss of network access, rate limits, malformed output, timeouts, receipt errors, and audit-log errors all close the gate.

The guarantee is deliberately narrower than “the machine is unchanged”:

- Pacman sync databases and `yay` metadata/cache may be refreshed before a review fails.
- A repository-only transaction has no AUR metadata and therefore does not invoke Codex.
- A failure after an approved build starts can leave downloaded sources, build directories, package artifacts, or build dependencies. A post-build inspection failure prevents the target AUR archive from being handed back as successful, but it cannot undo earlier build-side effects safely.
- Direct `yay`, `makepkg`, another AUR helper, or `pacman -U` bypasses this wrapper.

The project does not attempt risky rollback of Pacman databases or installed dependencies.

## Development usage

These commands run from the checkout and do not install the project:

```bash
./aur-codex-guard scan tests/fixtures/benign --deterministic-only
./aur-codex-guard scan /path/to/downloaded/aur/package
python3 -m unittest discover -s tests -v
ruff check .
ruff format --check .
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

## Project status

Version 0.2.0 is pre-release software. Unit tests and CI cover the static gate, fail-closed model policy, command construction, receipts, and archive-policy primitives. A real AUR installation has intentionally not been performed from this checkout yet.
