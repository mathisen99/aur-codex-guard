# Threat model

## Security objective

Reduce the chance that malicious or unexpectedly dangerous AUR build metadata reaches `makepkg` or Pacman unnoticed. Close the transaction when review completeness, model availability, or file integrity cannot be established.

This is a risk-reduction layer, not a sandbox and not a proof of safety.

## Boundary and sequence

1. The wrapper accepts only explicit sync/install transactions, rejects conflicting plumbing options, gives yay isolated config/cache directories, and forces clean checkout, `--combinedupgrade`, re-download, rebuild, an empty makepkg flag override, a private makepkg configuration, and the AUR editor hook.
2. `yay` clones or refreshes AUR metadata before invoking the hook.
3. The hook reads all regular metadata files without sourcing `PKGBUILD` and runs deterministic checks.
4. If static policy permits model review, Codex reviews each package independently from a fresh temporary directory with no shell, unified-exec, multi-agent, app, hook, or web-search tool surface.
5. A high-confidence, complete, finding-free, limitation-free `allow` creates an authenticated receipt covering the reviewed root identity plus each path, hash, and mode.
6. Every `makepkg` invocation must match the yay 13.0.1 argument allowlist and validates the receipt through no-follow directory descriptors. Final and cached/no-build outputs are confined to a fresh private package destination, validated again, and inspected before returning success.
7. Only then may `yay` install the AUR packages and any deferred repository upgrades.

`--combinedupgrade` is essential for mixed `-Syu` transactions: without it, `yay` can perform the repository upgrade before preparing and reviewing AUR targets.

## Trusted components

- This project's local code and Python interpreter
- The resolved local `yay`, `makepkg`, Git, `bsdtar`, Pacman, and Codex CLI binaries
- Codex authentication storage and the OpenAI service
- The operating system, current user account, and already-installed build toolchain
- AUR helper behavior compatible with the tested `yay` editor and makepkg interfaces

Compromise of a trusted component is out of scope.

## Untrusted inputs

- Every file and Git diff in an AUR package checkout
- Package names, paths, comments, source URLs, and generated metadata
- Model prompt-injection attempts embedded in package content
- Built package archive paths and metadata
- Upstream source archives and VCS checkouts, although these are not comprehensively reviewed

## Fail-closed conditions

- High or critical deterministic finding
- Symlink, special file, binary/non-UTF-8 input, scan race, unreadable file, or size limit
- Codex unavailable, unauthenticated, rate-limited, offline, timed out, killed, or returning malformed output
- Any Codex verdict other than `allow`
- Confidence below high, incomplete coverage, a non-exact reviewed-file manifest, any finding, or any limitation
- Missing, invalid, or mismatched approval receipt
- Reviewed path content or mode changes before or during build
- Audit event cannot be durably written for an allowed review
- Unexpected makepkg argument/configuration, package destination escape, or cached artifact outside the private transaction
- Built archive inspection fails or finds a forbidden path, link, file type, permission, or package-control behavior

## Explicit non-goals and residual risk

- The gate does not prove the absence of malware.
- It does not comprehensively analyze downloaded upstream sources or compiled binaries.
- It does not confine `prepare()`, `build()`, `check()`, or `package()`; these run as the invoking user after approval and can cause harm before installation.
- Valid checksums prove artifact identity, not safety. `SKIP` may also be legitimate for pinned VCS sources and is therefore escalated to Codex rather than always blocked.
- A subtle payload may evade deterministic rules and model reasoning.
- Receipt authentication protects transaction integrity but is not a security boundary after attacker-controlled code is already executing as the same user.
- The transaction secret is inherited by yay and can potentially be read by malicious same-user code through operating-system process introspection. It protects pre-build integrity; it is not a post-code-execution boundary.
- Repository-only transactions do not have AUR metadata and do not invoke this gate.
- Pacman sync databases, AUR caches, downloaded sources, build directories, artifacts, or build dependencies can change even when a later phase fails.
- The wrapper does not protect direct calls to `yay`, `makepkg`, other helpers, or `pacman -U`.
- Concurrent unguarded package operations are outside the transaction lock.
- Safe automatic rollback of Pacman state is not attempted.
- A terminal audit failure can be reported only after yay exits and cannot undo a transaction that already succeeded.

The strongest future improvement would be building approved packages in a disposable, network-constrained clean chroot and reviewing provenance for downloaded sources. That is intentionally not simulated with a partial home-grown sandbox.
