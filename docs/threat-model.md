# Threat model

## Security objective

Reduce the chance that malicious or unexpectedly dangerous AUR build metadata reaches `makepkg` or Pacman unnoticed. Close the transaction when review completeness, model availability, or file integrity cannot be established.

This is a risk-reduction layer, not a sandbox and not a proof of safety.

## Boundary and sequence

1. The wrapper accepts only explicit sync/install transactions, rejects conflicting plumbing options, and verifies the supported yay, makepkg, bsdtar, and Codex interfaces.
2. Before yay starts, a changed Codex executable must satisfy the local capability contract and pass a harmless live structured-output canary. Successful canaries are cached by executable hash, guard version, and contract version.
3. The wrapper gives yay isolated config/cache directories and forces clean checkout, `--combinedupgrade`, re-download, rebuild, an empty makepkg flag override, a private makepkg configuration, and the AUR editor hook.
4. `yay` clones or refreshes AUR metadata before invoking the hook.
5. The hook reads all regular metadata files without sourcing `PKGBUILD` and runs deterministic checks.
6. If static policy permits model review, Codex reviews each package independently from a fresh temporary directory with no shell, unified-exec, multi-agent, app, hook, or web-search tool surface.
7. A high-confidence, complete, finding-free, limitation-free `allow` opens automatically. A complete, limitation-free `warn` with at least medium confidence requires an explicit interactive human decision; acceptance is recorded without erasing the original Codex verdict. All other non-allows remain blocked.
8. An allowed or explicitly accepted review creates an authenticated receipt covering the reviewed root identity plus each path, hash, and mode.
9. Every `makepkg` invocation must match the yay 13.x argument allowlist and validates the receipt through no-follow directory descriptors. Final and cached/no-build outputs are confined to a fresh private package destination, validated again, and inspected before returning success.
10. Only then may `yay` install the AUR packages and any deferred repository upgrades.

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
- Unsupported tool family, missing Codex/yay capability, or failed Codex compatibility canary
- Codex `block`; Codex `warn` without explicit interactive acceptance; or a warning prompt without a controlling terminal
- Low confidence, a non-high-confidence `allow`, incomplete coverage, a non-exact reviewed-file manifest, any limitation, or findings accompanying an `allow`
- Missing, invalid, or mismatched approval receipt
- Reviewed path content or mode changes before or during build
- Audit event cannot be durably written for an allowed review
- Unexpected makepkg argument/configuration, package destination escape, or cached artifact outside the private transaction
- Built archive inspection fails or finds a forbidden path, link, file type, permission, or package-control behavior

## Explicit non-goals and residual risk

- The gate does not prove the absence of malware.
- A cached canary proves only that the same Codex executable previously completed the compatibility fixture. It never replaces the current package review, and server-side model behavior can still change between calls.
- It does not comprehensively analyze downloaded upstream sources or compiled binaries.
- It does not confine `prepare()`, `build()`, `check()`, or `package()`; these run as the invoking user after approval and can cause harm before installation.
- Valid checksums prove artifact identity, not safety. `SKIP` may also be legitimate for pinned VCS sources and is therefore escalated to Codex rather than always blocked.
- A subtle payload may evade deterministic rules and model reasoning.
- Policy is based on behavior, phase, destination, and crossed trust boundaries rather than recognizing a finite set of languages or commands. Build-local dependency resolution, compilation, test execution, and `$pkgdir` staging are baseline behavior even for an unfamiliar toolchain. Secret access, host mutation, privilege, persistence, integrity bypass, unexplained remote execution, or other purpose-inconsistent side effects remain in scope.
- This semantic calibration reduces alert fatigue but can also hide malicious behavior inside otherwise ordinary build steps. The representative ecosystem fixtures are regression examples, not proof that any ecosystem—or any package using it—is safe.
- Human warning acceptance is a deliberate risk decision, not a security finding dismissal. A user can approve dangerous behavior, so the audit retains both the Codex warning and the override flag.
- Receipt authentication protects transaction integrity but is not a security boundary after attacker-controlled code is already executing as the same user.
- The transaction secret is inherited by yay and can potentially be read by malicious same-user code through operating-system process introspection. It protects pre-build integrity; it is not a post-code-execution boundary.
- Repository-only transactions do not have AUR metadata and do not invoke this gate.
- Pacman sync databases, AUR caches, downloaded sources, build directories, artifacts, or build dependencies can change even when a later phase fails.
- The wrapper does not protect direct calls to `yay`, `makepkg`, other helpers, or `pacman -U`.
- Concurrent unguarded package operations are outside the transaction lock.
- Safe automatic rollback of Pacman state is not attempted.
- A terminal audit failure can be reported only after yay exits and cannot undo a transaction that already succeeded.

The strongest future improvement would be building approved packages in a disposable, network-constrained clean chroot and reviewing provenance for downloaded sources. That is intentionally not simulated with a partial home-grown sandbox.
