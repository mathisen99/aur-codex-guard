# Threat model

## Goal

Stop suspicious AUR metadata before any package-controlled build or installation code executes, while making routine changes reviewable.

## Trusted components

- The local Python interpreter and this project's checked-out code
- The locally installed `yay`, Git, and Codex CLI binaries
- Codex CLI authentication storage and the OpenAI service
- The user's explicit decision after a blocked review

## Untrusted inputs

- Every file in an AUR package repository
- Git history and diffs from that repository
- Package names, paths, comments, source URLs, and generated metadata
- Text that tries to instruct or manipulate the model

## Defenses

1. `yay`'s editor stage runs after AUR metadata download and before build execution.
2. Guard options are appended after passthrough arguments so caller-supplied editor options cannot disable the hook.
3. AUR metadata re-download and rebuild are forced so an old cached package cannot skip the hook.
4. The hook scans each package directory without sourcing `PKGBUILD`.
5. Symlinks are not followed, binary/oversized metadata blocks the gate, and scan limits fail closed.
6. High/critical deterministic findings cannot be overruled by the model.
7. Codex receives a serialized review bundle from a fresh temporary directory rather than entering the untrusted repository.
8. Codex runs ephemerally and read-only with project/user rules, hooks, apps, web search, and shell environment inheritance disabled.
9. Only an explicit `allow` with at least medium confidence opens the gate. Errors and uncertainty block.

## Important non-goals

- Proving the absence of malware
- Fully reviewing downloaded upstream source archives or VCS history
- Detecting vulnerabilities that require dynamic execution to observe
- Protecting users who invoke unguarded `yay`, `makepkg`, or `pacman -U` directly
- Replacing clean-chroot/container builds or human review

## Remaining risks

- The reviewed metadata can download a different or compromised upstream artifact later.
- Valid checksums prove identity, not safety.
- A malicious compiler, build tool, dependency, or already-compromised host is outside this boundary.
- A sufficiently subtle payload can evade both deterministic rules and model reasoning.
- The model can be influenced by adversarial text despite explicit data/instruction separation.
- A package update can occur between separate download and build operations; the enforced `yay` editor stage avoids that specific race for the transaction it guards.
