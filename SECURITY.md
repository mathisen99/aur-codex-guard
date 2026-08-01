# Security policy

This project is pre-release security tooling. An `allow` verdict is advisory and never proves that an AUR package is safe.

Report suspected bypasses through a private GitHub security advisory when that feature is available. If it is unavailable, open a minimal issue asking the maintainer to establish a private contact channel without disclosing exploit details. Do not publish a working exploit while remediation is in progress.

Reports should include the affected version, the exact guarded command, expected and actual behavior, and the smallest inert reproducer possible. Do not attach live credentials, private package contents, or executable malware.

Security-relevant scope includes fail-open behavior, bypass of the forced editor/makepkg path, receipt verification errors, unsafe archive acceptance, secret disclosure, and misleading guarantees. Model misclassification alone is expected residual risk unless it demonstrates a reproducible implementation bypass.
