from __future__ import annotations

import unittest
from pathlib import Path

from aur_codex_guard.scanner import deterministic_scan

FIXTURES = Path(__file__).parent / "fixtures" / "policy"
EXPECTED_CONVENTIONAL_CASES = {
    "dotnet_locked",
    "go_modules",
    "haskell_cabal",
    "jvm_gradle",
    "native_cmake",
    "node_pnpm",
    "python_pep517",
    "ruby_bundler",
    "rust_cargo",
    "unfamiliar_toolchain",
}


class SemanticPolicyTests(unittest.TestCase):
    def test_representative_ecosystem_matrix_does_not_become_an_allowlist(self) -> None:
        roots = sorted(path for path in (FIXTURES / "conventional").iterdir() if path.is_dir())
        self.assertEqual({path.name for path in roots}, EXPECTED_CONVENTIONAL_CASES)
        for root in roots:
            with self.subTest(case=root.name):
                report = deterministic_scan([root])
                self.assertEqual(report.deterministic_verdict, "allow")
                self.assertEqual(report.findings, [])

    def test_concrete_boundary_crossings_are_blocked_regardless_of_toolchain(self) -> None:
        roots = sorted(path for path in (FIXTURES / "suspicious").iterdir() if path.is_dir())
        self.assertGreaterEqual(len(roots), 3)
        for root in roots:
            with self.subTest(case=root.name):
                report = deterministic_scan([root])
                self.assertEqual(report.deterministic_verdict, "block")


if __name__ == "__main__":
    unittest.main()
