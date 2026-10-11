#!/usr/bin/env python3
"""Host guard for the Rust-native RPWN replacement."""
import os
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class RpwnRust(unittest.TestCase):
    def test_rust_suite(self):
        result = subprocess.run(
            ["cargo", "test", "--locked", "--manifest-path",
             str(ROOT / "rpwn" / "rust" / "Cargo.toml")],
            cwd=ROOT, capture_output=True, text=True,
            env={**os.environ, "CARGO_TARGET_DIR": "/private/tmp/dr1zzle-rpwn-test"})
        self.assertEqual(result.returncode, 0,
                         f"RPWN Rust tests failed:\n{result.stdout}{result.stderr}")


if __name__ == "__main__":
    unittest.main()
