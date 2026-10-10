"""Host-only checks for the storage/crypto pieces of phase 4."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class Phase4(unittest.TestCase):
    def test_apfs_aes_and_keybag_parser(self):
        with tempfile.TemporaryDirectory() as temp:
            binary = Path(temp) / "phase4"
            cc = os.environ.get("HOST_CC", "cc")
            subprocess.run([
                cc, "-std=c11", "-Wall", "-Wextra", "-Werror",
                "-fsanitize=address,undefined", "-Iinclude", "-Isrc",
                "src/fs/apfs.c", "src/research/keybag.c", "src/goat/aes.c",
                "tests/phase4_host_test.c", "-o", str(binary),
            ], cwd=ROOT, check=True)
            subprocess.run([str(binary)], cwd=ROOT, check=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
