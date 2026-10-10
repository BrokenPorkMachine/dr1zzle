"""Host checks for the legacy SEP fake-MMIO model and production guard.

Compiles tests/sep_test.c against src/drivers/sep.c and runs it to verify:
- Legacy mock behavior is internally consistent in test-only builds.
- Per-opcode timeout overrides work in the fake-MMIO build.
- Production initialization fails closed without touching the supplied window.
"""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


class SepDriver(unittest.TestCase):
    def test_sep_driver(self):
        with tempfile.TemporaryDirectory() as temp:
            binary = Path(temp) / "sep_test"
            cc = os.environ.get("HOST_CC", "cc")
            subprocess.run([
                cc, "-std=c11", "-Wall", "-Wextra", "-Werror", "-DSEP_TEST_MMIO",
                "-fsanitize=undefined",
                "-Iinclude", "-Isrc", "-DSOC_t8015",
                "src/drivers/sep.c", "src/util.c", "src/drivers/mmio.c", "tests/sep_stubs.c", "tests/uart_stubs.c",
                "tests/sep_test.c", "-o", str(binary),
            ], cwd=ROOT, check=True)

            result = subprocess.run([str(binary)], cwd=ROOT,
                                    capture_output=True, text=True)
            print(result.stdout)
            if result.stderr:
                print(result.stderr, file=sys.stderr)
            self.assertEqual(result.returncode, 0,
                             "sep_test exited with non-zero status")

    def test_production_transport_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            binary = Path(temp) / "sep_production_guard"
            cc = os.environ.get("HOST_CC", "cc")
            subprocess.run([
                cc, "-std=c11", "-Wall", "-Wextra", "-Werror",
                "-Iinclude", "-Isrc", "-DSOC_t8015",
                "src/drivers/sep.c", "src/util.c", "src/drivers/mmio.c",
                "tests/sep_stubs.c", "tests/uart_stubs.c",
                "tests/sep_production_guard.c", "-o", str(binary),
            ], cwd=ROOT, check=True)
            result = subprocess.run([str(binary)], cwd=ROOT,
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0,
                             "production SEP guard touched or enabled MMIO")


if __name__ == "__main__":
    unittest.main()
