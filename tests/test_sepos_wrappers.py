"""Host checks for the SEP shell-wrapper layer.

src/research/sepos.c owns the single static driver instance and the one-shot
init latch that the shell commands go through. It had no test, so these drive
it exactly as the shell does, over the same fake MMIO the driver tests use,
which checks the two layers against each other rather than each only against
itself.

Run: python3 -m unittest tests.test_sepos_wrappers
"""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


class SeposWrappers(unittest.TestCase):
    def test_wrapper_layer(self):
        with tempfile.TemporaryDirectory() as temp:
            binary = Path(temp) / "sepos_wrapper_test"
            cc = os.environ.get("HOST_CC", "cc")
            subprocess.run([
                cc, "-std=c11", "-Wall", "-Wextra", "-Werror",
                "-fsanitize=undefined",
                "-DSEP_HOST_TEST",
                "-Iinclude", "-Isrc", "-DSOC_t8015",
                "src/research/sepos.c", "src/drivers/sep.c", "src/util.c",
                "src/drivers/mmio.c",
                "tests/sep_stubs.c", "tests/uart_stubs.c",
                "tests/sepos_wrapper_test.c", "-o", str(binary),
            ], cwd=ROOT, check=True)

            result = subprocess.run([str(binary)], cwd=ROOT,
                                    capture_output=True, text=True)
            print(result.stdout)
            if result.stderr:
                print(result.stderr, file=sys.stderr)
            self.assertEqual(result.returncode, 0,
                             "sepos wrapper test exited non-zero")


if __name__ == "__main__":
    unittest.main()