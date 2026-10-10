"""Host checks for the SEP ASC mailbox driver.

Audit source: pongoOS src/drivers/sep/sep.c.

Compiles tests/sep_test.c against src/drivers/sep.c over fake MMIO and runs it.
The tests pin the things that must not drift from the reference:

- the 64-bit mailbox register offsets (0x8100..0x8838, A11 layout);
- the packed message layout ep|tag<<8|opcode<<16|param<<24|data<<32;
- the SEPROM endpoint (255) and the opcode+100 reply convention;
- opcode values 1 (ping), 16 (random), 5 (boot_tz0), 6 (send_sepos),
  17 (integrity tree) and the panic message (opcode 255);
- recv_sts bit 17 (0x20000) as "IOP->AP queue empty".

Run: python3 -m unittest tests.test_sep
"""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


class SepMailboxDriver(unittest.TestCase):
    def test_pongoos_protocol_conformance(self):
        with tempfile.TemporaryDirectory() as temp:
            binary = Path(temp) / "sep_test"
            cc = os.environ.get("HOST_CC", "cc")
            subprocess.run([
                cc, "-std=c11", "-Wall", "-Wextra", "-Werror",
                "-fsanitize=undefined",
                "-Iinclude", "-Isrc", "-DSOC_t8015",
                "src/drivers/sep.c", "src/util.c", "src/drivers/mmio.c",
                "tests/sep_stubs.c", "tests/uart_stubs.c",
                "tests/sep_test.c", "-o", str(binary),
            ], cwd=ROOT, check=True)

            result = subprocess.run([str(binary)], cwd=ROOT,
                                    capture_output=True, text=True)
            print(result.stdout)
            if result.stderr:
                print(result.stderr, file=sys.stderr)
            self.assertEqual(result.returncode, 0,
                             "sep_test exited non-zero: protocol drift from pongoOS")


if __name__ == "__main__":
    unittest.main()