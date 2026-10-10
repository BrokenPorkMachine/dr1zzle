"""Host-side checks for the goatloader server and its pre-configured address.

Two things are checked here that a compile cannot see:

1. The protocol. tests/goatloader_test.c drives src/goat/loader.c the way the
   main loop does -- goatloader_poll() over a fake socket -- and asserts on the
   bytes it produces. That matters because the wire format is a contract with
   goat/cli.py, and "GOAT/1 ERR" where the host tool expects "GOAT/1 OK" is a
   failed push, not a build error.

2. That the two ends still agree. The device's address and port are constants
   in include/net.h and include/goat/loader.h; the host tool's defaults are in
   goat/cli.py. Nothing in the build notices when one side changes, so both are
   read here and compared -- which is what keeps `goat push` working with no
   arguments.

Run: python3 tests/test_goatloader.py
"""

import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class LoaderProtocol(unittest.TestCase):
    def test_protocol_state_machine(self):
        with tempfile.TemporaryDirectory() as temp:
            binary = Path(temp) / "goatloader"
            cc = os.environ.get("HOST_CC", "cc")
            subprocess.run([
                cc, "-std=c11", "-Wall", "-Wextra", "-Werror",
                "-fsanitize=address,undefined",
                "-Iinclude", "-Isrc",
                "src/goat/loader.c", "src/util.c",
                "tests/goatloader_test.c", "-o", str(binary),
            ], cwd=ROOT, check=True)
            # Exit status 45 is the stub goat_enter's "something was wrong with
            # the RUN reply" answer; 44 is "RUN refused when it should not
            # have". Both name themselves in the test file.
            result = subprocess.run([str(binary)], cwd=ROOT,
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0,
                             f"goatloader test failed: {result.stdout}{result.stderr}")


class BothEndsAgree(unittest.TestCase):
    def test_device_port_matches_host_tool(self):
        loader = (ROOT / "include/goat/loader.h").read_text()
        cli = (ROOT / "goat/cli.py").read_text()
        device = re.search(r"#define\s+GOATLOADER_PORT\s+(\d+)u", loader)
        host = re.search(r"GOATLOADER_PORT\s*=\s*(\d+)", cli)
        self.assertIsNotNone(device, "no GOATLOADER_PORT in include/goat/loader.h")
        self.assertIsNotNone(host, "no GOATLOADER_PORT in goat/cli.py")
        self.assertEqual(device.group(1), host.group(1),
                         "device and host tool disagree on the goatloader port")

    def test_device_ipv4_matches_host_tool(self):
        net = (ROOT / "include/net.h").read_text()
        cli = (ROOT / "goat/cli.py").read_text()

        # NET_DEFAULT_IPV4 is written in wire order so it reads the same way
        # round as the address does.
        match = re.search(r"#define\s+NET_DEFAULT_IPV4\s+0x([0-9A-Fa-f]+)u", net)
        self.assertIsNotNone(match, "no NET_DEFAULT_IPV4 in include/net.h")
        value = int(match.group(1), 16)
        octets = ".".join(str((value >> shift) & 0xFF)
                          for shift in (24, 16, 8, 0))

        host = re.search(r'GOATLOADER_IP\s*=\s*"([^"]+)"', cli)
        self.assertIsNotNone(host, "no GOATLOADER_IP in goat/cli.py")
        self.assertEqual(octets, host.group(1),
                         "device address and host tool default disagree: "
                         f"{octets} vs {host.group(1)}")

    def test_address_is_documented_at_boot(self):
        """Bring-up prints where to connect, so a remote side is never guessing."""
        main = (ROOT / "src/main.c").read_text()
        self.assertIn("net_configure_static()", main,
                      "c_main does not configure the static address")
        self.assertIn("goatloader_init()", main,
                      "c_main does not bind the goatloader listener")
        self.assertIn("always on", main,
                      "the boot log does not say the listener is always on")


LLVM = "/opt/homebrew/opt/llvm/bin"


class StagingWindow(unittest.TestCase):
    """The device's staging window is whatever SRAM the linker left over, so
    the host tool's default container placement has to fit inside it. That
    cannot be a constant shared by both sides: it moves whenever the payload
    image does, and the failure it produces -- a container whose plaintext
    would land on the payload's own heap -- is not something a successful
    compile notices."""

    def symbols(self):
        elf = ROOT / "build" / "a11-payload.elf"
        if not elf.exists():
            self.skipTest("build/a11-payload.elf not built")
        nm = Path(LLVM) / "llvm-nm"
        if not nm.exists():
            self.skipTest("llvm-nm not available")
        result = subprocess.run([str(nm), str(elf)], capture_output=True,
                                text=True, check=True)
        found = {}
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) == 3:
                found[parts[2]] = int(parts[0], 16)
        return found

    def test_window_is_inside_sram_and_after_the_image(self):
        found = self.symbols()
        self.assertIn("__stage_base", found, "linker did not reserve a staging window")
        self.assertIn("__stage_limit", found, "linker did not reserve a staging window")
        base, limit = found["__stage_base"], found["__stage_limit"]
        self.assertGreater(limit, base, "staging window is empty")
        self.assertEqual(limit, 0x1801E8000, "window does not reach the end of SRAM")
        # The window starts after the payload's own stack, not on top of it.
        self.assertLessEqual(found["_stack_top"], base)

    def test_default_load_base_fits_the_window(self):
        found = self.symbols()
        if "__stage_base" not in found:
            self.skipTest("linker did not reserve a staging window")
        base, limit = found["__stage_base"], found["__stage_limit"]
        container = (ROOT / "goat/container.py").read_text()
        default = re.search(r"GOAT_DEFAULT_LOAD_BASE = (0x[0-9a-fA-F]+)",
                            container)
        self.assertIsNotNone(default, "no GOAT_DEFAULT_LOAD_BASE in goat/container.py")
        address = int(default.group(1), 16)
        self.assertLessEqual(base, address,
                             "the host tool's default load base is below the "
                             "device's staging window")
        self.assertLess(address, limit,
                        "the host tool's default load base is above the device's "
                        "staging window")


if __name__ == "__main__":
    unittest.main(verbosity=2)
