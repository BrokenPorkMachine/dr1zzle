#!/usr/bin/env python3
"""Guards the vendored checkm8 tree (ipwndfu/) as Python 3.

The tree arrived as Python 2. No current macOS ships a Python 2 interpreter and
arm64 Homebrew no longer builds one, so `goat pwn` was dead on arrival until it
was ported. A port that nothing exercises rots silently: the next person edits
one file, or the tree is re-synced from upstream, and the failure comes back as
a runtime error on a machine with a device attached.

Nothing here needs a device. What it checks:

1. Every module imports under the interpreter goat itself runs on.
2. The entry points parse their arguments and exit cleanly with no device.
3. The pure payload builders still produce bytes -- checkm8 for the t8015 (A11,
   the platform this payload targets), plus the img3 and NOR paths whose
   bytes/str handling is the easiest thing to get wrong in a port.
4. libusb resolves, because the vendored bottles are x86_64 dylibs that an
   arm64 Python cannot load; the tree has to fall back to a native libusb.

Run: python3 tests/test_ipwndfu.py
"""

import os
import re
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IPWND = ROOT / "ipwndfu"

MODULES = [
    "alloc8", "checkm8", "device_platform", "dfu", "dfuexec", "image3",
    "image3_24Kpwn", "limera1n", "nor", "recovery", "SHAtter", "steaks4uce",
    "usbexec", "utilities", "libusbfinder",
]


def run_in_tree(code):
    """Run a snippet with ipwndfu/ as cwd and on sys.path, and return it."""
    return subprocess.run([sys.executable, "-c", code], cwd=IPWND,
                          capture_output=True, text=True)


class TreeImports(unittest.TestCase):
    def test_every_module_imports(self):
        code = ("import importlib\n"
                + "".join("importlib.import_module(%r)\n" % m for m in MODULES)
                + "print('ok')\n")
        result = run_in_tree(code)
        self.assertEqual(result.returncode, 0,
                         f"vendored module failed to import:\n{result.stderr}")

    def test_no_python2_only_constructs_remain(self):
        """The handful of py2-only spellings that 2to3 rewrites. If one
        reappears, the file is a fresh upstream sync that was not ported."""
        # print <stmt> without parens
        for path in sorted(IPWND.glob("*.py")) + [IPWND / "ipwndfu", IPWND / "ipwnrecovery"]:
            for number, line in enumerate(path.read_text().splitlines(), 1):
                self.assertIsNone(
                    re.match(r"\s*print\s+[^(=]", line),
                    f"{path.name}:{number} is a Python 2 print statement: {line.strip()}")
        for path in sorted((IPWND / "usb").rglob("*.py")):
            for number, line in enumerate(path.read_text().splitlines(), 1):
                self.assertIsNone(
                    re.match(r"\s*print\s+[^(=]", line),
                    f"usb/{path.name}:{number} is a Python 2 print statement: {line.strip()}")


class EntryPoints(unittest.TestCase):
    def test_ipwndfu_prints_usage(self):
        result = subprocess.run(["./ipwndfu"], cwd=IPWND,
                                capture_output=True, text=True)
        self.assertIn("USAGE", result.stdout)
        self.assertNotIn("SyntaxError", result.stderr)

    def test_ipwnrecovery_prints_usage(self):
        result = subprocess.run(["./ipwnrecovery"], cwd=IPWND,
                                capture_output=True, text=True)
        self.assertIn("USAGE", result.stdout)
        self.assertNotIn("SyntaxError", result.stderr)

    def test_shebangs_are_python3(self):
        for name in ("ipwndfu", "ipwnrecovery"):
            first = (IPWND / name).read_text().splitlines()[0]
            self.assertTrue(first.startswith("#!"), f"{name} has no shebang")
            self.assertNotIn("/usr/bin/python\n", first + "\n",
                             f"{name} still points at the Python 2 interpreter")
            self.assertIn("python3", first,
                          f"{name} shebang does not name a Python 3 interpreter")


class PayloadBuilders(unittest.TestCase):
    """The pure half of the exploit: bytes assembled before any device I/O.
    A py2/bytes mistake shows up here rather than on a phone."""

    def test_checkm8_payloads_build_for_every_target(self):
        code = ("import checkm8\n"
                "for cpid in (0x8947,0x8950,0x8955,0x8002,0x8004,0x8960,0x8010,0x8011,0x8015):\n"
                "    p = checkm8.payload(cpid)\n"
                "    assert isinstance(p, bytes) and len(p) > 0, cpid\n"
                "print('ok')\n")
        result = run_in_tree(code)
        self.assertEqual(result.returncode, 0,
                         f"checkm8.payload failed:\n{result.stdout}{result.stderr}")

    def test_branch_encoder_is_exact(self):
        """asm_arm64_branch computes a PC-relative offset. Python 2's `/` floored;
        Python 3's `/` returns a float, which would silently change the encoded
        branch. Decode the instruction back and require an exact match."""
        code = (
            "import struct, checkm8\n"
            "def decode(w, pc):\n"
            "    assert (w >> 26) & 0x3f == 0b000101, 'not a B instruction'\n"
            "    imm = w & 0x03ffffff\n"
            "    if imm & 0x02000000: imm -= 0x04000000\n"
            "    return pc + (imm << 2)\n"
            "for src, dest in ((0x180000000,0x180001000),(0x180000000,0x1801E8000),\n"
            "                    (0x180010000,0x180000000),(0x180001000,0x180000000),\n"
            "                    (0x180000000,0x18000000C)):\n"
            "    w, = struct.unpack('<I', checkm8.asm_arm64_branch(src, dest))\n"
            "    assert decode(w, src) == dest, (hex(src), hex(dest), hex(w))\n"
            "print('ok')\n")
        result = run_in_tree(code)
        self.assertEqual(result.returncode, 0,
                         f"branch encoding is wrong:\n{result.stdout}{result.stderr}")

    def test_img3_round_trips_and_excludes_cert_from_signed_size(self):
        """CERT and SHSH are excluded from signedSize. Under py3 a str literal
        in that membership test never matches a bytes tag, so the exclusion
        silently stops happening -- and the produced image is wrong rather than
        broken."""
        code = (
            "import image3\n"
            "cert, shsh = b'CERT'[::-1], b'SHSH'[::-1]\n"
            "tags = [(cert,12+64,64,b'\\xAA'*64),(shsh,12+32,32,b'\\xBB'*32),(b'BBBB',12+16,16,b'\\xCC'*16)]\n"
            "out = image3.Image3.createImage3FromTags(b'IH9S', tags)\n"
            "back = image3.Image3(out)\n"
            "assert back.dataSize == 12+64 + 12+32 + 12+16, back.dataSize\n"
            "assert back.signedSize == 12+16, back.signedSize\n"
            "print('ok')\n")
        result = run_in_tree(code)
        self.assertEqual(result.returncode, 0,
                         f"img3 CERT/SHSH handling changed:\n{result.stdout}{result.stderr}")

    def test_nor_parses_and_round_trips(self):
        code = (
            "import binascii, struct, nor\n"
            "img2 = bytearray(52)\n"
            "struct.pack_into('<4s4I', img2, 0, b'IMG2', 0x1000, 0, 8, 0x80)\n"
            "struct.pack_into('<I', img2, 48, binascii.crc32(bytes(img2[:48])) & 0xffffffff)\n"
            "d = nor.NorData(bytes(img2) + bytes(nor.NOR_SIZE - 52))\n"
            "assert all(isinstance(p, bytes) for p in d.parts)\n"
            "assert len(d.dump()) == nor.NOR_SIZE\n"
            "img = struct.pack('<4sI', b'Img3'[::-1], 64) + b'\\x11'*56\n"
            "d2 = nor.NorData(bytes(img2) + bytes(0x8000-52) + img + bytes(nor.NOR_SIZE-0x8000-64))\n"
            "assert len(d2.images) == 1, len(d2.images)\n"
            "print('ok')\n")
        result = run_in_tree(code)
        self.assertEqual(result.returncode, 0,
                         f"nor parse/round-trip failed:\n{result.stdout}{result.stderr}")

    def test_alloc8_filters_its_own_images(self):
        """remove_exploit drops every 'zero'-typed image it added. Compared as a
        str it never matches a bytes tag, so nothing is filtered and the caller's
        assert trips instead."""
        code = (
            "import binascii, struct, nor, alloc8\n"
            "img2 = bytearray(52)\n"
            "struct.pack_into('<4s4I', img2, 0, b'IMG2', 0x1000, 0, 8, 0x80)\n"
            "struct.pack_into('<I', img2, 48, binascii.crc32(bytes(img2[:48])) & 0xffffffff)\n"
            "d = nor.NorData(bytes(img2) + bytes(nor.NOR_SIZE - 52))\n"
            "new = alloc8.exploit(d, '359.3')\n"
            "assert len(new.images) > 700, len(new.images)\n"
            "kept = alloc8.remove_exploit(new).images\n"
            "assert len(kept) < 32, len(kept)\n"
            "print('ok')\n")
        result = run_in_tree(code)
        self.assertEqual(result.returncode, 0,
                         f"alloc8 image filter changed:\n{result.stdout}{result.stderr}")


class Libusb(unittest.TestCase):
    def test_a_loadable_libusb_resolves(self):
        """The vendored bottles are x86_64 dylibs for macOS 10.14 and older. An
        arm64 Python cannot load those, so the tree must find a native libusb
        instead or checkm8 refuses to run at all."""
        code = ("import libusbfinder\n"
                "p = libusbfinder.libusb1_path()\n"
                "assert p, 'no libusb-1.0 found'\n"
                "import ctypes; ctypes.CDLL(p)\n"
                "print('ok')\n")
        result = run_in_tree(code)
        self.assertEqual(result.returncode, 0,
                         f"libusb did not resolve:\n{result.stdout}{result.stderr}")

    def test_the_backend_actually_loads(self):
        code = ("import usb.backend.libusb1, libusbfinder\n"
                "b = usb.backend.libusb1.get_backend("
                "find_library=lambda x: libusbfinder.libusb1_path())\n"
                "assert b is not None, 'libusb1 backend unavailable'\n"
                "print('ok')\n")
        result = run_in_tree(code)
        self.assertEqual(result.returncode, 0,
                         f"libusb1 backend failed to load:\n{result.stdout}{result.stderr}")


class GoatUsesIt(unittest.TestCase):
    def test_pwn_does_not_look_for_python2(self):
        """goat/pwn.py used to hunt for a python2 binary and give up when it
        found none, which is every current machine."""
        pwn = (ROOT / "goat" / "pwn.py").read_text()
        self.assertNotIn("python2", pwn,
                         "goat/pwn.py still expects a Python 2 interpreter")
        self.assertIn("sys.executable", pwn,
                      "goat/pwn.py should run the tree with goat's own interpreter")


if __name__ == "__main__":
    unittest.main(verbosity=2)