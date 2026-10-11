#!/usr/bin/env python3
import os
import sys
import tempfile
import unittest
from types import SimpleNamespace

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from goat import rp2350  # noqa: E402


class UsbR34KerBundleTest(unittest.TestCase):
    def test_all_bundled_images_have_valid_uf2_framing(self):
        for board in rp2350.BOARDS:
            path = rp2350.firmware_path(board)
            self.assertGreater(rp2350.validate_uf2(path), 0)

    def test_flash_copies_the_selected_image_verbatim(self):
        board = "pico2"
        source = rp2350.firmware_path(board)
        with tempfile.TemporaryDirectory() as mount:
            args = SimpleNamespace(board=board, firmware_dir=None,
                                   mount=mount, wait=0)
            self.assertEqual(rp2350.cmd_flash(args), 0)
            target = os.path.join(mount, os.path.basename(source))
            with open(source, "rb") as left, open(target, "rb") as right:
                self.assertEqual(left.read(), right.read())

    def test_bad_uf2_is_rejected(self):
        with tempfile.NamedTemporaryFile() as bad:
            bad.write(b"not a uf2")
            bad.flush()
            with self.assertRaises(ValueError):
                rp2350.validate_uf2(bad.name)


if __name__ == "__main__":
    unittest.main()
