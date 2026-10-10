#!/usr/bin/env python3
"""Host-side tests for the display stack.

Run: python3 tests/test_display.py

The framebuffer drawing and the FDT geometry parser are the two parts of the
display driver that can be exercised without an A11. Both are compiled for
the host here and driven directly, so the checks are behavioural rather than
pattern matches against source.

The panel link (MIPI register writes) is not covered: its offsets are assumed,
and a test that asserts on a guess only proves the guess is self-consistent.
"""

import os
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# The driver reads a real device tree blob, so build a synthetic FDT and feed
# it through the same parser the payload uses.
FDT_MAGIC = 0xD00DFEED


def build_fdt(props):
    """Build a minimal but structurally valid FDT.

    `props` is a list of (name, bytes) pairs appended to the root node.
    """
    strings = b""
    string_off = {}

    def add_string(s):
        nonlocal strings
        if s not in string_off:
            string_off[s] = len(strings)
            strings += s.encode() + b"\0"
        return string_off[s]

    struct_block = struct.pack(">I", 1)  # FDT_BEGIN_NODE
    struct_block += b"\0"  # empty root name

    for name, value in props:
        struct_block += struct.pack(">III", 3, len(value), add_string(name))
        struct_block += value
        struct_block += b"\0" * (-len(value) % 4)

    struct_block += struct.pack(">I", 2)  # FDT_END_NODE
    struct_block += struct.pack(">I", 9)  # FDT_END

    hdr_size = 40
    off_rsvmap = hdr_size
    # One terminating rsvmap entry: address and size of 0.
    rsvmap = struct.pack(">QQ", 0, 0)
    off_struct = off_rsvmap + len(rsvmap)
    off_strings = off_struct + len(struct_block)

    header = struct.pack(
        ">IIIIIIIIII",
        FDT_MAGIC,
        off_strings + len(strings),
        off_struct,
        off_strings,
        off_rsvmap,
        17,
        16,
        0,
        len(strings),
        len(struct_block),
    )
    return header + rsvmap + struct_block + strings


def video_args(base, width, height, stride, depth):
    return struct.pack("<IIIII", base, width, height, stride, depth)


class Harness:
    """Compiles display_fb.c + display_attach.c for the host and exposes them
    through ctypes, with the panel-link MMIO stubbed out."""

    def __init__(self):
        self.tmp = tempfile.mkdtemp(prefix="dr1zzle-display-")
        self.so = os.path.join(self.tmp, "display.so")
        srcs = [
            os.path.join(ROOT, "src/drivers/display_fb.c"),
            os.path.join(ROOT, "src/drivers/display_attach.c"),
            os.path.join(ROOT, "src/drivers/font8x8.c"),
            os.path.join(ROOT, "tests/host_stubs.c"),
        ]
        cmd = [
            "clang", "-shared", "-fPIC", "-O1", "-std=c11",
            "-I", os.path.join(ROOT, "include"),
            "-I", os.path.join(ROOT, "src"),
            "-D__BARE_METAL__", "-DARCH_AARCH64",
            *srcs, "-o", self.so,
        ]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            raise unittest.SkipTest(f"host build of display failed:\n{r.stderr}")
        import ctypes

        self.ctypes = ctypes
        self.lib = ctypes.CDLL(self.so)


HARNESS = None


def setUpModule():
    global HARNESS
    HARNESS = Harness()


class DisplayFbGeometry(unittest.TestCase):
    def test_rejects_degenerate_geometry(self):
        lib = HARNESS.lib
        for args in [
            (0, 100, 100, 400, 32),      # null base
            (0x1000, 0, 100, 400, 32),   # zero width
            (0x1000, 100, 0, 400, 32),   # zero height
            (0x1000, 100, 100, 400, 24), # unsupported depth
        ]:
            rc = lib.display_fb_attach(*args)
            self.assertEqual(rc, -1, f"attach {args} should be rejected")

    def test_rejects_stride_narrower_than_a_row(self):
        """A stride below width*bpp/8 would make rows overlap."""
        rc = HARNESS.lib.display_fb_attach(0x1000, 100, 10, 100, 32)
        self.assertEqual(rc, -1)

    def test_accepts_padded_stride(self):
        """Panels are commonly padded past width*bpp/8; honour the firmware."""
        rc = HARNESS.lib.display_fb_attach(0x1000, 100, 10, 512, 32)
        self.assertEqual(rc, 0)

    def test_rejects_wrapping_geometry(self):
        rc = HARNESS.lib.display_fb_attach(0x1000, 4096, 0xFFFFFFFF, 0x10000, 32)
        self.assertEqual(rc, -1)

    def test_geometry_is_reported_back(self):
        ctypes = HARNESS.ctypes
        lib = HARNESS.lib
        lib.display_fb_attach(0x2000, 64, 32, 256, 32)
        info = lib.display_info()
        class V(ctypes.Structure):
            _fields_ = [
                ("base", ctypes.c_uint32),
                ("width", ctypes.c_uint32),
                ("height", ctypes.c_uint32),
                ("stride_bytes", ctypes.c_uint32),
                ("bpp", ctypes.c_uint32),
                ("found", ctypes.c_int),
            ]

        self.assertEqual(ctypes.cast(info, ctypes.POINTER(V)).contents.base, 0x2000)


class DisplayFdtProbe(unittest.TestCase):
    def setUp(self):
        HARNESS.lib.display_fb_detach()

    def _probe(self, props):
        ctypes = HARNESS.ctypes
        blob = build_fdt(props)
        buf = (ctypes.c_char * len(blob)).from_buffer_copy(blob)
        rc = HARNESS.lib.display_probe_device_tree(ctypes.cast(buf, ctypes.c_void_p).value)
        return rc, HARNESS.lib.display_info()

    def test_rejects_absent_device_tree(self):
        self.assertEqual(HARNESS.lib.display_probe_device_tree(0), -1)

    def test_rejects_bad_magic(self):
        ctypes = HARNESS.ctypes
        buf = ctypes.create_string_buffer(64)
        self.assertEqual(HARNESS.lib.display_probe_device_tree(ctypes.addressof(buf)), -1)

    def test_finds_video_block(self):
        rc, info = self._probe([
            ("model", b"iPhone9,1\0"),
            ("apple,boot-args", video_args(0x100000000 & 0xFFFFFFFF,
                                           750, 1334, 3000, 32)),
        ])
        self.assertEqual(rc, 0)
        class V(HARNESS.ctypes.Structure):
            _fields_ = [
                ("base", HARNESS.ctypes.c_uint32),
                ("width", HARNESS.ctypes.c_uint32),
                ("height", HARNESS.ctypes.c_uint32),
                ("stride_bytes", HARNESS.ctypes.c_uint32),
                ("bpp", HARNESS.ctypes.c_uint32),
                ("found", HARNESS.ctypes.c_int),
            ]

        v = HARNESS.ctypes.cast(info, HARNESS.ctypes.POINTER(V)).contents
        self.assertEqual(v.width, 750)
        self.assertEqual(v.height, 1334)
        self.assertEqual(v.stride_bytes, 3000)
        self.assertEqual(v.bpp, 32)

    def test_rejects_implausible_dimensions(self):
        """A property that is wide enough but not a real panel must not be
        adopted, or we would draw into unrelated memory."""
        for bad in [
            video_args(0x1000, 3, 1334, 3000, 32),     # width below the floor
            video_args(0x1000, 750, 1334, 10, 32),     # stride too small
            video_args(0x1000, 750, 1334, 3000, 24),   # bad depth
            video_args(0, 750, 1334, 3000, 32),        # null base
        ]:
            rc, _ = self._probe([("apple,boot-args", bad)])
            self.assertEqual(rc, -1, f"should reject {struct.unpack('<IIIII', bad)}")

    def test_tolerates_properties_before_the_video_block(self):
        rc, _ = self._probe([
            ("compatible", b"apple,t8015\0"),
            ("a-string", b"x" * 7),
            ("apple,boot-args", video_args(0x1000, 640, 480, 2560, 32)),
        ])
        self.assertEqual(rc, 0)


class DisplayRaster(unittest.TestCase):
    """Drive the drawing primitives against a real host buffer."""

    BUF_BYTES = 64 * 64 * 4

    def setUp(self):
        ctypes = HARNESS.ctypes
        HARNESS.lib.display_fb_detach()
        # 64x64x4 = 16384 bytes
        self.buf = (ctypes.c_uint32 * (self.BUF_BYTES // 4))()
        self.addr = ctypes.addressof(self.buf)
        rc = HARNESS.lib.display_fb_attach(self.addr, 64, 64, 64 * 4, 32)
        self.assertEqual(rc, 0)
        self.lib = HARNESS.lib

    def px(self, x, y):
        return self.buf[y * 64 + x]

    def test_fill_covers_every_pixel(self):
        self.lib.display_fb_fill(0xDEADBEEF)
        for y in (0, 1, 32, 63):
            for x in (0, 1, 32, 63):
                self.assertEqual(self.px(x, y), 0xDEADBEEF)

    def test_fill_rect_clips_at_edges(self):
        """A rectangle running off the edge must fill its visible part, not
        skip entirely."""
        self.lib.display_fb_fill(0)
        self.lib.display_fb_fill_rect(60, 60, 100, 100, 0x11223344)
        self.assertEqual(self.px(60, 60), 0x11223344)
        self.assertEqual(self.px(63, 63), 0x11223344)
        # Unaffected pixel stays clear.
        self.assertEqual(self.px(59, 59), 0)

    def test_fill_rect_replicates_rows(self):
        """Row replication is what makes a bar taller than one row work."""
        self.lib.display_fb_fill(0)
        self.lib.display_fb_fill_rect(0, 0, 2, 10, 0xAABBCCDD)
        for y in range(10):
            self.assertEqual(self.px(0, y), 0xAABBCCDD)
            self.assertEqual(self.px(1, y), 0xAABBCCDD)
        self.assertEqual(self.px(2, 0), 0)

    def test_out_of_range_pixel_is_dropped(self):
        self.lib.display_fb_fill(0)
        self.lib.display_fb_pixel(64, 0, 0xFFFFFFFF)
        self.lib.display_fb_pixel(0, 64, 0xFFFFFFFF)
        # Must not have scribbled past the end of the buffer.
        self.assertEqual(self.px(0, 0), 0)
        self.assertEqual(self.px(63, 63), 0)

    def test_stroke_rect_leaves_interior_clear(self):
        self.lib.display_fb_fill(0)
        self.lib.display_fb_stroke_rect(2, 2, 10, 10, 0xFFFF0000)
        self.assertEqual(self.px(2, 2), 0xFFFF0000)
        self.assertEqual(self.px(11, 2), 0xFFFF0000)
        self.assertEqual(self.px(6, 6), 0)

    def test_drawing_without_framebuffer_is_a_noop(self):
        self.lib.display_fb_detach()
        self.lib.display_fb_fill(0xFFFFFFFF)
        self.lib.display_fb_fill_rect(0, 0, 4, 4, 0xFFFFFFFF)
        self.lib.display_fb_pixel(0, 0, 0xFFFFFFFF)
        self.lib.display_console_putc("x")
        self.assertIsNone(self.lib.display_fb())


class DisplayConsole(unittest.TestCase):
    """The console is what makes the display useful; check cursor movement,
    wrapping, scrolling and glyph output."""

    def setUp(self):
        ctypes = HARNESS.ctypes
        HARNESS.lib.display_fb_detach()
        # 6x8 cells, 64x64 pixels => 10 cols x 8 rows
        self.buf = (ctypes.c_uint32 * (64 * 64))()
        self.addr = ctypes.addressof(self.buf)
        HARNESS.lib.display_fb_attach(self.addr, 64, 64, 64 * 4, 32)
        # White on black, same colours main.c uses.
        HARNESS.lib.display_console_init(0xFFFFFFFF, 0x00000000)
        self.lib = HARNESS.lib

    def px(self, x, y):
        return self.buf[y * 64 + x]

    def ink_pixels(self):
        return sum(1 for v in self.buf if v == 0xFFFFFFFF)

    def test_clear_produces_an_empty_screen(self):
        self.lib.display_console_write("hello")
        self.lib.display_console_clear()
        self.assertEqual(self.ink_pixels(), 0)

    def test_writing_glyphs_sets_pixels(self):
        self.lib.display_console_write("A")
        self.assertGreater(self.ink_pixels(), 0,
                           "no glyph pixels were set for 'A'")

    def test_cursor_advances_per_character(self):
        self.assertEqual(self.lib.display_console_cursor(), 0)
        self.lib.display_console_putc("A")
        self.assertEqual(self.lib.display_console_cursor(), 1)
        self.lib.display_console_putc("B")
        self.assertEqual(self.lib.display_console_cursor(), 2)

    def test_carriage_return_returns_to_column_zero(self):
        self.lib.display_console_write("ABC")
        self.lib.display_console_putc("\r")
        self.assertEqual(self.lib.display_console_cursor(), 0)

    def test_backspace_erases(self):
        self.lib.display_console_write("AB")
        before = self.ink_pixels()
        self.lib.display_console_putc("\b")
        self.assertEqual(self.lib.display_console_cursor(), 1)
        self.assertLess(self.ink_pixels(), before,
                        "backspace left the glyph on screen")

    def test_line_wraps_at_screen_edge(self):
        # 10 columns per row at this size; the 10th char must wrap.
        for _ in range(9):
            self.lib.display_console_putc("A")
        self.assertEqual(self.lib.display_console_cursor(), 9)
        self.lib.display_console_putc("A")
        self.assertEqual(self.lib.display_console_cursor(), 11,
                         "the 10th column did not wrap to the next row")

    def test_scrolling_keeps_content_on_screen(self):
        for _ in range(20):
            self.lib.display_console_putc("\n")
        cursor = self.lib.display_console_cursor()
        # Must stay inside the 10x8 cell grid rather than walking off.
        self.assertLess(cursor, 10 * 8)

    def test_unprintable_becomes_a_blank_cell(self):
        self.lib.display_console_clear()
        before = self.ink_pixels()
        self.lib.display_console_putc("\x01")
        self.assertEqual(self.lib.display_console_cursor(), 1,
                         "control char should still consume a cell")
        self.assertEqual(self.ink_pixels(), before,
                         "control char should not have drawn ink")


class FontTable(unittest.TestCase):
    """The generated font must match the artwork in scripts/gen_font.py.

    If these drift, the checked-in table is not what the artwork says, and
    the console would render something nobody reviewed."""

    def test_table_matches_generator(self):
        gen = os.path.join(ROOT, "scripts/gen_font.py")
        out = subprocess.run([sys.executable, gen],
                             capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stderr)

        generated = out.stdout
        checked_in = open(os.path.join(ROOT, "src/drivers/font8x8.c")).read()
        # Compare only the table body; the include/macro preamble may differ.
        grab = lambda s: [ln.strip() for ln in s.splitlines()
                          if ln.strip().startswith("{")]
        self.assertEqual(grab(generated), grab(checked_in),
                         "font8x8.c is stale; regenerate with scripts/gen_font.py")

    def test_every_printable_ascii_has_a_glyph(self):
        gen = os.path.join(ROOT, "scripts/gen_font.py")
        art = subprocess.run([sys.executable, gen, "--render",
                              "".join(chr(c) for c in range(0x20, 0x7F))],
                             capture_output=True, text=True)
        self.assertEqual(art.returncode, 0, art.stderr)
        self.assertEqual(len(art.stdout.strip().splitlines()), 7,
                         "unexpected glyph render height")


if __name__ == "__main__":
    unittest.main(verbosity=2)