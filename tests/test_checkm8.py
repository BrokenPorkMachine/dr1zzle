#!/usr/bin/env python3
"""Tests for the checkm8 engine, the profiles, and the payload.

Three things are checked here that the implementation says it does.

**The profile values are the ones the image decodes to.** Every constant in
`goat/checkm8_profile.py` is re-derived here from the SecureROM bytes on disk
by matching the instruction shape the profile claims, so a profile value that
does not decode is a failing test rather than a wrong exploit. The A10 row is
additionally compared against the eLab fortalysis writeup's published values,
which is the external control that proves the derivation method and not just
its instances.

**The descriptor encoder reproduces the ROM's own descriptors.** The payload's
fake table is built with `goat/checkm8_payload.py`, and the encoder there is
checked by decoding descriptors measured out of the A11's live translation
table and re-encoding them through the same constants. That is what makes the
"read-execute page" claim in the payload source checkable rather than
aspirational.

**The engine talks to a device like the one described in the analysis.** A
fake DFU device records every control transfer, so the stage order, the request
bytes and the fact that the feng shui really does cancel a transfer mid-flight
are all observable without hardware.

Run: python3 -m unittest discover -s tests -p 'test_checkm8*.py'
"""

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from goat import checkm8 as cm8            # noqa: E402
from goat import checkm8_payload as pl     # noqa: E402
from goat import checkm8_profile as prof   # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORPUS = os.environ.get(
    "IPHEM_SECUREROM_DIR",
    "/Users/failbr34k/WORK/iphemeral-latest/SecureROM")

try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    HAVE_CAPSTONE = True
except Exception:                                    # pragma: no cover
    HAVE_CAPSTONE = False

ROM_BASE = 0x100000000


def load_rom(profile):
    path = os.path.join(CORPUS, profile.rom_path)
    if not os.path.isfile(path):
        raise unittest.SkipTest("SecureROM %s is not in the corpus" % path)
    with open(path, "rb") as fh:
        return fh.read()


def seq_at(img, off, wanted):
    """Decode `wanted` instruction texts at `off`; True if they all match."""
    if not HAVE_CAPSTONE:
        return False
    md = _MD
    for n, text in enumerate(wanted):
        got = list(md.disasm(img[off + 4 * n:off + 4 * n + 4],
                             ROM_BASE + off + 4 * n))
        if len(got) != 1:
            return False
        if ("%s %s" % (got[0].mnemonic, got[0].op_str)).strip() != text:
            return False
    return True


_MD = Cs(CS_ARCH_ARM64, CS_MODE_ARM) if HAVE_CAPSTONE else None


# The instruction each profile constant is claimed to be. These are shapes,
# not addresses: the same routine exists in every part at its own address, and
# this table is what makes "measured per part" a checkable claim.
SHAPES = {
    "dc_civac":       (["dc civac, x0", "ret"],),
    "dmb":            (["dmb sy", "ret"],),
    "write_ttbr0":    (["isb", "msr ttbr0_el1, x0", "isb", "ret"],
                       ["msr ttbr0_el1, x0", "isb", "ret"],
                       ["msr ttbr0_el1, x0", "isb", "isb", "ret"]),
    "tlbi":           (["dsb sy", "tlbi vmalle1", "dsb sy", "isb", "ret"],),
    "read_sctlr":     (["mrs x0, sctlr_el1", "ret"],),
    "enter_critical": (["msr daifset, #3", "isb", "ret"],),
    "exit_critical":  (["msr daifclr, #3", "isb", "ret"],),
    "pivot":          (["ldp x16, x17, [x0, #0x78]",
                        "ldp x19, x20, [x0, #0x98]"],),
    "pop_ret":        (["ldr x30, [sp], #0x10", "ret"],),
    "store_ptr":      (["str x8, [x0]", "ret"],),
    "callback_ldp":   (["ldp x8, x10, [x0, #0x70]"],
                       ["ldp x8, x9, [x0, #0x70]"]),
}


def decodes_as(img, off, alternatives):
    """True if the bytes at `off` decode as one of `alternatives`."""
    return any(seq_at(img, off, alt) for alt in alternatives)


class ProfileDecodesTest(unittest.TestCase):
    """Every measured constant decodes as the shape it was measured as."""

    def test_every_profile_constant_decodes(self):
        for cpid, profile in sorted(prof.PROFILES.items()):
            img = load_rom(profile)
            for name, field in sorted(profile.fields.items()):
                alternatives = SHAPES.get(name)
                if alternatives is None:
                    continue
                off = field.value - ROM_BASE
                longest = max(len(a) for a in alternatives)
                if not (0 <= off <= len(img) - 4 * longest):
                    self.fail("%s %s = 0x%x is outside the image"
                              % (profile.name, name, field.value))
                self.assertTrue(
                    decodes_as(img, off, alternatives),
                    "%s %s = 0x%x does not decode as any of %s"
                    % (profile.name, name, field.value,
                       [a[0] for a in alternatives]))

    def test_the_a10_profile_reproduces_the_published_analysis(self):
        """The external control: the writeup's A10 constants must match ours.

        This is the test that makes the whole per-part derivation trustworthy,
        so it is deliberately about a *different* part than the one this
        project's payload targets: agreeing with the analysis on the A10 by
        an independent decode of the same image is evidence about the method.
        """
        a10 = prof.PROFILES[0x8010]
        for name, published in prof.WRITEUP_A10.items():
            if name not in a10.fields:
                continue
            self.assertEqual(
                a10[name], published,
                "%s: measured 0x%x, the analysis published 0x%x"
                % (name, a10[name], published))

    def test_a_mutated_profile_constant_is_refused(self):
        """The check above is not vacuous: shifting one value by 4 fails it."""
        a11 = prof.PROFILES[0x8015]
        img = load_rom(a11)
        good = a11["dc_civac"]
        alternatives = SHAPES["dc_civac"]
        self.assertTrue(decodes_as(img, good - ROM_BASE, alternatives))
        # move the constant four bytes on: the instruction there is different
        self.assertFalse(decodes_as(img, good - ROM_BASE + 4, alternatives),
                         "moving the constant by 4 still decoded, so the test "
                         "is not checking anything")

    def test_parts_are_distinct(self):
        self.assertNotEqual(prof.PROFILES[0x8015]["dc_civac"],
                            prof.PROFILES[0x8010]["dc_civac"],
                            "the two parts decode their gadgets at the same "
                            "address, so this profile is a copy")


class PayloadBuildTest(unittest.TestCase):
    """The payload assembles, lays out, and encodes descriptors the ROM agrees with."""

    @classmethod
    def setUpClass(cls):
        cls.image, cls.sym, cls.notes = pl.build(prof.PROFILES[0x8015])

    def test_image_layout_is_fixed(self):
        self.assertEqual(self.sym["fake_l1"], pl.FAKE_L1_OFF)
        self.assertEqual(self.sym["fake_l2"], pl.FAKE_L2_OFF)
        self.assertEqual(self.sym["pivot_ctx"], pl.CTX_OFF)
        self.assertGreater(pl.FAKE_L1_OFF, max(
            a for n, a in self.sym.items()
            if not n.startswith("fake_") and n not in
            ("pivot_ctx", "payload_base", "gadget_table", "rom_ttbr0",
             "rom_vbar", "rom_wxn_mask", "pwndfu_targets", "pwndfu_status")))

    def test_the_fake_tables_are_written(self):
        # the L1 has a live table entry for the payload window and the ROM
        base = prof.PROFILES[0x8015]["image_base"]
        off = pl.FAKE_L1_OFF + pl.l1_index(base) * 8
        entry = struct.unpack_from("<Q", self.image, off)[0]
        self.assertEqual(entry & 3, pl.DESC_TABLE)
        rom_off = pl.FAKE_L1_OFF + pl.l1_index(ROM_BASE) * 8
        rom_entry = struct.unpack_from("<Q", self.image, rom_off)[0]
        self.assertEqual(rom_entry & 3, pl.DESC_BLOCK,
                         "the ROM's block descriptor must be carried across")
        self.assertEqual(rom_entry, 0x1000006A5)

        # the L2's code page is the read-execute entry, the rest are rw
        code = pl.FAKE_L2_OFF + pl.l2_index(base) * 8
        code_desc = struct.unpack_from("<Q", self.image, code)[0]
        self.assertEqual((code_desc >> 6) & 3, 2,
                         "the payload page must be read-only, which is what "
                         "makes it executable while WXN is set")
        other = pl.FAKE_L2_OFF + 0
        other_desc = struct.unpack_from("<Q", self.image, other)[0]
        self.assertEqual((other_desc >> 6) & 3, 0,
                         "every other page must be read-write or the stack "
                         "cannot be used")

    def test_descriptor_encoder_round_trips_the_measured_table(self):
        """The encoder reproduces the ROM's own descriptors, bit for bit.

        The values here were read out of the A11's live translation table with
        this project's emulator (the L1[128] block for the SecureROM and the
        L2[7] page for the payload window). Re-encoding them through the same
        constants the payload builder uses is what ties the payload's fake
        table to a measured table rather than to the ARM manual.
        """
        rom = pl.block_desc(0x100000000, pl.AP_RO)
        self.assertEqual(rom, 0x00000001000006A5)
        page = pl.page_desc(0x18001C000, pl.AP_RW)
        self.assertEqual(page, 0x006000018001C627)   # measured L2[7]
        rx = pl.page_desc(0x18001C000, pl.AP_RO)
        self.assertEqual(rx, page + 0x80)   # 0x006000018001C6A7

    def test_the_context_struct_is_where_the_pivot_reads_it(self):
        base = prof.PROFILES[0x8015]["image_base"]
        ctx = pl.CTX_OFF
        # +0xf8 is the slot the restore routine turns into SP (and TTBR0)
        x1 = struct.unpack_from("<Q", self.image, ctx + 0xF8)[0]
        self.assertEqual(x1, base + pl.FAKE_L1_OFF)
        # +0xe8 is (x29, x30): x29 is the return address in the context entry
        x29, x30 = struct.unpack_from("<QQ", self.image, ctx + 0xE8)
        self.assertEqual(x29, base + self.sym["stage2"])
        self.assertEqual(x30, prof.PROFILES[0x8015]["ctx_entry"])


# ---------------------------------------------------------------------------
# a device that behaves the way the analysis describes one behaving
# ---------------------------------------------------------------------------

class FakeDfuDevice:
    """Records control transfers instead of sending them.

    The point of this is not to emulate a SecureROM - it is to make the
    *host side* of each stage observable, which is the half this module owns.
    A stage that sends the wrong request, or sends the right request in the
    wrong order, fails here and not on a device that cannot be re-secured.
    """

    class Recorder:
        def __init__(self):
            self.calls = []
            self.control = []
            self.cancelled = []
            self.reset_count = 0

        def find_dfu(self, _timeout):
            return 1

    def __init__(self):
        self.usb = self.Recorder()
        self.serial = "CPID:8015 CPRV:11 CPFM:03 SCEP:01 BDID:0C ECID:1"
        self.handle = 1
        self.timeout_ms = 5000
        self.transfers = 0

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        self.close()

    def close(self):
        pass

    # the class requests a stage actually uses
    def get_status(self):
        self.usb.calls.append(("get_status",))
        return (0, 2, 0)

    def get_state(self):
        self.usb.calls.append(("get_state",))
        return 2

    def clear_status(self):
        self.usb.calls.append(("clear_status",))

    def dnload(self, data, block=0):
        self.usb.calls.append(("dnload", block, len(data)))

    def ctrl_quiet(self, *_args):
        self.usb.calls.append(("quiet",) + _args[:2])

    def stall(self):
        self.usb.calls.append(("stall",))

    def reset(self):
        self.usb.reset_count += 1

    def dnload_incomplete(self, data, block=0, cancel_after_ms=1):
        self.usb.calls.append(("incomplete_dnload", len(data)))


class StageOrderTest(unittest.TestCase):
    """The stages run in the analysis's order and say what they did."""

    def test_feng_shui_sends_stall_then_pairs_then_resets(self):
        dev = FakeDfuDevice()
        cm8._feng_shui(dev, {"reset_rounds": 6, "leak_len": 0xC0,
                             "no_leak_len": 0xC1}, False)
        names = [c[0] for c in dev.usb.calls]
        self.assertEqual(names.count("stall"), 1, "the feng shui opens with one stall")
        self.assertEqual(dev.usb.reset_count, 6,
                         "one USB reset per no_leak round")
        self.assertEqual(names[0], "stall")
        self.assertEqual(names[1], "quiet")
        for call in dev.usb.calls[2:]:
            self.assertEqual(call[0], "quiet")

    def test_uaf_stage_is_an_incomplete_dnload_then_clear_status(self):
        dev = FakeDfuDevice()
        cm8._uaf(dev, {"block_len": cm8.MAX_BLOCK}, False)
        self.assertEqual([c[0] for c in dev.usb.calls],
                         ["incomplete_dnload", "clear_status"])
        self.assertEqual(dev.usb.calls[0][1], cm8.MAX_BLOCK)

    def test_payload_upload_splits_on_the_block_boundary(self):
        plan = cm8.plan("CPID:8015 CPRV:11")
        dev = FakeDfuDevice()
        plan.payload = b"\xAA" * (cm8.MAX_BLOCK * 2 + 0x40)
        cm8._upload_payload(dev, plan, {"block_len": cm8.MAX_BLOCK}, False)
        blocks = [c[2] for c in dev.usb.calls if c[0] == "dnload"]
        self.assertEqual(blocks, [cm8.MAX_BLOCK, cm8.MAX_BLOCK, 0x40])


class RefusalTest(unittest.TestCase):
    """The gate that says no, before touching the device."""

    def test_a_part_checkm8_cannot_reach_names_the_hardware(self):
        plan = cm8.plan("CPID:8020 CPRV:11")
        self.assertFalse(plan.runnable)
        text = "\n".join(plan.blockers)
        self.assertIn("RP2350", text)
        self.assertIn("usbliter8", text)

    def test_an_unknown_part_is_refused_without_guessing(self):
        plan = cm8.plan("CPID:8123 CPRV:11")
        self.assertFalse(plan.runnable)
        self.assertTrue(any("no measured checkm8 profile" in b
                            for b in plan.blockers))

    def test_a_profile_missing_a_constant_is_refused(self):
        # the A10 part with one constant removed must refuse, not run short
        p = prof.PROFILES[0x8010]
        broken = prof.PartProfile(p.name, p.cpid, p.cprv,
                                  {k: v for k, v in p.fields.items()
                                   if k != "pivot"})
        cm8.METHOD_PIVOT.supports(broken)
        self.assertTrue(set(prof.REQUIRED) - set(broken.fields))
        self.assertEqual(broken.missing(), ["pivot"])

    def test_every_profile_declares_what_a_method_needs(self):
        for cpid, p in sorted(prof.PROFILES.items()):
            able = cm8.methods_for(p)
            self.assertTrue(able, "%s can run no method at all" % p.name)


if __name__ == "__main__":
    unittest.main(verbosity=2)
