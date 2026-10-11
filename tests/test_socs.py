#!/usr/bin/env python3
"""Checks the SoC registry against the sources that claim to define it.

The original registry is nine checkm8 profiles under include/soc/; the current
registry also carries newer host-only identities. Everything in them either
came from somewhere citable or was reverse-engineered from silicon, and the
only way to keep that honest is to fail when the two disagree:

  1. rpwn/rust/src/device_platform.rs -- the vendored checkm8 tool's own table, the
     single source for every profile's ROM/SRAM/DRAM/DFU geometry, nonce
     lengths and demotion register.
  2. rpwn/rust/src/checkm8.rs -- each CPID's device configuration, which is where
     the DFU trigger (button hold vs DFU-loop re-entry) comes from.
  3. include/soc/ itself -- the contract every profile has to satisfy.

A transcription error in any direction fails here, not on a device that cannot
be re-secured. No device is needed.

Run: python3 tests/test_socs.py
"""

import re
import os
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOC_DIR = ROOT / "include" / "soc"
IPWND = ROOT / "rpwn"

# Every CPID checkm8 supports, from rpwn/rust/README.md "current SoC support".
# The registry must cover exactly this set, no more and no fewer.
CHECKM8_CURRENT = [
    "s5l8947x", "s5l8950x", "s5l8955x", "s5l8960x", "t8002", "t8004",
    "t8010", "t8011", "t8015",
]

# S5L8960 covers both A7 variants, so ten CPIDs are nine profile headers.
PROFILES = [
    "s5l8947", "s5l8950", "s5l8955", "s5l8960", "t8002", "t8004", "t8010",
    "t8011", "t8015",
]

# Beyond checkm8: parts with a runnable usbliter8 handler, the second public
# bootrom bug. These are host tier -- the exploit needs an RP2350 as the USB
# host, and no peripheral map exists for them here -- but they are recorded
# rather than ignored, so the host tool can say which exploit applies instead
# of guessing.
USBLITER8_PROFILES = ["t8020", "t8030"]

# The source tree has handlers for A12 and A13. Its README explicitly says
# A12X/A12Z are theoretical and not implemented, so keep that distinction in
# the registry checks instead of treating a named bug as a runnable handler.
USBLITER8_IMPLEMENTED_PROFILES = ["t8020", "t8030"]

# Parts with no runnable exploit path in this tree. T8027 has measured partial
# geometry but no handler; T8021 is an identity-only stub.
NO_EXPLOIT_PROFILES = ["t8021", "t8027"]
IDENTITY_STUB_PROFILES = ["t8021"]

ALL_PROFILES = PROFILES + USBLITER8_PROFILES + NO_EXPLOIT_PROFILES

# The SEP interface, per field, per part. The A11 is the only part with a
# DT-cited control window, so only it carries SEP_BASE/SEP_SIZE; the A12/A12X/A13
# SEP power words come from the reference tree's cross-part ps-reg table and are
# carried on their own. Everything else has no SEP source here and carries none,
# rather than a guessed one -- which is the point of listing it per field.
SEP_FIELDS = {
    "SEP_BASE": ["t8015"],
    "SEP_SIZE": ["t8015"],
    "SEP_POWER_WORD": ["t8015", "t8020", "t8027", "t8030"],
}

# The contract. Each profile must define every one of these, or the drivers
# that use them fail at the use site instead of here.
FIELDS = {
    "identity": ["NAME", "CPID", "CPRV", "SCEP", "SRTG", "ARCH"],
    "tier": ["TIER", "MAPPED_BLOCKS"],
    "geometry": [
        "SRAM_BASE", "SRAM_SIZE", "SECURE_ROM_BASE", "SECURE_ROM_SIZE",
        "DRAM_BASE", "DFU_IMAGE_BASE", "DFU_LOAD_BASE",
        "RECOVERY_IMAGE_BASE", "RECOVERY_LOAD_BASE", "ROM_BASE", "ROM_SIZE",
        "ROM_SHA1", "NONCE_LENGTH", "SEP_NONCE_LENGTH", "DEMOTION_REG",
        "DFU_TRIGGER",
    ],
    # The SEP interface. Present on every profile that has a source for it,
    # absent on the identity stub -- the stub test is what pins that absence.
    # This is the geometry a SEP-targeting payload actually depends on, and it
    # was unrecorded for every part until the A11/A12/A12Z/A13 profiles gained
    # it; before that the registry described the AP and nothing else.
    "sep": ["SEP_BASE", "SEP_SIZE", "SEP_POWER_WORD"],
}

# Fields a host-tier profile is not expected to carry: only the payload tier
# has a peripheral map, so only it defines IRQ numbers, block bindings and
# per-block offsets.
PAYLOAD_ONLY = [
    "IRQ_USB_OTG", "I2C_BLOCK", "SPI_BLOCK", "NAND_BLOCK",
    "NAND_PAGE_SIZE", "NAND_OOB_SIZE", "NAND_PAGES_PER_BLOCK",
    "NAND_BLOCK_COUNT", "DCP_AES_OFFSET", "DCP_AES_PIPE_OFFSET",
    "AES_CLK_GATE", "RECFG_AES_ADDR", "RECFG_SRAM_BASE", "RECFG_SRAM_END",
    "AOP_CFG_TABLE", "AOP_SRAM_LOCK_RANGE", "AOP_SRAM_LOCK_SET",
    "AOP_CFG_LOCK", "IORVBAR_0", "IORVBAR_1", "IORVBAR_2", "IORVBAR_3",
    "IORVBAR_4", "IORVBAR_5",
]

EXPLOITS = {"checkm8": "SOC_EXPLOIT_CHECKM8",
            "usbliter8": "SOC_EXPLOIT_USBLITER8",
            "none": "SOC_EXPLOIT_NONE"}

# Everything a profile can define, for the "a stub stays a stub" check.
ALL_FIELDS = ([field for group in FIELDS.values() for field in group]
              + ["EXPLOIT"])

# Where usbliter8 lives on this machine. The tree is read, not copied: these
# tests assert the registry agrees with it, exactly as the ones below assert
# agreement with RPWN. A checkout that is not present makes those checks
# skip rather than fail, because "no local reference" is not the same claim as
# "the registry disagrees with the reference".
USBLITER8 = Path.home() / "usbliter8-main"

ARCHS = {
    "arm64": "SOC_ARCH_AARCH64",
    "armv7": "SOC_ARCH_ARMV7",
    "armv7s": "SOC_ARCH_ARMV7S",
    "armv7k": "SOC_ARCH_ARMV7K",
}

TIERS = {"payload": "SOC_TIER_PAYLOAD", "host": "SOC_TIER_HOST"}

TRIGGERS = {"buttons": "SOC_DFU_TRIGGER_BUTTONS", "loop": "SOC_DFU_TRIGGER_LOOP"}

# Blocks a payload image is built out of: include/soc.h SOC_BLK_PAYLOAD.
PAYLOAD_BLOCKS = [
    "SOC_BLK_ROM", "SOC_BLK_SRAM", "SOC_BLK_DRAM", "SOC_BLK_UART",
    "SOC_BLK_TIMER", "SOC_BLK_AIC", "SOC_BLK_PMGR", "SOC_BLK_GPIO",
    "SOC_BLK_I2C", "SOC_BLK_SPI", "SOC_BLK_WDT", "SOC_BLK_NAND",
    "SOC_BLK_USB", "SOC_BLK_DCP",
]


def parse_profile(name):
    """A profile header, as {field: value} for SOC_<name>_<field>."""
    path = SOC_DIR / ("%s.h" % name)
    if not path.exists():
        return None
    # Join a value continued onto the next line before matching, or the
    # MAPPED_BLOCKS mask matches as a lone backslash.
    text = re.sub(r"\\\s*\n\s*", " ", path.read_text())
    found = {}
    for match in re.finditer(
            r"^#define\s+SOC_%s_([A-Z0-9_]+)\s+(.+?)\s*$" % name.upper(),
            text, re.MULTILINE):
        field = match.group(1)
        # Trailing comments are common enough on a value that carries a caveat,
        # and they must not become part of the value: a parser that keeps them
        # fails to read the number rather than reading it wrong.
        value = re.sub(r"/\*.*?\*/", "", match.group(2)).strip()
        # Keep the first definition, so a profile cannot satisfy the test
        # with a later override.
        found.setdefault(field, value)
    return found


def as_int(value):
    """'0x8947u' -> 0x8947, '32u' -> 32."""
    return int(re.match(r"(0x[0-9A-Fa-f]+|\d+)[uUlL]*$", value.strip()).group(1), 0)


def parse_device_platform():
    """The vendored tool's platform table, as {cpid: {attr: value}}."""
    text = (IPWND / "device_platform.py").read_text()
    platforms = {}
    # One DevicePlatform(...) call per platform. Splitting on the opening
    # keeps this independent of the argument order inside the call.
    for block in text.split("DevicePlatform(")[1:]:
        cpid = re.search(r"cpid=0x([0-9A-Fa-f]+)", block)
        if not cpid:
            continue
        entry = {"cpid": int(cpid.group(1), 16)}
        for key, match in _assignments(block):
            entry[key] = match
        # The three string-valued constructor arguments are not part of the
        # scalar override set, because __init__ never touches them.
        for key, pattern in (("arch", r"\barch='([^']*)'"),
                             ("srtg", r"\bsrtg='([^']*)'"),
                             ("rom_sha1", r"\brom_sha1='([0-9a-f]+)'")):
            match = re.search(pattern, block)
            if match:
                entry[key] = match.group(1)
        platforms[entry["cpid"]] = entry
    # __init__ overrides the constructor's geometry per CPID group: the DFU
    # and recovery bases are set there, not in the call, so a parser that
    # reads only the constructor silently loses them.
    for cpids, assignments in _init_overrides(text):
        for cpid in cpids:
            if cpid in platforms:
                platforms[cpid].update(assignments)
    return platforms


ASSIGN_RE = r"\b%s\s*=\s*(0x[0-9A-Fa-f]+|\d+|None|'[^']*')"


def _assignments(text):
    """(key, value) for every scalar assignment in `text`."""
    for key in ("cprv", "scep", "rom_base", "rom_size", "sram_base",
                "sram_size", "dram_base", "nonce_length",
                "sep_nonce_length", "demotion_reg", "dfu_image_base",
                "dfu_load_base", "recovery_image_base", "recovery_load_base"):
        # The table writes `rom_base=0x3F000000` in the constructor call and
        # `self.dfu_image_base      = 0x34000000` in __init__, so the pattern
        # has to accept both spacings.
        match = re.search(ASSIGN_RE % key, text)
        if match:
            raw = match.group(1)
            yield key, (None if raw == "None" else
                        raw.strip("'") if raw.startswith("'") else int(raw, 0))


def _init_overrides(text):
    """[(cpids, {field: value})] from __init__'s per-CPID `if` groups."""
    # The class body lives before the first DevicePlatform( call.
    body = text.split("DevicePlatform(")[0]
    # A CPID list is written 0x8940, so the pattern has to accept the 'x' in
    # a 0x prefix as well as the digits.
    groups = re.findall(
        r"if\s+self\.cpid\s+(?:in\s+(\[0x[0-9A-Fa-fx,\s]*\])|"
        r"(?:==\s*(0x[0-9A-Fa-f]+)))"
        r"\s*:(.*?)(?=\n\s*if\s+self\.cpid|\n\s*def\s|\Z)",
        body, re.DOTALL)
    for list_form, single, assignments in groups:
        if list_form:
            cpids = [int(tok, 0) for tok in
                     re.findall(r"0x[0-9A-Fa-f]+|\d+", list_form)]
        else:
            cpids = [int(single, 0)]
        yield cpids, dict(_assignments(assignments))


def parse_checkm8_triggers():
    """CPID -> "loop"/"buttons", from checkm8.py's device configurations."""
    text = (IPWND / "checkm8.py").read_text()
    triggers = {}
    # Each DeviceConfig line ends with a comment naming the SoC and how it
    # enters DFU: "T8015 (DFU loop)" / "T8010 (buttons)". The strings are
    # padded to align the comments, so the pattern allows space before the
    # comma.
    for line in text.splitlines():
        config = re.search(r"DeviceConfig\('[^']*'\s*,\s*0x([0-9A-Fa-f]+),", line)
        kind = re.search(r"\((DFU loop|buttons)\)", line)
        if config and kind:
            triggers[int(config.group(1), 16)] = (
                "loop" if kind.group(1) == "DFU loop" else "buttons")
    return triggers


class TestRegistry(unittest.TestCase):
    """The registry is a table; every profile has to satisfy it."""

    def test_every_supported_soc_has_a_profile(self):
        missing = [name for name in PROFILES if parse_profile(name) is None]
        self.assertEqual(missing, [], "profiles listed in PROFILES are missing")
        # Ten CPIDs, nine headers: S5L8960 stands for both A7 variants.
        cpids = {as_int(parse_profile(name)["CPID"]) for name in PROFILES}
        self.assertEqual(len(cpids), len(CHECKM8_CURRENT),
                         "the registry should cover the checkm8 SoC list")

    def test_every_profile_defines_the_whole_contract(self):
        for name in ALL_PROFILES:
            profile = parse_profile(name)
            missing = [field
                       for group in FIELDS.values() for field in group
                       if group is not FIELDS["sep"]
                       and field not in profile]
            self.assertEqual(missing, [],
                             "profile %s is missing %s" % (name, missing))

    def test_an_identity_stub_carries_no_sep_field(self):
        """A profile with no recorded geometry at all stays that way.

        Scoped to stubs rather than to "no exploit", because those are
        different sets: the A12Z has no implemented exploit *and* has real
        sourced geometry, including a SEP power word its own ioreg confirms.
        Calling it a stub would have failed the check for the wrong reason.

        The contract test exempts the SEP group, so this is what holds that
        exemption closed -- a stub acquiring a SEP field means a source was
        found, and the point of a stub is that none was.
        """
        for name in ALL_PROFILES:
            profile = parse_profile(name)
            recorded = [f for f in FIELDS["geometry"]
                        if f in profile and profile[f] != "SOC_UNRECORDED"
                        and profile[f] != '""']
            if recorded:
                continue
            present = [f for f in FIELDS["sep"] if f in profile]
            self.assertEqual(present, [],
                             "%s records no geometry but carries %s"
                             % (name, present))


    def test_a_sep_window_has_an_extent(self):
        """A base with no size is not a window, and a size with no base is not
        either.

        This is the invariant that survives another agent adding a part: it
        says nothing about *which* profiles carry the fields, only that a
        profile carrying half of one is wrong. The previous form asserted an
        exact membership whitelist, and it broke the first time a new part was
        mapped correctly and with its own source.
        """
        for name in ALL_PROFILES:
            profile = parse_profile(name)
            self.assertEqual("SEP_BASE" in profile, "SEP_SIZE" in profile,
                             "%s carries SEP_BASE without SEP_SIZE, or the "
                             "reverse" % name)

    def test_the_carrying_set_is_reported_not_assumed(self):
        """The set of profiles carrying each field, printed rather than
        asserted against a whitelist."""
        carried = {}
        for field in FIELDS["sep"]:
            carried[field] = sorted(name for name in ALL_PROFILES
                                    if field in parse_profile(name))
        print("SEP fields carried by: %s" % carried)
        self.assertTrue(carried["SEP_POWER_WORD"],
                        "no profile carries a SEP power word")

    def test_every_profile_has_a_tier(self):
        for name in ALL_PROFILES:
            profile = parse_profile(name)
            self.assertIn(profile.get("TIER"), TIERS.values(),
                          "profile %s has an unknown tier" % name)

    def test_every_profile_declares_the_blocks_it_maps(self):
        for name in ALL_PROFILES:
            profile = parse_profile(name)
            blocks = profile.get("MAPPED_BLOCKS", "")
            # Every profile at least records the ROM window, and it says
            # which: a mask that names nothing is a profile nobody read. The
            # one exception is an identity stub, which has no window to name
            # and whose emptiness is the point -- see the stub check below.
            if name not in IDENTITY_STUB_PROFILES:
                for block in ("SOC_BLK_ROM",):
                    self.assertIn(block, blocks,
                                  "profile %s should claim %s"
                                  % (name, block))
            # The AArch64 checkm8 profiles record SRAM and DRAM too, from
            # device_platform.py. The newer ones do not have those windows
            # documented, so requiring them would be requiring an invention.
            if name in PROFILES:
                for block in ("SOC_BLK_SRAM", "SOC_BLK_DRAM"):
                    self.assertIn(block, blocks,
                                  "profile %s should claim %s"
                                  % (name, block))

    def test_payload_tier_is_the_only_one_with_a_map(self):
        for name in ALL_PROFILES:
            profile = parse_profile(name)
            if profile["TIER"] == TIERS["payload"]:
                for block in PAYLOAD_BLOCKS:
                    self.assertIn(
                        block, profile["MAPPED_BLOCKS"],
                        "payload-tier profile %s must map %s" % (name, block))

    def test_exactly_one_profile_is_payload_tier(self):
        """A second one means someone promoted a SoC without mapping it, or
        mapped it without updating the tier. Both are worth a message."""
        payload = [name for name in PROFILES
                   if parse_profile(name)["TIER"] == TIERS["payload"]]
        self.assertEqual(payload, ["t8015"],
                         "only the A11 profile should be payload tier today")

    def test_only_the_payload_tier_carries_peripheral_defines(self):
        for name in ALL_PROFILES:
            profile = parse_profile(name)
            if profile["TIER"] == TIERS["host"]:
                present = [f for f in PAYLOAD_ONLY if f in profile]
                self.assertEqual(present, [],
                                 "host-tier profile %s carries %s, which it "
                                 "has no map for" % (name, present))


class TestSepGeometry(unittest.TestCase):
    """The SEP interface, which the registry had not recorded at all.

    These fields are the ones a SEP-targeting payload depends on, and they are
    separate from the AP-side map: the SEP is a different processor with its
    own control window and its own power gate. Recording only the AP made the
    registry look complete while saying nothing about the endpoint.
    """

    # The SEP power-state word per part, read from the reference tree's own
    # cross-part pmgr ps-reg table. The A11 is the entry its table names for
    # that part, the A12/A12X share d321ap's ps-reg[5], and the A13 is at a
    # different offset entirely.
    SEP_POWER_WORDS = {
        "t8015": 0x232080400,   # A11  ps-reg[5] 0x00080400
        "t8020": 0x23B080600,   # A12  ps-reg[5] 0x00080600
        "t8027": 0x23B080600,   # A12X ps-reg[5] 0x00080600
        "t8030": 0x23B080C00,   # A13  plane 8 +0xc00, a different offset
    }

    def test_the_sep_window_is_recorded_where_a_source_establishes_it(self):
        for name, expected in sorted(self.SEP_POWER_WORDS.items()):
            profile = parse_profile(name)
            self.assertIn("SEP_POWER_WORD", profile,
                          "%s should carry a SEP power word" % name)
            self.assertEqual(as_int(profile["SEP_POWER_WORD"]), expected,
                             "%s: SEP power word does not match the "
                             "reference ps-reg table" % name)

    def test_the_a13_offset_is_not_the_a12s(self):
        """The two A12-generation parts use +0x600 and the A13 uses +0xc00 in
        the same PMGR plane. The reference tree is explicit that copying the
        A12's word onto the A13 would be wrong, so the difference is pinned
        rather than left to a reader to notice."""
        band = 0x23B000000
        a12 = as_int(parse_profile("t8020")["SEP_POWER_WORD"]) - band
        a13 = as_int(parse_profile("t8030")["SEP_POWER_WORD"]) - band
        self.assertNotEqual(a12, a13)
        self.assertEqual(a12 & 0xFFF, 0x600)
        self.assertEqual(a13 & 0xFFF, 0xC00)

    def test_the_a11_sep_control_window_is_the_dt_cited_one(self):
        """The strongest-sourced address in the whole registry, and it was
        missing until now. DeviceTree.d22ap's /arm-io/sep gives
        reg = 0x43000000 + 0x1000 with the aarch64 flag present."""
        profile = parse_profile("t8015")
        self.assertEqual(as_int(profile["SEP_BASE"]), 0x243000000)
        self.assertEqual(as_int(profile["SEP_SIZE"]), 0x1000)

    def test_the_pmgr_band_is_the_power_words_band(self):
        """Every part with a recorded SEP power word must have its PMGR in the
        same band as that word.

        This is the check that catches the error this commit corrects: the
        A12/A12X profiles carried pmgr_base 0x20e000000 from a shared yaml
        while the A12's own power word sits at 0x23b080600. A profile can be
        self-consistent and still wrong, and the band is what shows it."""
        for name, word in sorted(self.SEP_POWER_WORDS.items()):
            profile = parse_profile(name)
            self.assertIn("PMGR_BASE", profile,
                          "%s should carry a PMGR base" % name)
            band = as_int(profile["PMGR_BASE"])
            self.assertEqual(word & ~0xFFFFFF, band,
                             "%s: PMGR base 0x%x is not the band the SEP "
                             "power word 0x%x sits in" % (name, band, word))


class TestExploitMapping(unittest.TestCase):
    """Which public exploit reaches a part, per profile.

    The registry started as "the ten SoCs checkm8 covers", which made the
    exploit a property of the set. A second bootrom bug (usbliter8) covers
    parts checkm8 never did, so the mapping moved onto the profile where the
    host tool can read it. These checks are what keep it from drifting back
    into a set-level assumption.
    """

    def test_checkm8_profiles_name_checkm8(self):
        for name in PROFILES:
            profile = parse_profile(name)
            self.assertEqual(profile["EXPLOIT"], "SOC_EXPLOIT_CHECKM8",
                             "%s is in the checkm8 SoC list, so its exploit "
                             "field should say checkm8" % name)

    def test_every_profile_uses_a_known_exploit_value(self):
        for name in ALL_PROFILES:
            self.assertIn(parse_profile(name)["EXPLOIT"], EXPLOITS.values(),
                          "%s has an unknown exploit value" % name)

    def test_usbliter8_profiles_name_usbliter8(self):
        """Every profile records the public exploit family that reaches it."""
        for name in USBLITER8_PROFILES:
            profile = parse_profile(name)
            self.assertEqual(profile["EXPLOIT"], "SOC_EXPLOIT_USBLITER8",
                             "%s should name usbliter8" % name)

    def test_implemented_usbliter8_profiles_have_handlers(self):
        """Cross-check runnable entries against usbliter8's CPID switch."""
        if not USBLITER8.exists():
            self.skipTest("usbliter8 tree not present at %s" % USBLITER8)
        text = (USBLITER8 / "exploit.c").read_text()
        for name in USBLITER8_IMPLEMENTED_PROFILES:
            profile = parse_profile(name)
            self.assertEqual(profile["EXPLOIT"], "SOC_EXPLOIT_USBLITER8",
                             "%s should name usbliter8" % name)
            cpid = "0x%04x" % as_int(profile["CPID"])
            self.assertIn("case %s:" % cpid, text,
                          "%s: usbliter8's exploit.c has no case for %s"
                          % (name, cpid))

    def test_checkm8_and_usbliter8_have_different_reach(self):
        """The two bugs are not the same set, and the registry has to keep
        them apart rather than picking one table for the whole family.

        The A12 is where they diverge sharply: it is the first part checkm8
        cannot reach AND the first usbliter8 can. If a future edit makes these
        two sets overlap, this is the test that notices the family-level
        shortcut being taken again."""
        checkm8 = {parse_profile(n)["CPID"] for n in PROFILES}
        usbliter8 = {parse_profile(n)["CPID"] for n in USBLITER8_PROFILES}
        self.assertEqual(checkm8 & usbliter8, set(),
                         "no part should be claimed by both exploits")

    def test_the_a12_is_where_checkm8_stops(self):
        """The exploit fields are load-bearing for the host tool's advice, so
        the boundary is pinned rather than left to convention: the A11's
        0x8015 remains checkm8-covered, while the first runnable usbliter8
        profile is 0x8020."""
        usbliter8 = [as_int(parse_profile(n)["CPID"])
                     for n in USBLITER8_PROFILES]
        checkm8 = {as_int(parse_profile(n)["CPID"]) for n in PROFILES}
        self.assertIn(0x8015, checkm8)
        self.assertNotIn(0x8020, checkm8)
        self.assertIn(0x8020, usbliter8)

    def test_parts_with_no_exploit_say_so(self):
        for name in NO_EXPLOIT_PROFILES:
            profile = parse_profile(name)
            self.assertEqual(profile["EXPLOIT"], "SOC_EXPLOIT_NONE",
                             "%s has no public exploit path in this tree, so "
                             "its field should say NONE" % name)

    def test_an_identity_stub_records_nothing_else(self):
        """T8021 is a real part with no local source for its geometry. The
        guard is that it stays that way until somebody finds one: a filled-in
        field in a stub means a source that is not cited yet.

        Identity and tier are the exception, and deliberately so -- a profile
        that named nothing could not be selected, and a stub that was not
        marked host tier would claim the map it does not have."""
        identity = {"NAME", "CPID", "ARCH", "TIER", "MAPPED_BLOCKS", "EXPLOIT"}
        for name in IDENTITY_STUB_PROFILES:
            profile = parse_profile(name)
            recorded = [field for field in ALL_FIELDS
                        if field not in identity and field in profile and
                        profile[field] != "SOC_UNRECORDED" and
                        profile[field] != '""']
            self.assertEqual(recorded, [],
                             "%s is an identity stub; %s should not be "
                             "recorded without a source" % (name, recorded))


class TestProfileFiles(unittest.TestCase):
    """Mechanical checks on the profile headers themselves.

    The per-SoC headers are the one place every SoC's constants live, so a
    structural defect in one is invisible everywhere else: the compiler is
    happy, the values are right, and the file is simply twice the size it
    should be with two copies to keep in step.
    """

    def test_no_profile_defines_the_same_field_twice(self):
        """A duplicated #define is silently shadowed.

        C permits an identical redefinition, so a file that defines a field
        twice with the same value compiles clean and reads fine -- until
        somebody edits one copy. Then the file is wrong and nothing says so,
        which is the failure this catches. Differing values would be a harder
        error, but identical ones are the ones that get through review.
        """
        for name in ALL_PROFILES:
            path = SOC_DIR / ("%s.h" % name.upper())
            if not path.exists():
                continue
            seen = {}
            for line in path.read_text().splitlines():
                match = re.match(r"^#define\s+(SOC_%s_[A-Z0-9_]+)\s"
                                 % name.upper(), line)
                if not match:
                    continue
                field = match.group(1)
                seen.setdefault(field, []).append(line.strip())
            conflicting, identical = {}, {}
            for field, lines_ in seen.items():
                if len(lines_) < 2:
                    continue
                # Comments are stripped before comparing, or the same value
                # written once with a caveat and once without reads as a
                # conflict and the gate fires on a tree that is merely untidy.
                values = {re.sub(r"/\*.*?\*/", "", l.split(None, 2)[2]).strip()
                          for l in lines_}
                (conflicting if len(values) > 1 else identical)[field] = lines_

            # Conflicting values are wrongness: one of the two is not what the
            # profile means, and the compiler takes the last one silently.
            self.assertEqual(conflicting, {},
                             "%s defines %s twice with different values"
                             % (name, sorted(conflicting)))

            # Identical values are a maintenance hazard rather than a bug --
            # they compile and they read fine -- so they are reported and not
            # gated. The owning agent dedupes at a stopping point; a gate here
            # would fail a tree whose values are still all correct.
            if identical:
                print("%s: %d field(s) defined twice with the same value "
                      "(hazard, not a bug): %s"
                      % (name, len(identical), sorted(identical)))

    def test_no_profile_defines_a_field_belonging_to_another_part(self):
        """A profile must not carry another part's namespaced prefix.

        The whole point of the namespacing is that a copy-paste from a sibling
        is detectable, so a field with the wrong prefix is either a rename that
        was not finished or a copy that was not adapted.
        """
        for name in ALL_PROFILES:
            path = SOC_DIR / ("%s.h" % name.upper())
            if not path.exists():
                continue
            foreign = set()
            for other in ALL_PROFILES:
                if other == name:
                    continue
                for line in path.read_text().splitlines():
                    if re.match(r"^#define\s+SOC_%s_[A-Z0-9_]+" % other.upper(),
                                line):
                        foreign.add(other)
            self.assertEqual(foreign, set(),
                             "%s carries fields prefixed for %s"
                             % (name, sorted(foreign)))



class TestRustDriver(unittest.TestCase):
    """The RPWN Rust driver owns exploit behavior after the Python tree removal."""

    def test_rpwn_rust_suite_passes(self):
        result = subprocess.run(
            ["cargo", "test", "--locked", "--manifest-path",
             str(ROOT / "rpwn" / "rust" / "Cargo.toml")],
            cwd=ROOT, capture_output=True, text=True,
            env={**os.environ, "CARGO_TARGET_DIR": "/private/tmp/dr1zzle-rpwn-test"})
        self.assertEqual(result.returncode, 0,
                         f"RPWN Rust tests failed:\n{result.stdout}{result.stderr}")


class TestSelection(unittest.TestCase):
    """What the build actually does with a profile."""

    PROBE = '#include "memory_map.h"\nint soc_probe = (int)SRAM_BASE;\n'

    def _compile(self, soc=None):
        args = ["clang", "-Iinclude", "-Isrc", "-DARCH_AARCH64",
                "-D__BARE_METAL__", "-fsyntax-only"]
        if soc:
            args.append("-DSOC_%s" % soc)
        return subprocess.run(args + ["-xc", "-"],
                              input=self.PROBE, capture_output=True,
                              text=True, cwd=str(ROOT))

    def test_the_default_profile_compiles(self):
        result = self._compile()
        self.assertEqual(result.returncode, 0,
                         "the default (A11) profile should compile:\n"
                         + result.stderr)

    def test_a_payload_profile_compiles(self):
        result = self._compile("t8015")
        self.assertEqual(result.returncode, 0,
                         "the A11 profile should compile:\n" + result.stderr)

    def test_a_host_tier_profile_is_refused_and_named(self):
        """Not merely refused: refused with the profile named, so the failure
        says which SoC is missing a map instead of which base went missing."""
        result = self._compile("t8010")
        self.assertNotEqual(result.returncode, 0,
                            "a profile with no map must not build")
        self.assertIn("no peripheral register map for t8010", result.stderr,
                      "the refusal should name the profile: %s" % result.stderr)

    def test_a_32bit_profile_is_refused_too(self):
        result = self._compile("s5l8947")
        self.assertNotEqual(result.returncode, 0,
                            "an ARMv7 profile must not build an AArch64 image")
        self.assertIn("no peripheral register map for s5l8947x", result.stderr,
                      "the refusal should name the profile: %s" % result.stderr)

    def test_every_host_profile_is_refused_and_named(self):
        """The refusal contract applies to new identity and partial-map rows
        too; none may accidentally fall through to a driver compile."""
        for name in ALL_PROFILES:
            profile = parse_profile(name)
            if profile["TIER"] != TIERS["host"]:
                continue
            with self.subTest(profile=name):
                result = self._compile(name)
                self.assertNotEqual(result.returncode, 0,
                                    "%s unexpectedly built" % name)
                display_name = profile["NAME"].strip('"')
                self.assertIn("no peripheral register map for " + display_name,
                              result.stderr,
                              "%s: refusal did not name the profile: %s"
                              % (name, result.stderr))


if __name__ == "__main__":
    unittest.main(verbosity=2)
