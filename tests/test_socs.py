#!/usr/bin/env python3
"""Checks the SoC registry against the sources that claim to define it.

The registry is nine profiles under include/soc/. Everything in them either
came from somewhere citable or was reverse-engineered from silicon, and the
only way to keep that honest is to fail when the two disagree:

  1. ipwndfu/device_platform.py -- the vendored checkm8 tool's own table, the
     single source for every profile's ROM/SRAM/DRAM/DFU geometry, nonce
     lengths and demotion register.
  2. ipwndfu/checkm8.py -- each CPID's device configuration, which is where
     the DFU trigger (button hold vs DFU-loop re-entry) comes from.
  3. include/soc/ itself -- the contract every profile has to satisfy.

A transcription error in any direction fails here, not on a device that cannot
be re-secured. No device is needed.

Run: python3 tests/test_socs.py
"""

import re
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOC_DIR = ROOT / "include" / "soc"
IPWND = ROOT / "ipwndfu"

# Every CPID checkm8 supports, from ipwndfu/README.md "current SoC support".
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
        field, value = match.group(1), match.group(2)
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
        for name in PROFILES:
            profile = parse_profile(name)
            missing = [field
                       for group in FIELDS.values() for field in group
                       if field not in profile]
            self.assertEqual(missing, [],
                             "profile %s is missing %s" % (name, missing))

    def test_every_profile_has_a_tier(self):
        for name in PROFILES:
            profile = parse_profile(name)
            self.assertIn(profile.get("TIER"), TIERS.values(),
                          "profile %s has an unknown tier" % name)

    def test_every_profile_declares_the_blocks_it_maps(self):
        for name in PROFILES:
            profile = parse_profile(name)
            blocks = profile.get("MAPPED_BLOCKS", "")
            # Every host-tier profile at least records ROM/SRAM/DRAM, and it
            # says which: a mask that names nothing is a profile nobody read.
            for block in ("SOC_BLK_ROM", "SOC_BLK_SRAM", "SOC_BLK_DRAM"):
                self.assertIn(block, blocks,
                              "profile %s should claim %s" % (name, block))

    def test_payload_tier_is_the_only_one_with_a_map(self):
        for name in PROFILES:
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
        for name in PROFILES:
            profile = parse_profile(name)
            if profile["TIER"] == TIERS["host"]:
                present = [f for f in PAYLOAD_ONLY if f in profile]
                self.assertEqual(present, [],
                                 "host-tier profile %s carries %s, which it "
                                 "has no map for" % (name, present))


class TestAgainstTheVendoredTable(unittest.TestCase):
    """The geometry has to be the vendored tool's geometry."""

    def setUp(self):
        self.platforms = parse_device_platform()
        self.assertTrue(self.platforms, "device_platform.py parsed to nothing")

    def test_platforms_were_parsed(self):
        self.assertEqual(sorted(self.platforms), sorted(
            [0x8947, 0x8950, 0x8955, 0x8002, 0x8004, 0x8960, 0x8010, 0x8011,
             0x8015]))

    def test_every_profile_matches_its_platform(self):
        for name in PROFILES:
            profile = parse_profile(name)
            expected = self.platforms[as_int(profile["CPID"])]
            for field in ("CPID", "CPRV"):
                self.assertEqual(as_int(profile[field]), expected[field.lower()],
                                 "%s: %s does not match device_platform.py"
                                 % (name, field))
            for field in ("SRTG", "ROM_SHA1"):
                self.assertEqual(profile[field].strip('"'),
                                 expected[field.lower()],
                                 "%s: %s does not match device_platform.py"
                                 % (name, field))
            for field in ("NONCE_LENGTH", "SEP_NONCE_LENGTH"):
                value = as_int(profile[field])
                # The vendored table records a part with no SEP nonce as
                # None; the registry uses 0 for the same thing.
                if expected[field.lower()] is None:
                    expected[field.lower()] = 0
                self.assertEqual(value, expected[field.lower()],
                                 "%s: %s does not match device_platform.py"
                                 % (name, field))

    def test_geometry_matches_the_platform(self):
        for name in PROFILES:
            profile = parse_profile(name)
            expected = self.platforms[as_int(profile["CPID"])]
            for field in ("ROM_BASE", "ROM_SIZE", "DRAM_BASE",
                          "DFU_IMAGE_BASE", "DFU_LOAD_BASE",
                          "RECOVERY_IMAGE_BASE", "RECOVERY_LOAD_BASE",
                          "SRAM_BASE", "DEMOTION_REG"):
                value = as_int(profile[field])
                self.assertEqual(value, expected[field.lower()],
                                 "%s: %s is 0x%x, device_platform.py says 0x%x"
                                 % (name, field, value,
                                    expected[field.lower()]))

    def test_sram_window_fits_inside_the_documented_one(self):
        """t8015 uses the iphem-soc usable window, not the whole SRAM the
        vendored table reports. That is a deliberate difference, so this is a
        containment check rather than an equality one."""
        for name in PROFILES:
            profile = parse_profile(name)
            expected = self.platforms[as_int(profile["CPID"])]
            base = as_int(profile["SRAM_BASE"])
            size = as_int(profile["SRAM_SIZE"])
            self.assertEqual(base, expected["sram_base"],
                             "%s: SRAM base differs from the vendored table"
                             % name)
            self.assertLessEqual(size, expected["sram_size"],
                                 "%s: SRAM window is larger than the part has"
                                 % name)

    def test_dfu_trigger_matches_the_checkm8_config(self):
        triggers = parse_checkm8_triggers()
        self.assertTrue(triggers, "checkm8.py device configs parsed to nothing")
        for name in PROFILES:
            profile = parse_profile(name)
            expected = triggers[as_int(profile["CPID"])]
            self.assertEqual(profile["DFU_TRIGGER"], TRIGGERS[expected],
                             "%s: DFU trigger is %s, checkm8.py says %s"
                             % (name, profile["DFU_TRIGGER"], expected))

    def test_arch_matches_the_platform(self):
        for name in PROFILES:
            profile = parse_profile(name)
            expected = self.platforms[as_int(profile["CPID"])]
            self.assertEqual(profile["ARCH"], ARCHS[expected["arch"]],
                             "%s: arch is %s, device_platform.py says %s"
                             % (name, profile["ARCH"], expected["arch"]))

    def test_nonce_lengths_are_plausible(self):
        """The one field the registry cannot check against a second source:
        a zero nonce length would make every GID transaction nonsense."""
        for name in PROFILES:
            profile = parse_profile(name)
            length = as_int(profile["NONCE_LENGTH"])
            self.assertIn(length, (20, 32),
                          "%s: nonce length %d is not 20 or 32" % (name, length))


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


if __name__ == "__main__":
    unittest.main(verbosity=2)
