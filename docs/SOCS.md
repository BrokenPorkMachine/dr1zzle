# SoC registry

dr1zzle builds for one SoC at a time, selected at build time:

```
make SOC=t8015        # the default; A11
make SOC=t8010        # refused: see the payload gate below
```

The point of the registry is that "which SoCs exist" is a table, not a set of
`-DSOC_` branches scattered through the drivers. Every binding that varies
between SoCs lives in one per-SoC header under `include/soc/`, and
`include/soc.h` selects it.

## What is in it

The ten CPIDs checkm8 supports — `ipwndfu/README.md`, "current SoC support" —
each with a profile. Ten SoCs, nine headers: S5L8960 covers both A7 variants.

| Profile | CPID | CPU | SRAM | ROM | DFU image | File |
|---|---|---:|---:|---:|---:|---|
| t8015 | 0x8015 | AArch64 | 0x180000000 + 0x1E8000 | 0x100000000 + 0x100000 | 0x18001C000 | `include/soc/t8015.h` |
| t8011 | 0x8011 | AArch64 | 0x180000000 + 0x200000 | 0x100000000 + 0x100000 | 0x1800B0000 | `include/soc/t8011.h` |
| t8010 | 0x8010 | AArch64 | 0x180000000 + 0x200000 | 0x100000000 + 0x20000 | 0x1800B0000 | `include/soc/t8010.h` |
| s5l8960 | 0x8960 | AArch64 | 0x180000000 + 0x400000 | 0x100000000 + 0x80000 | 0x180380000 | `include/soc/s5l8960.h` |
| t8004 | 0x8004 | ARMv7k | 0x48800000 + 0x140000 | 0x40000000 + 0x20000 | 0x48818000 | `include/soc/t8004.h` |
| t8002 | 0x8002 | ARMv7k | 0x48800000 + 0x120000 | 0x40000000 + 0x100000 | 0x48818000 | `include/soc/t8002.h` |
| s5l8955 | 0x8955 | ARMv7s | 0x10000000 + 0x80000 | 0x3F000000 + 0x10000 | 0x10000000 | `include/soc/s5l8955.h` |
| s5l8950 | 0x8950 | ARMv7s | 0x10000000 + 0x80000 | 0x3F000000 + 0x10000 | 0x10000000 | `include/soc/s5l8950.h` |
| s5l8947 | 0x8947 | ARMv7 | 0x34000000 + 0x40000 | 0x3F000000 + 0x10000 | 0x34000000 | `include/soc/s5l8947.h` |

Three of those numbers are worth a second look, because they are where an
A11-shaped assumption silently breaks:

- **ROM size**: 0x100000 on t8015/t8011, **0x20000 on t8010 and t8004**. A
  capture sized from the wrong row reads a fraction of the ROM.
- **SRAM size**: 0x1E8000 on t8015, **0x400000 on s5l8960**. The window an
  image may occupy is derived from it.
- **DFU image base**: 0x18001C000 on t8015, **0x180380000 on s5l8960**, and
  the A7 exploits load at the SRAM base rather than at 0x800000000. The
  placement bound the payload link is asserted against comes from the profile
  for exactly this reason.

## Tiers

A tier says what this tree can *do* with a profile, not how much is known
about it:

- `SOC_TIER_PAYLOAD` — the peripheral map needed to link an image is present.
- `SOC_TIER_HOST` — registry, host tooling and exploit geometry only.

`t8015` is `SOC_TIER_PAYLOAD`; the other nine are `SOC_TIER_HOST`, and
`include/soc.h` refuses a build for them with a message that names the profile
rather than letting a driver fail on a base that was never measured.

That is not a judgement about the Silicon, it is a statement about this tree:
every base listed above came from `ipwndfu/device_platform.py`, which
documents ROM, SRAM, DRAM and DFU geometry and nothing else. A payload needs a
console, and a console needs a register base, so a geometry-only profile
cannot become an image.

The five 32-bit parts (s5l8947, s5l8950, s5l8955, t8002, t8004) are host tier
for a second, independent reason: `start.S`, the vector table, the MMU setup
and every driver in `src/` are AArch64, so an image built for them could not
run on an ARMv7/ARMv7k CPU even with a perfect register map. The three AArch64
host-tier parts (s5l8960, t8010, t8011) are host tier on the missing map
alone.

## Promoting a profile

One header and one define:

1. Add the register bases to `include/soc/<name>.h` (UART, TIMER, AIC, PMGR,
   GPIO, I2C, SPI, watchdog, NAND, USB, DCP).
2. Check each driver against this part's block differences — PMGR device
   masks, the AIC version, NAND geometry, the AES/DCP pipe.
3. Set `SOC_<name>_TIER` to `SOC_TIER_PAYLOAD` and add the blocks to
   `SOC_<name>_MAPPED_BLOCKS`.

`include/memory_map.h` needs no change: it aliases the driver-facing names to
the selected profile through `DR1ZZLE_CAT`, so a new profile is a new header
and a new `#elif` in `include/soc.h`, not a driver edit.

## What is not here

`ipwndfu/README.md` also lists a "future SoC support" line: s5l8940x, s5l8942x,
s5l8945x, s5l8747x, t7000, t7001, s7002, s8000, s8001, s8003, t8012. Those have
no entry in `device_platform.py`, so there is no geometry to record and no
profile was written for them. t8016 — the other A11 CPID, in the iPhone 8 Plus
and X — is likewise absent from the vendored tool's tables, so it is not
invented here.

Adding any of them is the same two steps as promotion: an entry in the vendored
table to cite, then a header.

## Tests

`make soc-test` (tests/test_socs.py) checks the registry against the sources
that are supposed to be authoritative for it:

- every profile defines the whole contract, and `t8015`'s values are unchanged
  from the ones the tree was built against;
- the geometry in each profile matches `ipwndfu/device_platform.py`, so a
  transcription error in either direction fails the test rather than a device;
- the DFU trigger matches `ipwndfu/checkm8.py`'s per-CPID device configuration;
- exactly one profile is payload tier, and it maps every block in
  `SOC_BLK_PAYLOAD`;
- `make SOC=<name>` compiles for the payload tier and is refused, with the
  profile named, for every host-tier profile.

No device is needed for any of it, which is the point: the parts of this
expansion that can be verified without silicon are verified without it.
