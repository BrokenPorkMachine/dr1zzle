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

The registry contains the ten CPIDs checkm8 supports — `rpwn/rust/README.md`,
"current SoC support" — plus the newer T8020/T8021/T8027/T8030 identities
named by the usbliter8 reference tree. The latter are host-only records: this
repository does not build or run their device-side code. S5L8960 covers both
A7 variants, so the original ten CPIDs occupy nine headers.

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
| t8020 | 0x8020 | AArch64 | 0x19C000000 + unrecorded | 0x100000000 + 0x100000 | unrecorded | `include/soc/t8020.h` |
| t8021 | 0x8021 | AArch64 | unrecorded | unrecorded | unrecorded | `include/soc/t8021.h` |
| t8027 | 0x8027 | AArch64 | 0x19C000000 + unrecorded | 0x100000000 + 0x100000 | unrecorded | `include/soc/t8027.h` |
| t8030 | 0x8030 | AArch64 | 0x19C000000 + unrecorded | 0x100000000 + 0x30000 | unrecorded | `include/soc/t8030.h` |

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

The T8020/T8027 and T8030 rows intentionally show `unrecorded` where this
tree lacks a platform measurement. `SOC_UNRECORDED` is a sentinel, not a
usable address; host-tier selection refuses to link a payload against these
profiles. T8021 is an identity stub with no geometry in the local sources.

The exploit field is also per profile. The original ten entries carry
`SOC_EXPLOIT_CHECKM8`; T8020 and T8030 carry
`SOC_EXPLOIT_USBLITER8`; T8021 and T8027 carry `SOC_EXPLOIT_NONE`. The
usbliter8 reference currently implements T8020 and T8030 and describes T8027
as theoretical, so the registry does not imply a runnable handler for T8027.

## Tiers

A tier says what this tree can *do* with a profile, not how much is known
about it:

- `SOC_TIER_PAYLOAD` — the peripheral map needed to link an image is present.
- `SOC_TIER_HOST` — registry, host tooling and exploit geometry only.

`t8015` is `SOC_TIER_PAYLOAD`; every other profile is `SOC_TIER_HOST`, and
`include/soc.h` refuses a build for them with a message that names the profile
rather than letting a driver fail on a base that was never measured.

That is not a judgement about the Silicon, it is a statement about this tree:
every base listed above came from `rpwn/rust/src/device_platform.rs`, which
documents ROM, SRAM, DRAM and DFU geometry and nothing else. A payload needs a
console, and a console needs a register base, so a geometry-only profile
cannot become an image.

The five 32-bit parts (s5l8947, s5l8950, s5l8955, t8002, t8004) are host tier
for a second, independent reason: `start.S`, the vector table, the MMU setup
and every driver in `src/` are AArch64, so an image built for them could not
run on an ARMv7/ARMv7k CPU even with a perfect register map. The three AArch64
host-tier parts (s5l8960, t8010, t8011) are host tier on the missing map
alone. The T8020/T8027/T8030 profiles are host tier because this repository
has no payload map for that generation; T8021 remains an identity-only stub,
while T8027 has only a partial, host-side geometry record.

## Which exploit reaches which part

A tier says what this tree can *do* with a profile. That is not the same
question as whether the part can be pwned at all, so the exploit is a separate
field on the profile (`SOC_<name>_EXPLOIT`), and the two do not line up:

| Profile | CPID | Reached by | Builds here? |
|---|---|---|---|
| t8015 | 0x8015 | checkm8 | yes |
| t8011, t8010, s5l8960, t8004, t8002, s5l8955, s5l8950, s5l8947 | — | checkm8 | no (no map) |
| t8020 | 0x8020 | usbliter8 | no (no map) |
| t8030 | 0x8030 | usbliter8 | no (no map) |
| t8027 | 0x8027 | none | no (no map) |
| t8021 | 0x8021 | none | no (no map) |

Two public bootrom bugs, and they do not cover the same set. checkm8 ends with
the A11. usbliter8 covers the A12 and the A13, and its own README names
A12X/A12Z as "theoretically supported as well, but it's not implemented yet" —
so the A12Z (T8027) is a part this registry can describe and no public exploit
can reach, which is why it and the A12X (T8021) carry `SOC_EXPLOIT_NONE`. Both
sets are read off the vendored tooling's own CPID switches by
`make soc-test`, so a claim about either set is checkable against the source
that makes it.

The practical difference is which host is in the middle of the cable. checkm8
runs over a Mac's own USB stack. usbliter8 runs on an RP2350 (e.g. a Raspberry
Pi Pico 2) as the USB host, which this tool can neither substitute for nor
emulate. `goat pwn` reads the attached CPID and refuses out of hand for a part
checkm8 cannot reach, naming what would be needed, instead of pointing the
exploit at a device that cannot take it and leaving an operator guessing at
the cable.

The A13 has the best evidence in the registry: a hardware-verified run in
which a T8030 device enumerated in DFU, was exploited, and re-enumerated with
`PWND:[usbliter8]` in its serial string. That is evidence for the addresses in
its profile and for the exploit's reach — not for this tree's ability to use
them, which the tier still refuses.

## Post-checkm8 geometry

The A12/A13 profiles are not the A11's numbers with a new CPID. The parts with
any source at all differ in the places that matter:

| | t8015 | t8020 | t8030 |
|---|---:|---:|---:|
| SRAM base | 0x180000000 | 0x19C000000 | 0x19C000000 |
| ROM size | 0x100000 | 0x100000 | **0x30000** |
| AIC | 0x232100000 | **0x23B100000** | unrecorded |
| PMGR | 0x232000000 | **0x23B000000** | 0x23B000000 |

An A11-shaped assumption would misplace the interrupt controller and the power
manager on the A12 and read a fifth of the A13's ROM. Everything not in that
table is `SOC_UNRECORDED` in those profiles — a value distinct from `0x0` and
from any plausible address, so a placement rule built on a field nobody
sourced cannot be confused with one that was.

The A12 PMGR entry is a correction rather than a first draft. It read
`0x20E000000` when these profiles were committed, copied from the shared T802x
yaml, and the A12X measurement that came after it says plainly that "the shared
pmgr_base: 0x20e000000 is therefore the wrong band for this part": the A12's own
composed `movz`/`movk` bases name the `0x23b0` band instead, and its first PMGR
plane is `0x30000` — ten 16 KiB entries at `0x4000` stride — not one page. The
shape of that error is worth keeping in mind: a platform config that is right
for one part can be wrong for a sibling, and copying the sibling's file is how
that survives review. `test_the_pmgr_band_is_the_power_words_band` is what
catches it now, by requiring a part's PMGR band to contain its own SEP power
word.

The A12X (T8021) is the extreme case: no reference tree in this registry
carries a platform record for it, so its profile records the CPID, the
architecture, and nothing else. It exists so that a device in DFU can be named
and refused rather than attempted, and `make soc-test` enforces the exception —
a stub that acquires a field means somebody found a source and needs to cite
it.

## The SEP interface

**dr1zzle does not run on the application processor. It runs on the SEP**, so
the registry's most important geometry is the one it did not have: until now it
described the AP of every part and the enclave of none. Three fields close that,
per part, where a source establishes them.

| | SEP control window | SEP power word |
|---|---|---|
| t8015 (A11) | **0x243000000 + 0x1000** | 0x232080400 |
| t8020 (A12) | unrecorded | 0x23B080600 |
| t8027 (A12Z) | unrecorded | 0x23B080600 |
| t8030 (A13) | unrecorded | 0x23B080C00 |

The A11 SEP control window is the strongest-sourced address in this registry:
`DeviceTree.d22ap`'s `/arm-io/sep` node gives
`reg = 0x43000000 + 0x1000` with the `aarch64` flag present on `sep` and on
nothing else. Combined with the recorded `gIOBase`, this resolves the SEP
control node at `0x243000000`; it does not by itself resolve the mailbox
resource base or authorize AP writes into protected SEP RAM.

The SEP power word is the other half. It is the PMGR `ps-reg` entry that gates
whether the enclave is powered, and it is the word each part's SecureROM polls
with `(w & 0xf0) == 0xf0` before it will bring the SEP up. It is also the
clearest demonstration that per-part records matter: the A12 and A12Z use
`+0x600`, the A13 uses `+0xc00` in the same plane, and the reference tree is
explicit that copying the A12's word onto the A13 would be wrong.

The A11 AP SecureROM also contains the 8-byte literal `0x243000000` at file
offset `0x1c190`, in a SEP-mail descriptor table. That establishes an
AP-visible aperture base, not FIFO offsets. The independent mailbox census
records accesses in the `0x243008000` window. PongoOS's A11-specific source
derives its mailbox structures from the SEP DeviceTree register and places
control registers at `+0x8100` and message FIFOs at `+0x8800`/`+0x8830`.
These are useful cross-checks, but the project has not captured a complete
hardware request/reply exchange. The old `0x23C000000` value remains
unestablished for A11 and must not be used as a measured base.

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

`rpwn/rust/README.md` lists a "future SoC support" line: s5l8940x, s5l8942x,
s5l8945x, s5l8747x, t7000, t7001, s7002, s8000, s8001, s8003, t8012. Those have
no entry in `device_platform.py`, so there is no geometry to record and no
profile was written for them. t8016 — the other A11 CPID, in the iPhone 8 Plus
and X — is likewise absent from the vendored tool's tables, so it is not
invented here.

pongoOS does carry per-SoC USB register sets for t7000, t7001, s8000, s8001 and
s8003 (A8 through A9X), which would narrow that list — but a register set is
not a platform record, and a profile with a USB block and nothing else is not
a profile anything can build. Those parts stay unrecorded until a source
establishes a full geometry for them.

There is also no A12/A13 device-side adapter here. The usbliter8 tree runs its
own shellcode on an RP2350 and hands the device to a raw iBoot image; it has
nothing a dr1zzle *image* could be loaded with, and this tree has not written
the equivalent for the A10/A11 family either. The profiles exist so the
registry is honest about which parts exist, and so the host tool can refuse an
unsupported one by name.

## Tests

`make soc-test` (tests/test_socs.py) checks the registry against the sources
that are supposed to be authoritative for it:

- every profile defines the whole contract, and `t8015`'s values are unchanged
  from the ones the tree was built against;
- exploit-family fields agree with the checkm8 and usbliter8 reference trees,
  while the T8021 stub is prevented from acquiring unsourced geometry;
- the geometry in each profile matches `rpwn/rust/src/device_platform.rs`, so a
  transcription error in either direction fails the test rather than a device;
- each part's PMGR band contains its own SEP power word — the check that
  caught the A12's wrong `0x20e000000` PMGR, and the reason a profile that is
  self-consistent can still be caught being wrong;
- the SEP fields are carried exactly where a source establishes them, per field
  rather than per profile, so "unrecorded" cannot quietly become zero;
- the DFU trigger matches `rpwn/rust/src/checkm8.rs`'s per-CPID device configuration;
- exactly one profile is payload tier, and it maps every block in
  `SOC_BLK_PAYLOAD`;
- `make SOC=<name>` compiles for the payload tier and is refused, with the
  profile named, for every host-tier profile.

No device is needed for any of it, which is the point: the parts of this
expansion that can be verified without silicon are verified without it.
