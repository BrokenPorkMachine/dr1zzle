# Firmware corpus capture

`goat pull` captures device-family **firmware** artifacts from a pwndfu device
into a directory with a self-describing manifest.

```
python3 goat/goat pull --list-targets
python3 goat/goat pwn                 # checkm8 into pwndfu state
python3 goat/goat pull --outdir corpus/<host>-<date>
python3 goat/goat pull securerom dfu-state --skip-unverified
```

## What it captures

| Target | Address | Length | Access |
|---|---|---|---|
| `securerom` | 0x100000000 | 0x100000 | direct |
| `sram` | 0x180000000 | 0x200000 | direct |
| `dfu-state` | 0x18001C000 | 0x40000 | direct |
| `dram` | 0x800000000 | 0x100000 | state |
| `iboot` | 0x800000000 | 0x400000 | state (unverified) |
| `llb` | 0x800000000 | 0x80000 | state (unverified) |
| `sep-mailbox` | 0x23C000000 | 0x10000 | direct |

`access`:

- **direct** — one memcpy read while in pwndfu state.
- **state** — only meaningful once the boot chain has loaded that stage. A
  capture taken in DFU mode reads uninitialised DRAM, which is still valid
  *evidence that DRAM is uninitialised* and nothing more.
- **handshake** — needs a protocol exchange, not a plain read. `seprom` is
  defined but deliberately never captured: there is no documented AP-side read
  address for SEP firmware in this tree, so a capture would be guesswork.

## Provenance

Addresses come from two places, recorded per target in `manifest.json`:

- `rpwn/rust/src/device_platform.rs` — the vendored tool's own t8015 platform entry
  (`rom_base`, `rom_size`, `sram_base`, `sram_size`, `dram_base`,
  `dfu_image_base`).
- `include/memory_map.h` — the A11 map in this tree, for the SEP mailbox
  window.

Targets that rely on a base address but not a documented extent (`iboot`,
`llb`, `seprom`) are marked `unverified` and can be excluded with
`--skip-unverified`. Nothing here invents an address.

## Self-verification

The A11 SecureROM SHA-1 is published and pinned in
`rpwn/rust/src/device_platform.rs`. `pull` captures `securerom` first and compares
the result:

- **Match** — the DFU transport, read path, file write and hashing are all
  correct, so the remaining captures are credible.
- **Mismatch** — the tool prints a warning and the manifest records
  `digest_matches_known: false`. Any other capture from that run should be
  treated as suspect and not compared against a unit you do not have.

This is the only cross-check available offline, which is why it is the first
thing a run does.

## Scope

Firmware and device-family metadata only: images Apple ships on every unit of
a given model/firmware version, plus register windows. There is no identity,
credential, or user-state collection in this path, and adding one is out of
scope for this tree — see `README.md`.

## Manifest

`manifest.json` records format, timestamp, device serial, and per-target:
address, length, captured byte count, SHA-256, source string, unverified
flag, and the SecureROM SHA-1 comparison. Captures are stored alongside as
`<target>.bin`.
