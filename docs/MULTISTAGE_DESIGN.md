# dr1zzle Multi-Stage Self-Orchestrating Loader Design

## What changed and why

The payload used to be one flat image that brought up every peripheral and
linked every driver. It outgrew the one placement rule that cannot be
recovered from on the device: `goat kload` (the pwndfu upload path) writes
through a window that must not reach the pwndfu command area at
`0x18001C000` (`goat/usb.py`, `DFU_IMAGE_BASE`). A flat image spanning that
window could not be loaded at all.

The fix is a split, not a compression:

```
┌───────────────────────────────────────────────────────────────────┐
│                        SRAM 0x180000000                           │
├───────────────────────────────────────────────────────────────────┤
│  CORE  (build/a11-payload.elf)                                    │
│  • written by `goat kload` (must stay below 0x18001C000)          │
│  • console, timer, interrupts, NAND, USB + CDC-ECM + TCP, goat    │
│  • a menu: choose a firmware, or receive one over the wire        │
├───────────────────────────────────────────────────────────────────┤
│  STAGING WINDOW 0x180100000 .. 0x1801E8000  (0xE8000 = 950 KB)    │
│  • the goatloader window (GOAT_STAGE_BASE/SIZE on the host)       │
│  • where a pushed container is decrypted and where a NAND         │
│    firmware is copied before it is entered                        │
└───────────────────────────────────────────────────────────────────┘
```

The core never needs to know what a firmware does. It knows where a firmware
lands (its tag, in the staging window), how to check it (magic / CRC), and
how to enter it (jump to `load_base + entry_off`). That is the same contract
the goat container path already used, so the on-NAND format
(`firmware_header_t` + image, `include/firmware.h`) and the goat container
format are one definition, not two that drift.

## The two images

### Core — the bootstrap and menu (`src/core/core_main.c`, `src/core/fw_store.c`)

Bring-up is the same dependency chain `src/main.c` documents, minus the
feature code:

- pmgr, UART, console, timer, AIC/exception, gpio, watchdog
- USB (DWC2) + CDC-ECM + TCP + the goatloader (`goatloader_init`)
- NAND init once; `fw_store_scan()` reads the slot headers

The menu:

- `list` — firmware slots found on NAND
- `run <n>` — copy slot `n` into the staging window, verify CRC, `goat_enter`
- `fw install <n>` — write the staged container into NAND slot `n`
- `goat` / `nand` — status lines
- `reboot`, `help`, `ver`

The menu never blocks on the network: while it waits for a keystroke it also
services `net_poll()`/`goatloader_poll()`, so `goat push --run` can arrive
between menu commands. `goat shell` drives the same command set remotely —
`shell_exec` in the core is the menu dispatcher.

The core linker (`linker/a11.ld`) pins the staging window to
`0x180100000 .. 0x1801E8000` and asserts the core's own `.bss`/heap/stack end
below it. The host tool's `GOAT_STAGE_BASE`/`GOAT_STAGE_SIZE` were *already*
that exact window; the device side used to compute its window dynamically
from wherever `.bss` ended and quietly drifted above `0x180100000`, so every
push was rejected as a placement error. Pinning the linker is what makes the
two definitions equal.

### Firmware — the feature image (`build/firmware/dr1zzle.elf`)

The old full image, linked for the SRAM tail (`linker/firmware.ld`, base
`0x180100000`). It runs the complete monitor shell including the dump
front-end (`dump <target>` over the registry in `src/drivers/dump.c`). It is
entered by the core (`run <n>`) or staged directly (`goat push --run`). It
also paints an on-screen menu into the framebuffer the bootloader left
running — a fixed panel with a reserved output pane below it and a pinned
status line, so command output never scrolls the menu; see
[docs/MENU.md](MENU.md).

The firmware drops the one thing that could not fit after the base moved up:
the MMU translation tables, ~590 KB of `.bss` for a translation regime this
build never enables. `mmu.c` stays in the core, where `tests/test_hw.py`
expects it.

The firmware also carries the other half of the writer: `fw save <slot>`
writes *its own* running image to a slot, so a field upgrade does not need a
host. It is the same `fw_store_install()` the core's `goat install` path calls;
the only difference is where the bytes come from (this image's
`[FW_LOAD_BASE, __firmware_image_end)` instead of a staged container). The
linker defines `__firmware_image_end` so that extent is exactly the `.bin` the
build produced — `tests/test_hw.py` asserts they match, because otherwise the
copy on flash would be truncated or padded and nothing would notice until the
next boot. Because the running image's `.data` may have been initialized at
boot, `goat install` from a sealed container is the pristine path; `fw save`
is the no-host convenience.

Specialization is an extension, not a fork: a firmware is just an image
linked for `0x180100000`. A dumping-only build, a diagnostics build, a
network build are all the same `linker/firmware.ld` with a different source
set and a different header name (`--name`). The menu does not care.

## Storage tiers

| Tier | Medium | Used for |
|------|--------|----------|
| T0 | SRAM, `0x180000000` | core, heap, stack |
| T1 | SRAM tail, `0x180100000` | the staging window / one firmware in flight |
| T2 | NAND, fixed slots from block `0x2000` | persistent firmware store (8 x 1 MB) |
| T3 | USB CDC-ECM/TCP (goatloader) | delivery of firmware and containers |
| T4 | DRAM (future, if initialized) | large runtime buffers |

## Self-orchestration

"Loads the space it needs" in the original plan meant the final payload grew
into whatever memory its loaders could free. The core/firmware split keeps
that property in a form that actually builds:

1. The core is small by construction: features live out of it, so the kload
   window is never the constraint the flat image ran into.
2. Each firmware is self-contained for one kind of work, so the operator
   (or the menu) loads exactly what the task needs, not a superset.
3. A firmware is *entered*, not daisy-chained: the previous image is done.
   Three stages handing off to each other (the old `src/stage1/..3`
   experiment) never linked; one bootstrap handing control to a
   whole-job image is what the tree actually has.

The old `src/stage1/`, `src/stage2/`, `src/stage3/` trees and
`linker/stage{1,2,3}.ld` are retired: they are a half-finished parallel
attempt and are not part of `C_SRCS`. `scripts/build_flash.py` remains as a
host-side image builder but has no runnable stages to feed it.

## Firmware format

`firmware_header_t` (packed, 44 bytes; `include/firmware.h`):

```c
uint32_t magic;        /* FW_MAGIC "DFW1" */
uint16_t version;
uint16_t flags;        /* 0 */
uint64_t load_base;    /* link address, == FW_LOAD_BASE == GOAT_STAGE_BASE */
uint32_t entry_off;    /* entry = load_base + entry_off (== _start offset) */
uint32_t size;         /* image bytes after the header */
uint32_t crc32;        /* IEEE 802.3 (zlib-compatible), over image only */
char     name[16];     /* "dr1zzle", "dump", "diag", ... */
```

`scripts/mkfirmware.py` builds a record from the build artifacts and derives
`entry_off` from the ELF's `e_entry`. `make firmware-record` produces
`build/firmware/dr1zzle.fw`.

## How an image gets onto the device

```sh
# core first (the only pwndfu-size image)
make deploy                       # ./goat/goat kload build/a11-payload.elf

# then the firmware over USB (needs a sealing key, see docs/GOAT.md)
make deploy-firmware KEY_HEX=<hex> [CERT=<goat-key.json>]

# or by hand:
goat seal build/firmware/dr1zzle.bin \
    --cert goat-key.json \
    --key-hex <hex> \
    --load-base 0x180100000 \
    --entry-off 0x1000 \
    --out build/firmware/dr1zzle.g1
goat push build/firmware/dr1zzle.g1 --key-hex <hex> --run

# or seal it straight into a NAND slot, so it survives a reboot:
goat install build/firmware/dr1zzle.g1 --slot 1 --key-hex <hex>
```

At the menu: `list` shows NAND slots, `run <n>` loads one, `fw install <n>`
writes the staged container to a slot. `goat install` does the staging and the
write in one host-side command. A firmware can also write itself with
`fw save <n>` from its own shell.

The two directions onto NAND — host-staged (`goat install`, or `fw install`)
and device-self (`fw save`) — share `fw_store_install()` in
`src/core/fw_store.c`, which erases the slot's blocks, programs every page
with the controller's ECC engine enabled, and reads every page back and
compares it. `goat` over USB (staging + `RUN`) remains the path that does not
touch flash at all.

## Build system

`Makefile` produces two artifacts from one object tree:

- `CORE_C_SRCS` → `build/a11-payload.elf/.bin` (linker/a11.ld)
- `FW_C_SRCS` (= full sources, minus mmu.c) → `build/firmware/dr1zzle.elf/.bin`
  (linker/firmware.ld)
- `all` builds both; `deploy` kloads the core; `firmware-record` builds the
  NAND record; `deploy-firmware` seals + pushes the firmware.

## Testing

- `tests/test_hw.py` — asserts the core's vectors/text layout, bring-up order,
  stack and MMU symbols; the NAND write sequences and write-path exports
  (`TestNandWriter`); and that the firmware's `__firmware_image_end` matches
  its `.bin` (`TestFirmwareImage`). `make` + `python3 tests/test_hw.py`.
- `tests/goat_test.py`, `tests/test_goatloader.py` — container format, the
  staging-window assertions (`__stage_base == 0x180100000`,
  `__stage_limit == 0x1801E8000`), push placement, and the `INSTALL` verb
  (OK / no-stage / out-of-range / store failure).
- `tests/test_phase4.py` — phase-4 regressions.
- `make firmware-record` then re-parse the record: magic, CRC (zlib match),
  `entry_off == 0x1000`.

## Status

- [x] Core links below `0x18001C000` (flat image ends ~0x180011000)
- [x] Staging window pinned to the host constant (`0x180100000`, 0xE8000)
- [x] Firmware builds and fits the window (~0x24000 of 0xE8000)
- [x] `fw_store` scan/read/CRC/enter on the core
- [x] `goat push --run` / `goat shell` reach the core menu
- [x] `dump <target>` front-end in the full firmware
## Status

- [x] Core links below `0x18001C000` (flat image ends ~0x180012000)
- [x] Staging window pinned to the host constant (`0x180100000`, 0xE8000)
- [x] Firmware builds and fits the window (~0x27000 of 0xE8000)
- [x] `fw_store` scan/read/CRC/enter on the core
- [x] `goat push --run` / `goat shell` reach the core menu
- [x] `dump <target>` front-end in the full firmware
- [x] On-screen menu: fixed panel, reserved output pane, `clear` redraw
- [x] Host-side NAND writer (ECC-assisted) for firmware slots
      (`fw_store_install`, `goat install`, core `fw install`)
- [x] Device-self install from the running firmware (`fw save`)
- [ ] Specialized builds (dump-only, diag-only) as extra `--name` firmwares