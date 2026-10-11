# dr1zzle A11 payload — hardware/driver task status

The portable monitor now has a separate, tested hardware-profile build:
`make profiles-test`. See [HARDWARE_PROFILES.md](HARDWARE_PROFILES.md) for its
256 KiB/2 MiB budgets and limits. This does not validate the A11 drivers below.

Active A11 build is the root `Makefile` (`src/` tree). The parallel `kernel/`,
`net/`, `lib/`, `drizzle/` trees are not part of that A11 build. Selected portable components are now
integrated into `boards/Makefile` and tested independently.

Verification available from a Mac without a device:
`make -B`, `make phase4-test`, and `python3 tests/test_hw.py`. The test files
assert on both the built artifact and host-side parser/crypto fixtures, so
they catch regressions that a successful compile hides. `tests/test_hw.py`
now also pins the AIC register work (EVENT read, MASK_CLR EOI, `AIC_INFO`
validation, an 8 KiB dispatch table), the peripheral registers (I2C IMASK
clear and revision read, SPI PIN/divider, watchdog counters zeroed), the
timer's masked interrupt output, the F-stays-masked boot exit, and the
`c_main` ordering.

| Task | Status | Evidence |
| --- | --- | --- |
| Goatloader TCP server (port 1234, always on) | Implemented, silicon unverified | `src/goat/loader.c` binds at bring-up; the protocol contract is documented in [GOATLOADER.md](GOATLOADER.md). |
| Pre-configured static IPv4 | Implemented, silicon unverified | `NET_DEFAULT_IPV4` 192.168.42.1/24 (`include/net.h`), installed by `net_configure_static()` in `c_main`; the host tool's default is asserted equal to it. |
| CDC-ECM RX wired to the stack | Implemented, silicon unverified | `cdc_ecm.c` assembles frames (short-packet boundary) and `net_poll()` delivers them; frames were previously received and dropped. |
| Vector table + EL1h entry | Complete | 16 slots x 0x80 = 0x800, 2KB aligned. `tests/test_hw.py::TestVectorTable` (5 tests) checks geometry, B-encoding, and that every branch target lands inside `.text`. |
| MMU identity map + device regions | Complete, off by default | `src/arch/arm64/mmu.c` walks L0->L1->L2->L3 with 4KB pages, maps SRAM executable and MMIO Device-nGnRnE read/write, and rejects conflicting mappings. `mmu_enable()` is separate and gated behind `DR1ZZLE_ENABLE_MMU`. Not yet run on silicon. |
| UART S5L @ 115200 | Complete | TX_EN now set (`UCON=0x3`, was `0x5`); struct pad fixed from 4 words to 2 so UTRSTAT/UTXH/UBRDIV land on their real offsets; UBRDIV=12 at +0x28. Asserted in `TestUartAndTimer`. |
| Timer CNTPCT_EL0 | Complete | Frequency read from `CNTFRQ_EL0` rather than assumed 24MHz; added `timer_wait_reg()` for MMIO polling. |
| Exception handlers Sync/IRQ/FIQ/SError | Complete | All four wired with a real 256-byte frame. Fault dumper prints EC/ESR/FAR/ELR/SP/CPSR. `TestRegisterSaveRestore` (5 tests) checks frame size, no slot collisions, contiguity. |
| IRQ dispatch | Complete | `src/drivers/aic.c` programs the AIC v1 controller (EVENT +0x2004 read-to-ack, MASK_CLR +0x4180 as EOI, TARGET +0x3000) and `irq_handler` now dispatches on the line number the controller reports, sized to the controller's maximum (`irq_handlers`, 8 KiB). DWC2 is claimed on line 324. Unclaimed lines stay masked. Layout grounded in the upstream `irq-apple-aic` driver's `apple,t8015-aic` (v1 + fast IPI) descriptor; `AIC_BASE` itself is unverified, so `aic_init()` validates `AIC_INFO` first and the old polling path remains as a fallback. Asserted in `TestAicInterruptController` (7 tests). |
| PMGR clock gate + reset | Complete, unverified | `src/drivers/pmgr.c`. Bit masks come from the published A11 PMGR node but have not been checked against silicon. GPIO/I2C/SPI/WDT masks are **zero on purpose**: their bit numbers are device-tree information this build does not have, and a guessed mask could gate a device the payload is using. `pmgr ungate <mask>` / `pmgr reset <mask>` exist so an operator can correct that from the shell. `reboot` now uses the watchdog reset and falls back to the PMGR one. |
| GPIO / pinmux | Implemented, unverified | `src/drivers/gpio.c`. One 32-bit config word per pin: DATA +0x0, MODE 3:1, PERIPH 6:5, PULL 8:7, INPUT_ENABLE +9 (layout from the upstream Apple pinctrl driver). Function select clears the mode first so a pin does not glitch while the mux changes. Pins past `GPIO_MAX_PINS` are refused rather than written to. |
| I2C master | Implemented, unverified | `src/drivers/i2c.c` drives the PA Semi PWRficient SMBus block that `apple,t8015-i2c` binds to. Command FIFO at +0x00, status +0x14, control +0x1c, revision +0x28; divider = ceil(ref / (16 * hz)) clamped to 4..255; interrupt masked at init; every failure path resets the FIFOs. Reference clock is an assumption and the computed divider is printed so it can be checked against a scope. |
| SPI master | Implemented, unverified | `src/drivers/spi.c` drives the Apple SPI block polled (MODE_POLLED, 8-bit words, FIFO depth 16). Reset FIFOs, program TXCNT/RXCNT, prime, RUN, then service both FIFOs by level until the word count is done. `spi id` reads the JEDEC RDID. |
| Watchdog | Implemented, unverified | `src/drivers/watchdog.c` disarms WD0/WD1/WD2 at init (an armed watchdog the boot firmware left running resets the device while a transfer waits, which looks like a bus fault), then arms WD1 on request. `wdog arm <s>` / `kick` / `disarm`. |
| USB PHY | Complete, unverified | `usb_phy_init()` unlocks, enables, and polls STATUS_READY with a 100ms timeout. Register map assumed. |
| DWC2 device core init | Complete | Full core/fifo reset with AHBIDLE wait, forced device mode, FIFO sizes programmed, EP0 + EP1 interrupt IN + EP2 bulk IN/OUT configured, DAINT/DIEPMSK/DOEPMSK/GINTMSK set. |
| CDC-ECM descriptors + control | Complete | Descriptors present. Standard + class requests handled. `SET_ADDRESS` is now deferred to the IN-completion path (was applied during the setup packet, which drops enumeration). |
| CDC-ECM data path | Partial | `cdc_ecm.c` has RX/TX rings and bulk framing. The Ethernet/ARP/IP stack in `net/` is not wired to it; `usb_cdc_last_frame()` is the only consumer. |
| NAND controller + page reader | Implemented, unverified | `src/drivers/nand.c` performs reset, ID validation, row/column page reads, controller ECC status handling, bad-block checks, and bounded page-sink dumps. The A11 register/geometry profile still needs silicon confirmation. |
| BCH-8 page validation | Implemented conservatively | `nand_bch8_check()` validates erased-page ECC framing and refuses to claim correction without a controller correction status; a captured non-erased page is reported uncorrectable until the A11 BCH layout is verified. |
| APFS container/volume reader | Implemented, host-tested | `src/fs/apfs.c` parses NXSB/APSB, verifies object checksums, walks variable-key/value B-tree nodes, decodes extents, and streams file extents through a callback. OMAP virtual-OID resolution and pathname lookup remain an explicit follow-up. |
| AES/GID engine | Implemented, hardware unverified | `src/drivers/aes.c` provides bounded hardware block transactions plus AES-256-CBC software vectors. GID/UID material stays in hardware; `aes test` does not print secret-derived bytes. |
| KBAG parser + GID check | Implemented, hardware unverified | `src/research/keybag.c` accepts DER and fixed-width KBAG records, validates bounds/class/lengths, and reports metadata plus internal GID-check status. Secret plaintext is deliberately withheld from UART. |
| Shell | Complete | `help`, `memdump`, `memwrite`, `time`, `reboot`, `usb`, `irqstat`, plus the research commands. Phase 3 peripherals each have a command group: `gpio read|set|in|out|func|raw`, `i2c status|scan|read|wr|write|speed`, `spi status|id|xfer|speed|cs`, `wdog status|arm|kick|disarm`, `irq stat|list|map`, `pmgr status|gate|ungate|reset`. |

## Bugs fixed in this pass

Each of these compiled cleanly before and would have failed on hardware:

1. **`start.S` vector table was 0x784 bytes** — 15.03 slots instead of 16, and
   not 2KB aligned as `VBAR_EL1` requires.
2. **`SAVE_REGS` wrote to `[sp,#224]` in a 128-byte frame**, and reused slots
   `#10` and `#11` for two register pairs each. x20-x27 were clobbered on
   every single exception.
3. **`SP` was never loaded** and `.bss` was never zeroed before the first C
   call.
4. **`c_main` re-ran `mmu_init`, `uart_early_init`, and `usb_init`** which
   `start.S` had already called. DWC2 cannot survive a second `GRSTCTL.CSRST`.
5. **`MMU` mapped nothing.** The old table indexed L0 by `vaddr >> 39`, so
   index 0 covered `0..0x80000000` while SRAM sits at `0x180000000`.
6. **`UART UCON = 0x5`** (RX_EN|RX_ERR) — TX_EN was never set, so `uart_putc`
   would spin forever on a TX-empty bit the transmitter could not raise.
7. **`UART` struct had 4 pad words where the map needs 2**, putting UTRSTAT
   at +0x20 instead of +0x18, UTXH at +0x28 instead of +0x20, UBRDIV at +0x30
   instead of +0x28.
8. **`usb.c` defined the same ~20 constants 9 times over**, and OR'd
   `GUSBCFG_TOUTCAL_7` with `GUSBCFG_USBTRDTIM_5` — overlapping fields.
9. **`usb.c` never programmed `GRXFSIZ`/`GNPTXFSIZ`** and never set device
   mode via `GOTGCTL.CMODE`.
10. **`usb.c` called `usb_cdc_rx()` and `usb_cdc_tx_pending()`**, which did
    not exist. It would not have linked had the stubs not been masking it.
11. **`reboot` branched to `0x100000000`** (SecureROM base) instead of
    resetting anything.
12. **`timer_now_us()` divided by a hardcoded 24** regardless of the actual
    `CNTFRQ_EL0`.
13. **`timer_init()` enabled the timer *interrupt*** (`CNTP_CTL_EL0 = 1`).
    On this part the ARM generic timers are delivered as FIQs that bypass
    the AIC, so a comparator the boot firmware left programmed landed in
    `fiq_handler()`, which halts the payload. It now writes 3
    (ENABLE | IMASK); nothing here wants a timer interrupt.
14. **`start.S` unmasked F as well as I** (`daifclr, #3`). Every FIQ source
    on this SoC — fast IPIs, the generic timers, the performance monitors —
    is either unused or masked by its driver, and none has a handler that
    can run. Only I is cleared now.
15. **`reboot` asserted and released 0xffffffff** on the PMGR. It now uses
    the documented watchdog reset and only falls back to the blanket PMGR
    pulse, which is a last resort rather than a first choice.

### What is still true of this pass

Every peripheral above is *implemented and unverified*. Nothing in it has
run on an A11: the register layouts are grounded in published reference
drivers (upstream `irq-apple-aic`, `pinctrl-apple-gpio`,
`i2c-pasemi-core`, `spi-apple`, `apple_wdt`), not in an A11 datasheet, and
the base addresses come from `memory_map.h`. Two things make that
survivable here: peripheral init never stops the boot (a dead I2C bus must
not cost the operator the shell), and every block has a shell command that
prints what it actually read back, so the first failed transfer on silicon
is diagnosable from the shell instead of from a debugger.

## Not done

- ACE2, the A11 WiFi radio transport, and silicon verification of the NAND/AES
  register maps remain hardware-specific work. Public D22AP data identifies the radio as BCM4357 over an Apple
  PCIe/UART control path; the portable tree has a tested WiFi state/link driver
  in `net/wifi.c`, but it still requires the controller sequence, firmware,
  calibration payload, and hardware verification before it can associate.
  iPhemeral's `WifiSdio` is a synthetic CMD52/CMD53 test model and is explicitly
  not A11 silicon.
- SSH/SCP is not present. A standards-compliant server needs a host-key store,
  secure key exchange, authenticated user database, encrypted transport, and a
  file service. The current QEMU profile has no network device, so an SSH
  server cannot be honestly verified there. What is present instead is the
  plaintext goatloader ([GOATLOADER.md](GOATLOADER.md)): a different trust
  model, acceptable for now only because the CDC-ECM link is point-to-point.
- Ethernet/ARP/IP wired to the CDC-ECM RX path. (Done for the `src/` build:
  `cdc_ecm.c` assembles frames and `net_poll()` delivers them; not silicon
  verified.).
- APFS OMAP translation and full pathname-to-inode traversal are not yet wired
  to the NAND adapter; the current `apfs scan` command intentionally stops at
  verified container/volume metadata and extent primitives.
- `net/` and `kernel/` trees are unintegrated duplicates of work in `src/`.
- Nothing has been run on an A11. Every "unverified" marker above is real.

## QEMU

`scripts/run-qemu.sh` runs the portable QEMU monitor on `virt` with PL011
UART and an optional `ramfb` display. The separate A11 payload still cannot
run correctly on `virt`: it needs Apple S5L UART and other MMIO devices that
QEMU does not emulate.

## Specified, not implemented

[SPEC.md](../SPEC.md) v2.0 adds the remote-instrument capability: dumps as
framed, checksummed streams, CPU register snapshots, and SSH/SCP on TCP 443.
The specification is complete; the code is not started. Status of each piece:

| Piece | Spec | Code | Notes |
| --- | --- | --- | --- |
| Dump source registry | [SPEC.md](../SPEC.md) §5.1 | partial | `src/drivers/dump.c` has the target table; it gains `id`, `kind`, `flags` and a read callback |
| `DZ1` container, chunk records, CRC32, trailer | [DUMP_WIRE_FORMAT.md](DUMP_WIRE_FORMAT.md) §1-3 | none | ~400 lines plus a CRC table |
| `DZREGS1` snapshot record | [DUMP_WIRE_FORMAT.md](DUMP_WIRE_FORMAT.md) §4 | none | reuses the 256-byte frame `SAVE_REGS` already writes |
| SRAM-staged snapshot on fault | [SPEC.md](../SPEC.md) §6.4 | none | `exception.c` currently prints and halts |
| Link abstraction and selection | [TRANSPORT.md](TRANSPORT.md) §1 | none | USB backend exists inside `src/net/tcp.c` |
| `net_recv_frame` wired to CDC-ECM | [TRANSPORT.md](TRANSPORT.md) §1 | **missing** | `cdc_ecm.c` receives frames and the IPv4 path never sees them |
| Windowed TCP sender | [TRANSPORT.md](TRANSPORT.md) §3 | none | current stack is stop-and-wait, 492 B per RTT |
| Stream scheduler | [TRANSPORT.md](TRANSPORT.md) §5 | none | cooperative job advanced from `net_poll()` |
| SHA-512, X25519, Ed25519, ChaCha20, Poly1305, HMAC | [SSH_SCP_443.md](SSH_SCP_443.md) §6 | none | ~1,300 lines, all host-testable against RFC vectors |
| SSH transport, connection, channels | [SSH_SCP_443.md](SSH_SCP_443.md) §4, §7 | none | |
| SFTP v3 + legacy SCP over the registry | [SSH_SCP_443.md](SSH_SCP_443.md) §7.2, §7.3 | none | read-only; upload is refused by design |
| Console input refactor for session channels | [SSH_SCP_443.md](SSH_SCP_443.md) §8 | none | separate `execute()` from the `uart_getc()` loop |

The first block of work is the crypto primitives: they are the only part that
can be written and verified against published vectors with no silicon and no
network device, and everything in the SSH stack waits on them.
