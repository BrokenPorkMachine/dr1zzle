# dr1zzle — Technical Specification

**Version:** 2.0
**Supersedes:** 1.0 (A11 Research Payload — Technical Specification)
**Classification:** Private / Proprietary
**Target:** Apple A11 (T8015) — iPhone 8 / iPhone X, plus the portable QEMU `virt` monitor
**Entry Point:** checkm8 (DFU) → payload upload via DFU DNLOAD
**Host Interfaces:** USB CDC-ECM (TCP/IP) primary, Wi-Fi (BCM4357) planned, UART fallback
**Remote Access:** SSH-2 + SCP/SFTP on TCP 443

---

## 1. Scope

### 1.1 What this document is

This is the master specification for dr1zzle. Version 1.0 described a
research payload with a command list. Version 2.0 describes the same
payload as a *remote instrument*: something that can be driven from a normal
SSH client, that hands over firmware images, memory images and CPU state as
verifiable byte streams, and that does so over whichever TCP/IP link is
attached.

The three capabilities this version adds, and the documents that specify them
in byte-level detail:

| Capability | Spec |
|---|---|
| Firmware, memory and register dumps as a framed, checksummed stream | [docs/DUMP_WIRE_FORMAT.md](docs/DUMP_WIRE_FORMAT.md) |
| CPU register state and fault snapshots | [docs/DUMP_WIRE_FORMAT.md](docs/DUMP_WIRE_FORMAT.md) §4 |
| SSH-2 / SCP / SFTP on port 443 | [docs/SSH_SCP_443.md](docs/SSH_SCP_443.md) |
| Link selection, TCP behaviour, stream scheduling | [docs/TRANSPORT.md](docs/TRANSPORT.md) |

### 1.2 Core capabilities

| Category | Features |
|----------|----------|
| **Firmware dumps** | SecureROM, iBoot, LLB, kernelcache, NAND (raw + APFS-extracted), SEP image, baseband — each a named source with a base, a length and an honest readiness status |
| **Memory dumps** | SRAM, DRAM, MMIO register windows; bounded hex for humans, unbounded binary for machines |
| **CPU state** | Full exception frame (x0–x30, SP, ELR, SPSR, ESR, FAR, TPIDR) plus a versioned system-register list; captured on demand or automatically on a fault, staged in SRAM so it survives a halt |
| **Transport** | USB CDC-ECM today; Wi-Fi (BCM4357) as a link contract; one TCP/IP stack, one link selector |
| **Remote access** | SSH-2 transport (X25519, Ed25519 host key, ChaCha20-Poly1305), public-key auth, a session channel wired to the existing monitor console, an SFTP subsystem and legacy SCP, all on TCP 443 |
| **Integrity** | Per-chunk CRC32 and a whole-stream SHA-256, so a 128 MB transfer over a lossy link is verifiable rather than merely plausible |
| **Console** | UART, framebuffer raster console, and a TCP session are three sinks over one command loop — not three implementations that agree |
| **Determinism** | Cycle-accurate timing API from `CNTFRQ_EL0`, µs-precision delays, IRQ latency measured rather than assumed |

### 1.3 Non-goals

- An exploit delivery mechanism, device restore, or any signing bypass. The
  payload is uploaded by a separate tool; dr1zzle does not contain or invoke
  it ([docs/CLEAN_ROOM.md](docs/CLEAN_ROOM.md)).
- Printing GID/UID-derived key bytes to a console or to an unauthenticated
  stream. See §5.5 — this is a policy, not an omission.
- TLS. Port 443 carries SSH directly. There is no TLS record layer, and none
  is planned: SSH already provides confidentiality, integrity and server
  authentication, and layering TLS underneath it would add a second trust
  store to get nothing.
- Full iOS userspace interaction. Kernel-level only.
- Graphical output. Headless, with a framebuffer console for diagnostics.

---

## 2. Hardware platform

### 2.1 Target SoC

| Parameter | Value |
|-----------|-------|
| **SoC** | T8015 (A11 Bionic) |
| **CPU** | 2× Monsoon (perf) + 4× Mistral (eff) — ARMv8.3-A |
| **RAM** | LPDDR4X — 2/3 GB (payload runs in SRAM) |
| **SRAM** | 0x1800_00000 — 0x1801_E8000 (1.9 MB, `0x1E8000`) |
| **SecureROM** | 0x1000_00000 — 0x1010_0000 (1 MB) |
| **NAND** | NVMe-like controller at 0x2000_00000 |
| **USB** | DWC2 OTG (device) + ACE2 (host) |
| **Wi-Fi** | Broadcom BCM4357 ("herculese"), Apple PCIe + UART control path |
| **SEP** | ARMv7-A (S5L8960X) — separate CPU behind the ASC mailbox |

### 2.2 Memory map

```c
#define SRAM_BASE           0x180000000ULL
#define SRAM_SIZE           0x1E8000ULL

#define SECURE_ROM_BASE     0x100000000ULL
#define SECURE_ROM_SIZE     0x100000ULL

#define UART_BASE           0x20A0C0000ULL
#define TIMER_BASE          0x20E100000ULL
#define AIC_BASE            0x232100000ULL
#define PMGR_BASE           0x232000000ULL
#define MAILBOX_BASE        0x23C000000ULL
#define DCP_BASE            0x235000000ULL
#define NOR_BASE            0x240000000ULL
#define BLOCK_BASE          0x241000000ULL
#define NAND_BASE           0x200000000ULL
#define USB_BASE            0x250000000ULL
#define WATCHDOG_BASE       0x2352B0000ULL
#define GPIO_BASE           0x20A100000ULL
#define I2C_BASE            0x20A200000ULL
#define SPI_BASE            0x20A400000ULL
#define PMU_BASE            0x20A000000ULL
#define SPMI_BASE           0x20A300000ULL
#define THERMAL_BASE        0x20A700000ULL
#define USB_PHY_BASE        0x20A1A0000ULL
#define USB_MUX_BASE        0x20A1A1000ULL
#define USB_PD_BASE         0x20A1A2000ULL
#define PANEL_BASE          0x20A110000ULL
#define DSI_PHY_BASE        0x20A120000ULL
#define RASTER_BASE         0x20A130000ULL
#define TOUCH_BASE          0x20A140000ULL
#define AUDIO_BASE          0x20A150000ULL
#define BT_BASE             0x20A160000ULL
#define WIFI_BASE           0x20A170000ULL
#define CAMERA_BASE         0x20A180000ULL
#define SENSORHUB_BASE      0x20A190000ULL
#define ACE2_BASE           0x230000000ULL
#define ACE2_SIZE           0x10000ULL
```

Addresses are from published device-tree values and are **unverified against
silicon**. Every driver that touches a window fails closed when the window
does not answer, and every driver has a shell command that prints what it
actually read back. That combination is what makes a first failed transfer on
real hardware diagnosable without a debugger.

### 2.3 SRAM allocation

| Region | Address | Size | Owner |
|---|---|---|---|
| Vector table | `SRAM_BASE + 0x0000` | 0x800 | `start.S` |
| `.text` / `.rodata` | `SRAM_BASE + 0x0800` | — | linker |
| `.bss` | — | — | linker |
| Heap | — | 64 KiB | `util.c` |
| Stack | — | 16 KiB | `start.S` |
| IRQ dispatch table | — | 8 KiB | `exception.c` |
| **CPU snapshot** | to be reserved | 2 KiB | `exception.c` (§6) |
| **DZ1 chunk buffer** | — | 16 KiB | `stream.c` (§5.3) |
| **SSH state** | — | ~4 KiB | `ssh.c` (§8.5) |
| Goat staging window | 0x1801_00000 | 0xE8000 | `goat` |

The snapshot region does not exist in the linker script yet, and adding it is
blocked on a layout problem this specification surfaces rather than creates:
see §2.4.

The additions this version introduces are budgeted against real free space
rather than hoped for — but the space does not exist until §2.4 is fixed, so
the arithmetic, and the reason it currently cannot be spent, are in §10.

### 2.4 A layout problem this specification surfaced

The default build's `.bss` runs from `0x1800_18000` to `0x1801_17494`, and
`GOAT_STAGE_BASE` is `0x1801_00000`. The goat staging window therefore already
sits inside `.bss`.

The cause is `src/arch/arm64/mmu.c`: it statically allocates 622 KiB of
translation tables (`128 × 512 × 8` bytes of L3 tables alone) whether or not
the MMU is ever enabled, and the MMU is **off by default**. Those bytes are
`NOLOAD`, so they cost nothing in the flat image and 622 KiB of SRAM at
runtime.

Consequences, in order of severity:

1. A staged goat container at `0x1801_00000` overwrites the L3 translation
   tables. Harmless today only because the MMU is off; corrupt the moment
   `DR1ZZLE_ENABLE_MMU` and `goat` are used together.
2. There is no free SRAM below `0x1801_00000` to place the 2 KiB snapshot
   region this version needs, so the linker cannot reserve it without first
   freeing the tables.

Both are fixed by gating the page-table declarations behind
`DR1ZZLE_ENABLE_MMU` — about a dozen lines — which frees 622 KiB and drops
`.bss` back to ~431 KiB. That is deliberately **not** done here: it changes
existing behaviour, and `tests/test_hw.py` disassembles `mmu_init` out of the
default build, so gating it to an opt-in macro breaks the suite as it stands.
It is recorded as a prerequisite instead, which is why the snapshot region is
specified in §6.4 and not yet present in
[`linker/a11.ld`](linker/a11.ld).

---

## 3. Boot flow

### 3.1 Entry conditions

```
Register state at _start:
  x0 = device tree pointer (0 if none)
  EL = EL1h
  MMU = Off
  Caches = Off
  VBAR_EL1 = 0
  DAIF = all masked
```

### 3.2 Initialisation sequence

```
 1. Mask DAIF
 2. Load SP from _stack_top, zero .bss
 3. Clear SCTLR_EL1.M/C/I/A, install VBAR_EL1 → vector table
 4. Enable CNTPCT_EL0 / CNTV_CTL_EL0 (masked interrupts)
 5. Publish the device tree pointer to g_boot_dtb
 6. c_main():
      pmgr_init()          clocks and resets, first
      uart_early_init()    the console; everything after reports here
      console_init()
      timer_init()
      exception_init()     AIC v1
      gpio_init()
      i2c_init() / spi_init()
      watchdog_init()      disarmed on purpose
      usb_init()           DWC2 device mode, CDC-ECM
      display_probe_device_tree(g_boot_dtb)
 7. net_init() + link registration + listeners (443, optionally 23)
 8. daifclr #2 (I only, never F)
 9. shell_run()
```

The order is a dependency chain, not a list of peers: a peripheral that is
still gated off or still muxed to the bootloader's choice will not respond
to a correct transfer. Every peripheral init is allowed to fail without
stopping the payload — a dead I2C bus must not cost the operator the shell
that would have explained why.

### 3.3 Vector table

16 slots of 0x80, 2 KiB aligned, `.org 0x800`. Sync/IRQ/FIQ/SError all
branch to `_sync_el1h` / `_irq_el1h` / `_fiq_el1h` / `_serror_el1h`, each of
which runs `SAVE_REGS` (a 256-byte frame, slot *n* at `[sp, #n*16]`, x30 at
`#240`) before entering C.

---

## 4. Architecture

```
                 ┌──────────────────────────────────────────┐
   UART ────────▶│ console: one loop, N sinks               │
   framebuffer ──│   execute(line)                          │
   SSH channel ──└───────────────┬──────────────────────────┘
                                 │
              ┌──────────────────┼───────────────────┐
              ▼                  ▼                   ▼
        dump registry      CPU snapshot          driver commands
              │                  │                   │
              └────────┬─────────┴───────────────────┘
                       ▼
              DZ1 chunker (stream.c)
                       │
              tcp_send()  ── windowed sender (§7.2)
                       │
              link_send_frame() ──▶ usb-cdc-ecm | wifi-bcm4357
```

Two structural rules, both already true of the code this version extends:

1. **One command loop.** `execute(char *line)` in `src/shell/shell.c` takes a
   line and writes to `uart_puts`. The v2.0 change is that the sink becomes a
   console sink rather than the UART, so an SSH session runs the identical
   code path. A command that works over UART works over SSH, and a command
   that is missing from `help` is missing for both.
2. **Sources are data, not code paths.** A dump target is a registry entry
   with a read callback. Adding NAND or a SEP image does not add a code path
   to the shell; it adds an entry and a callback.

---

## 5. Dump subsystem

### 5.1 The registry

Every dumpable thing is a source. A source answers four questions: what is
your id, how long are you, can you be read right now, and where do your bytes
come from.

```c
typedef enum {
    DUMP_KIND_MEMORY = 0,   /* physical range, identity-mapped read      */
    DUMP_KIND_MMIO,         /* register window                           */
    DUMP_KIND_FIRMWARE,     /* named image: SecureROM, iBoot, kernelcache */
    DUMP_KIND_NAND,         /* flash pages via the controller            */
    DUMP_KIND_FILE,         /* APFS-extracted file                       */
    DUMP_KIND_CPU,          /* register snapshot record (not a byte range) */
} dump_kind_t;

typedef enum {
    DUMP_READY = 0,      /* readable now                                   */
    DUMP_UNVERIFIED = 1, /* published guess at base/geometry; readable, may fault */
    DUMP_NO_DRIVER = 2,  /* waits on silicon-verified registers or a key   */
} dump_status_t;

typedef int (*dump_read_fn)(uint64_t offset, uint8_t *out, uint32_t len,
                            void *ctx);

typedef struct {
    const char   *name;
    const char   *desc;
    const char   *depends;      /* what a NO_DRIVER entry waits on */
    uint32_t      id;
    uint8_t       kind;
    uint8_t       status;
    uint8_t       flags;        /* DUMP_FLAG_SECRET, ... */
    uint16_t      reserved;
    uint64_t      base;
    uint64_t      length;
    dump_read_fn  read;         /* 0 only for a source with no bytes to read */
    void         *ctx;
} dump_source_t;
```

`dump_read` is the whole contract. For `DUMP_KIND_MEMORY` the default
callback is a straight read through the identity mapping; everything else
supplies its own. The chunker in §5.3 never knows or cares which kind it is
streaming, which is why a SecureROM dump and a 4 KiB NAND page use the same
framing, the same CRC and the same digest.

`DUMP_FLAG_SECRET` marks sources whose bytes are key material. It changes
authorisation and reporting, never framing — see §5.5.

### 5.2 Built-in sources

| Name | Kind | Base | Length | Status |
|---|---|---|---|---|
| `sram` | memory | 0x180000000 | 0x1E8000 | ready |
| `securerom` | firmware | 0x100000000 | 0x100000 | ready |
| `nandregs` | mmio | 0x200000000 | 0x1000 | ready |
| `pmgr` | mmio | 0x232000000 | 0x1000 | ready |
| `dwc2` | mmio | 0x250000000 | 0x1000 | ready |
| `aic` | mmio | 0x232100000 | 0x1000 | ready |
| `ace2` | mmio | 0x230000000 | 0x1000 | ready |
| `mailbox` | mmio | 0x23C000000 | 0x1000 | ready |
| `sepos` | firmware | — | — | needs-driver (SEP mailbox dump protocol) |
| `dram` | memory | 0x800000000 | 0x80000000 | unverified |
| `iboot` | firmware | 0x800000000 | 0x400000 | unverified |
| `llb` | firmware | 0x800000000 | 0x80000 | unverified |
| `kernelcache` | firmware | 0x800000000 | 0x2000000 | unverified |
| `nand` | nand | — | geometry | unverified (register map) |
| `nandbad` | nand | — | — | unverified |
| `apfs` | file | — | — | unverified (needs OMAP resolution) |
| `baseband` | firmware | — | — | needs-driver (attach + address map) |
| `panic` | memory | — | — | needs-driver (panic block address) |
| `gid` / `uid` | firmware | — | — | **secret**, needs-driver (silicon AES path) |
| `keybag` | firmware | — | — | **secret**, needs-driver (AES + GID) |
| `img4` | firmware | — | — | needs-driver (IMG4 parser + NAND read) |
| `regs` | cpu | — | 2 KiB record | ready |

The status column is the point of the table. A source that is not `ready`
either says what it is waiting on (`depends`) or says that its geometry is a
published guess. No source is presented as working because it might.

`dump list` prints exactly this table with the status word spelled out, so
the shell cannot disagree with the registry.

### 5.3 The stream

`dump stream <source> [chunk]` starts a job. Default chunk 4096 bytes, max
16384. The job:

1. reads one chunk through `source->read()` into a 16 KiB staging buffer;
2. accumulates a streaming SHA-256 (`goat_sha256`, already in the tree);
3. emits a chunk record: magic, sequence, offset, length, CRC32, data;
4. hands the record to `tcp_send()`;
5. stops when `source->length` bytes have been emitted, then writes the
   trailer with the completion code and the whole-payload digest;
6. prints one progress line per megabyte to the invoking console, so a long
   transfer over a link that has gone quiet can be told from a hung one.

Framing, field widths, the resume protocol and the completion codes are in
[docs/DUMP_WIRE_FORMAT.md](docs/DUMP_WIRE_FORMAT.md).

Three properties the stream must have, each of which the current code gets
wrong in a way worth naming:

- **Sparse collapse is a console feature, not a stream feature.** `dump_run()`
  in `src/drivers/dump.c` collapses runs of identical 16-byte rows to `*`.
  That is right for a human reading a megabyte of padding and wrong for a
  receiver that has to reassemble the image. The binary stream emits every
  byte; the `*` exists only on the hex path.
- **Hex output is capped, binary is not, and the two caps are different
  numbers for a reason.** `DUMP_MAX_LENGTH` (1 MiB) bounds the hex path
  because nobody reads more than that in a terminal. The binary path is
  bounded by `source->length` and by the link, and a 128 MB NAND dump is the
  normal case for it.
- **Secret sources stream only to a secret-cleared session.** See §5.5.

### 5.4 Existing console path

`dump <target>`, `dump digest <target>` and `dump find <pattern>` keep their
current semantics: hex to the console, `DUMP_MAX_LENGTH` clamp, progress
every 4 KiB. They are the human view of the same sources, and they remain the
fastest way to sanity-check a window before committing to a stream.

Serializer note: the console path and the stream path share the source
registry and the digest code, and share nothing else. They do not share
output code, because a hex row and a length-prefixed chunk record have no
common formatting step worth abstracting.

### 5.5 Secret material policy

Three sources are flagged secret: `gid`, `uid`, `keybag`. The rule is one
sentence: **a secret source never writes to an unauthenticated sink, and
never writes to a console that a person might be filming.**

Concretely:

| Sink | Secret source behaviour |
|---|---|
| UART console | refused, with the reason printed |
| Framebuffer console | refused, with the reason printed |
| TCP console (legacy port 23) | refused, port 23 has no authentication |
| SSH session, public-key authenticated | allowed, after an explicit `confirm` |
| SSH session, password authenticated | allowed only if `ssh allow-secret on` is set |

Two reasons this is stricter than it needs to be to keep keys off a screen,
and both are deliberate. First, a key dumped to a framebuffer that the boot
firmware left scanning out is a key on a display that is easier to photograph
than a serial log. Second, an unauthenticated TCP console that can emit GID
material is an exfiltration path that needs no exploit at all — anyone who
can reach the link owns the keys.

The stream itself is unchanged: a secret source is framed, CRC'd and digest'd
like any other, and the host-side verifier cannot tell it apart. Only the
authorisation gate and the reporting differ.

---

## 6. CPU register state and snapshots

### 6.1 Why snapshots are a first-class feature

A bare-metal payload that faults has one chance to tell you what happened.
`src/arch/arm64/exception.c` already prints EC/ESR/FAR/ELR/SP/CPSR and halts,
which is enough to *classify* a fault and not enough to *diagnose* one: no
general registers, no system registers, no timestamp, and nothing that
survives the halt for a later pull over the network.

The snapshot record fixes both halves. It is captured at the moment of the
fault into a fixed SRAM address, so it can be streamed after the fact over
SSH even though the CPU is spinning in a `wfe` loop.

### 6.2 What is captured

**The exception frame.** `SAVE_REGS` in `start.S` already stores all 31
general registers in a 256-byte frame, slot *n* at `[sp, #n*16]`, x30 at
`#240`. The snapshot copies that frame verbatim. No new save path is needed,
which is the point: the record is the frame the fault handler already has.

**System registers.** A versioned, extensible list of `(id, value)` pairs
rather than a fixed struct, so a new register does not invalidate every
existing capture file:

| Id | Register | Notes |
|----|----------|-------|
| 0x0001 | `elr_el1` | faulting PC |
| 0x0002 | `spsr_el1` | |
| 0x0003 | `esr_el1` | |
| 0x0004 | `far_el1` | |
| 0x0005 | `sp_el1` | |
| 0x0006 | `tpidr_el1` | |
| 0x0010 | `vbar_el1` | confirms the vectors are ours |
| 0x0011 | `sctlr_el1` | MMU/cache state at fault time |
| 0x0012 | `ttbr0_el1` | |
| 0x0013 | `ttbr1_el1` | |
| 0x0014 | `tcr_el1` | |
| 0x0015 | `mair_el1` | |
| 0x0020 | `currentel` | |
| 0x0021 | `midr_el1` | identifies Monsoon vs Mistral |
| 0x0022 | `mpidr_el1` | which core took the fault |
| 0x0023 | `cpacr_el1` | |
| 0x0030 | `cntfrq_el0` | timer frequency, from hardware not assumption |
| 0x0031 | `cntpct_el0` | cycle timestamp |
| 0x0032 | `daif` | |
| 0x0033 | `nzcv` | |
| 0x0040 | `pmgr_clock_state` | gate status, MMIO read |
| 0x0041 | `aic_event` | last controller event, if the AIC is up |

**Timestamps.** `CNTPCT_EL0` raw cycles and `timer_now_us()` together, so a
capture can be correlated with host-side logs without knowing the frequency.

**Trigger.** Which of these produced the capture: on-demand (`regs snapshot`),
sync fault, SError, FIQ, or watchdog.

### 6.3 Scope, stated plainly

One snapshot, one core. `MPIDR_EL1` records which core it was. Capturing
another core's registers would require stopping that core — an IPI or a
forced exception entry — and on this payload the other cores are either idle
in `wfe` or running firmware code this build does not own. Freezing them to
read state they were not asked about risks corrupting whatever they are
doing. So the snapshot is "the state of the core that called it", which is
also exactly the core that faulted.

FIQ snapshots are lower priority than the others: `fiq_handler()` halts the
payload, and every FIQ source on this SoC is masked or unused, so a FIQ
snapshot is a record of a bug rather than a diagnostic.

### 6.4 Where it lives and how it is read

The record is staged in a 2 KiB NOLOAD window above the heap and stack and
clear of the goat staging window — to be reserved in
[`linker/a11.ld`](linker/a11.ld) as `_snapshot_base` once the layout problem
in §2.4 is resolved, which is why the symbol is named here and does not exist
in the script yet. On capture, the record is written there *and* reported to
the console. Reads go through the normal source mechanism: `dump regs`
streams the record as a `DUMP_KIND_CPU` source, so it is pulled over SFTP
like anything else. The fault handler therefore does not need the network to
be up at the moment of the fault — it needs the network to be up later.

`regs show` prints the same record as text for the UART case. `regs snapshot
nostage` captures without writing the staging window, which is the case where
you want the text and not the SRAM footprint. `regs clear` invalidates the
staged record so a later reader cannot mistake a stale capture for a current
one.

### 6.5 Wire format

`DZREGS1` — header, then the 256-byte frame, then the system-register list.
Field widths, the id table and the digest are specified in
[docs/DUMP_WIRE_FORMAT.md](docs/DUMP_WIRE_FORMAT.md) §4.

---

## 7. Transport

Full specification in [docs/TRANSPORT.md](docs/TRANSPORT.md). Summary and
requirements:

### 7.1 Links

One TCP/IP stack, one link selector, two candidate links:

| Link | Status | Notes |
|---|---|---|
| `usb-cdc-ecm` | implemented, unverified | 192.168.42.1/24, point-to-point, no ARP needed in principle |

The address is a pre-configured constant, installed by `net_configure_static()`
during bring-up, and it is the address the goatloader listener is bound to
(§7.5). The host tool defaults to the same number, so neither end needs to be
told anything for a connection to work.
| `wifi-bcm4357` | contract only | needs the PCIe/UART backend, firmware and calibration documented in [WIFI.md](docs/WIFI.md) |

`link_send_frame()` replaces the direct `usb_send()` call inside
`net_send_frame()`. A link is only selected when it reports up; `auto` never
guesses and names the link it chose.

### 7.2 TCP changes required for bulk

`src/net/tcp.c` is stop-and-wait with 512-byte segments and a 500 ms
retransmit timer. That is a shell protocol. Streaming 128 MB through it is
wrong in a measurable way, and the required changes are:

1. a sliding window of at least 8 segments, per-segment retransmit;
2. segment size driven by the link MTU rather than by `MAX_PACKET`;
3. one ACK per two segments at most, so a delayed-ACK peer does not halve
   throughput;
4. per-socket buffers sized for streaming (§10).

The arithmetic that makes this a requirement rather than an optimisation is
in [TRANSPORT.md](docs/TRANSPORT.md) §3: on a Wi-Fi link with a 20 ms RTT,
stop-and-wait moves 492 bytes per RTT, which is 24 KB/s, which is 90 minutes
for a 128 MB NAND dump.

### 7.3 Streaming scheduler

A dump is a cooperative state machine advanced from `net_poll()`. It never
blocks the shell, never copies more than one chunk per poll, accepts
whatever `tcp_send()` will take and records the shortfall, and aborts on
socket close, retry exhaustion, or an explicit abort record. The console
stays live throughout, because the progress lines go to the console sink,
not to the stream.

### 7.4 Ports

443 for SSH, on by default. Port 23 (legacy plaintext console) is off by
default, requires an explicit `transport legacy-console on`, prints a
warning naming the exposure, and is not sticky across reboot. A plaintext
line protocol that accepts `memwrite` does not belong on a routable network.

---

## 8. Remote access: SSH-2 / SCP / SFTP on 443

Full specification in [docs/SSH_SCP_443.md](docs/SSH_SCP_443.md).

### 8.1 Why 443

Two reasons, in order of importance. It is the port that survives: a
restrictive host network, a captive portal or a corporate egress filter that
passes HTTPS will pass TCP 443, and the operator does not have to negotiate
firewall policy to read a register. And it is unambiguous with the legacy
console: with port 23 off by default, everything on the wire is
authenticated and encrypted.

Port 443 carries SSH directly. There is no TLS layer. `ssh -p 443` and
`scp -P 443` are the client invocations.

### 7.5 What is implemented instead, today

SSH is not written. What the payload *does* run is the goatloader: one TCP
listener at the pre-configured static address `192.168.42.1`, port `1234`,
bound during bring-up and not switchable off at runtime. It is a plaintext line
protocol -- no key exchange, no host key, no authentication -- which is a
different trust model from this section's, and is acceptable here only because
the link is point-to-point (one host, one device, no router).

The reason it is spelled out next to §7.4 rather than hidden in the code is
that it is the one service the rest of the container flow depends on:
`goat push`, `goat shell` and `goat run` are all conversations with it, so
turning it off is not an option an operator should be offered. The protocol,
the ordering rules (parse, verify, then decrypt) and the exposure are recorded
in [docs/GOATLOADER.md](docs/GOATLOADER.md). The port-23 legacy console stays
off, as above.

### 8.2 Protocol stack

| Layer | Selected algorithms |
|---|---|
| Transport | `curve25519-sha256`, `curve25519-sha256@libssh.org` |
| Host key | `ssh-ed25519` (primary), `rsa-sha2-512` (fallback) |
| Cipher | `chacha20-poly1305@openssh.com` (primary), `aes128-ctr` + `hmac-sha2-256` (fallback) |
| Compression | `none` |
| Userauth | `publickey`, `password` |
| Connection | `session` channels: `shell`, `exec`, `subsystem sftp` |
| File service | SFTP v3 (primary), legacy `scp -f` / `scp -t` (compatibility) |

Algorithm negotiation follows RFC 4253 §7.1: first client proposal that the
server also supports wins, and an empty intersection is a fatal
`SSH_MSG_DISCONNECT_KEY_EXCHANGE_FAILED` rather than a silent downgrade.

### 8.3 Crypto primitives — what exists, what must be written

The `goat` tree already provides SHA-256, AES-256-CBC **decrypt**, RSA
PKCS#1 v1.5 **verify**, DER and hex. SSH needs a different set, and the gap
is worth stating exactly:

| Primitive | In tree | Work required |
|---|---|---|
| SHA-256 | yes (`goat/sha256.c`) | none |
| HMAC-SHA-256 | derived | thin wrapper, ~40 lines |
| X25519 | no | field arithmetic + Montgomery ladder, ~350 lines |
| Ed25519 | no | needs **SHA-512** (absent), sign + verify, ~600 lines |
| ChaCha20 | no | quarter-round stream, ~120 lines |
| Poly1305 | no | 130-bit MAC, ~150 lines |
| AES-CTR | partial | `goat_aes` is decrypt-only and CBC-only; needs an encrypt key schedule and CTR mode |

Ed25519 as the host key is the reason SHA-512 is on the list. The fallback
`rsa-sha2-512` host key would also need a private-key modexp, which
`goat_rsa` deliberately does not have — so RSA host keys are a later,
optional addition, not part of the first cut.

Total new code is bounded and known: roughly 1,300 lines of freestanding C
plus a small constant-time bignum. It is the single largest block of work in
this version and it is all self-contained, testable on the host, and
independent of any A11 silicon question.

### 8.4 Host key

Generated on first boot and stored in a reserved SRAM slot, or in a NAND page
once the NAND driver is silicon-verified. Entropy: SEP `get_random`
(opcode 0x10) when the mailbox path works, else a seed hashed from
`CNTPCT_EL0`, uninitialised SRAM contents and the boot device tree — with the
limitation stated in the code, because a device with no entropy source
cannot produce an unpredictable host key and pretending otherwise would be
worse than documenting it.

`ssh fingerprint` prints the SHA-256 fingerprint of the current host key in
OpenSSH's format, so the operator can pin it in `known_hosts`.

### 8.5 Authentication and session model

- Single operator account, `operator`. No root, no `none` auth, ever.
- Public-key authentication by default: `authorized_keys` is either baked in
  at build time or provisioned once over the UART console with
  `ssh authorized-add <key>`.
- Password authentication is off unless explicitly enabled, and prints the
  exposure when it is.
- Max 6 auth attempts per connection, then disconnect. No login shell into
  arbitrary memory reads without the read having an owner: every dump
  command in a session is logged to the audit line with the authenticated
  key fingerprint and the timestamp.
- `session` channels: `shell` binds to the existing `execute()` loop with a
  console sink pointed at the channel; `exec` runs one command and closes;
  `subsystem sftp` enters the file service.
- Two concurrent channels maximum, bounded by the four-socket table in
  `src/net/tcp.c` (one listener plus four peers).

### 8.6 The file service and SCP

SFTP v3 exposes the dump registry as a read-only virtual filesystem:

```
/securerom.bin       819 KiB
/sram.bin           1972 KiB
/dram.bin        2147483648 KiB
/nand.bin          geometry
/apfs/<path>        extracted files
/regs.bin             2 KiB
/audit.log
```

Each handle is a `dump_source_t`. `READ` is served by the same chunker the
stream path uses, which means a file pull is resumable: reopen and `READ`
from the offset you reached, and the record framing means the host can verify
what it got rather than assume it.

Legacy `scp` is supported for script compatibility (`scp -f <path>` /
`scp -t <path>`), driven from `exec` channels. SFTP is preferred and is what
the host tool uses.

### 8.7 What this does not do

It does not make the payload reachable in a way it was not before: SSH is
only listening on a link that is up, and the USB link is point-to-point with
one host. The exposure this introduces is *deliberate and named*: when Wi-Fi
is up and SSH is listening on 443 on a routable subnet, the payload is a
network service with a shell on it. That is exactly why the plaintext
console is off by default and why every session is audited.

---

## 9. Shell command surface

New and changed commands. Everything in the existing shell keeps its
behaviour; this version adds to it and changes no existing command's
semantics.

```
dump list                             Registry with status words
dump <target> [hex]                   Hex to the console, DUMP_MAX_LENGTH capped
dump stream <target> [chunk]          Binary DZ1 to the active link
dump stream <target> --link <name>    Forced link, one transfer
dump abort                            Abort the running stream job
dump jobs                             Stream job state, bytes sent, retransmits
dump digest <target>                  SHA-256 over a source
dump find <pattern>                   Pattern search, unchanged

regs snapshot [nostage]             Capture now; stages in SRAM unless 'nostage'
regs show                           Print the staged record as text
regs clear                          Invalidate the staged record

transport status                      Links, addresses, listeners, counters
transport link <auto|name>            Force or clear link selection
transport address <link> <ip> <bits>  Override static addressing
transport ports                       Listeners and their ports
transport legacy-console <on|off>     Port 23, default off, warns

ssh status                            Negotiated algorithms, session, audit tail
ssh fingerprint                       Host key SHA-256 fingerprint
ssh authorized-add <key>              Provision a key (UART only)
ssh authorized-list
ssh port <n>                          Move the listener
ssh allow-secret <on|off>             Secret-source authorisation, default off
ssh enable | ssh disable
```

`help` lists all of them. A command that exists in the registry but not in
`help` is a bug in the same class as a driver that reports success without
reading anything back.

---

## 10. Memory budget

SRAM is `0x1E8000` bytes (1.9 MB). This version adds buffers that must be
counted rather than assumed, and counting them is only possible after the
layout problem in §2.4 is resolved — so this section states the requirement
and then states what it costs.

| Addition | Size | Notes |
|---|---|---|
| DZ1 chunk buffer | 16 KiB | one per active stream |
| Stream job state | < 256 B | per job |
| CPU snapshot record | 2 KiB | one, staged in the SRAM tail |
| X25519 context | 160 B | five 32-byte field elements |
| Ed25519 context | ~1.5 KiB | precomputed table, host key only |
| ChaCha20 / Poly1305 | 96 B | per direction |
| SSH connection state | ~4 KiB | two channels, per connection |
| TCP window growth | 4 × 16 KiB | 64 KiB, see below |
| **Total** | **~86 KiB** | steady-state, not peak-during-KEX |

Two items need explaining.

**The TCP window growth.** `src/net/tcp.c` today allocates
`TX_BUF 2048` + `RX_BUF 2048` per socket across `MAX_SOCKETS 4`, which is
16 KiB. A windowed sender useful for streaming needs roughly 16 KiB of
transmit buffer per socket, so four sockets becomes 128 KiB of transmit
buffer alone. Growing the buffers is not free and is not done silently: the
number has to be re-derived from the linker's budget, and the socket cap has
to come down if it does not fit. Three sockets at 16 KiB is 48 KiB, which is
the fallback if 128 KiB is uncomfortable.

**Which budget it comes out of.** Today there is no space clear of the goat
staging window to spend. The payload plus heap and stack currently ends at
`0x1801_67494`, which is `0x67494` bytes *inside* `GOAT_STAGE_BASE`, because
`.bss` carries 622 KiB of MMU page tables (§2.4). Gating those behind
`DR1ZZLE_ENABLE_MMU` frees 622 KiB, drops the image end to roughly
`0x1800_80494`, and leaves about 511 KiB between there and the goat window.

That is the number this version actually spends: **~86 KiB of 511 KiB
available after the §2.4 fix**, or about 4.3% of SRAM. Which is a
comfortable margin — but only after the fix, and claiming it before the fix
would be claiming space that is currently occupied by translation tables for
a feature that is off by default.

The mitigation if the numbers get tight later is to reserve the SRAM tail for
streaming rather than to shrink the window: a shell does not need 16 KiB of
transmit buffer, and the dump path is the case that fails visibly when the
window is too small.

---

## 11. Host tool

The host side is unchanged in spirit from v1.0 and extended in kind: the same
CLI now drives OpenSSH directly rather than a bespoke protocol.

```bash
dr1zzle-host [OPTIONS] <COMMAND>

OPTIONS:
  -t, --link <TYPE>      usb|wifi|auto   (default: auto)
  -a, --address <IP>     Target IP (default: 192.168.42.1)
  -p, --port <PORT>      TCP port (default: 443)
  -k, --key <PATH>       SSH identity (default: ~/.ssh/id_ed25519)
  -v, --verify           Recompute SHA-256 after transfer

COMMANDS:
    pull <source> <out>      Stream a dump source, verify the digest
    verify <source> <file>   Recompute and compare against the device
    regs [--out <file>]      Pull the CPU snapshot record
    sources                  List the registry with status
    audit                    Session audit log
    ssh [-- <args>]          Proxy to the system ssh with -p 443
```

Because the server speaks real SSH, the standard clients work without the
host tool at all:

```bash
ssh -p 443 operator@192.168.42.1
sftp -P 443 operator@192.168.42.1
scp -P 443 operator@192.168.42.1:/securerom.bin .
```

`dr1zzle-host pull` exists because it adds the thing OpenSSH does not: it
reads the `DZEND` trailer's digest, recomputes over the received bytes, and
fails loudly on a mismatch. Over a link that drops packets, "the file arrived"
and "the file is correct" are different claims, and only one of them is worth
having.

---

## 12. Testing and validation

### 12.1 Host-side unit tests

All of these run on a Mac with no device, and all of them are specified
because they are the tests that catch the class of bug this codebase has
already had: code that compiles, links, and is wrong.

| Module | Tests |
|---|---|
| DZ1 codec | Round-trip a synthetic stream; reject bad magic, short chunks, CRC mismatch, offset discontinuity, duplicate sequence |
| DZ1 chunker | Chunk boundaries at 0, 1, chunk-1, chunk, chunk+1; zero-length source; length not a multiple of chunk |
| CRC32 | Known vectors, and the ones that catch a reflected-vs-not table error |
| DZREGS1 codec | Frame verbatim from a fixture; unknown system-register id tolerated; id order stability |
| Streaming SHA-256 | Incremental vs one-shot agreement over 1 MiB |
| Link selector | Registration order, `auto` with none up, forced link, both up |
| Windowed sender | ACK advancement, per-segment retransmit, window exhaustion and recovery |
| SSH packet layer | Framing, MAC, sequence numbers, disconnect on short read |
| X25519 / Ed25519 / ChaCha20 / Poly1305 | RFC 7748 §6.1, RFC 8032 §7.1, RFC 8439 §2.4.2, RFC 8439 §2.5.2 |
| SFTP v3 | `OPEN`/`READ`/`CLOSE` against a fixture registry |

### 12.2 Integration tests (on device)

| Test | Criterion |
|---|---|
| `dump list` | Every source prints a status word; no source claims ready without a read callback |
| `dump stream securerom` | 1 MiB, `DZEND` digest matches `dump digest securerom` |
| `regs snapshot` then `regs show` | Frame matches the console fault dump on an induced fault |
| Induced fault | Sync abort captures, stages, halts; `dump regs` over SSH still returns the record |
| `ssh status` | Ed25519 host key, ChaCha20-Poly1305 negotiated, fingerprint matches `ssh fingerprint` |
| `sftp` from OpenSSH | `get /nand.bin` completes, digest verified |
| `scp -P 443` | Legacy path works against `scp -O` |
| 128 MB NAND stream | Completes over USB; measured goodput reported and bounded by §7.2 |
| Link failover | Pull Wi-Fi mid-transfer; job aborts with a named completion code, not a hang |
| `transport legacy-console on` | Warning printed; port 23 not sticky across reboot |
| Secret source over UART | Refused with reason; over authenticated SSH, allowed after `confirm` |

### 12.3 Interop, stated honestly

The strongest SSH verification available in this repository is host-side:
the crypto primitives against their RFC test vectors, and the packet layer
against a captured reference trace. End-to-end interop with OpenSSH requires
either a network-capable QEMU board profile or an A11 transport backend. The
portable QEMU `virt` profile in `boards/` has no network device today, which
is the same gap
[docs/REMOTE_ACCESS.md](docs/REMOTE_ACCESS.md) identified before this spec
existed; adding a `virtio-net` board profile is the work that closes it.

---

## 13. Verification status matrix

The table below is the contract between this document and
[docs/TASK_STATUS.md](docs/TASK_STATUS.md). If a row says "spec", it means
this document specifies it and no code exists.

| Capability | Code | Silicon |
|---|---|---|
| Dump source registry | exists (`src/drivers/dump.c`), extended by this spec | unverified |
| Console hex dump path | exists, `DUMP_MAX_LENGTH` capped | unverified |
| DZ1 container + chunker | spec | — |
| CRC32 | spec | — |
| DZREGS1 snapshot capture | spec (frame save exists in `start.S`) | — |
| SRAM-staged snapshot | spec | — |
| Link abstraction | spec (USB backend exists) | unverified |
| `net_recv_frame` wired to CDC-ECM | **missing** — frames are received and dropped | unverified |
| Windowed TCP sender | spec | — |
| Stream scheduler | spec | — |
| SSH transport (X25519, Ed25519, ChaCha20-Poly1305) | spec — primitives to be written | — |
| SSH connection + session channel | spec | — |
| SFTP v3 + legacy SCP | spec | — |
| Wi-Fi BCM4357 backend | contract only ([docs/WIFI.md](docs/WIFI.md)) | unverified |
| SecureROM dump | ready (source exists) | unverified |
| NAND dump | register map unverified | unverified |
| AES/GID path | implemented, key bytes withheld | unverified |

Nothing in this document claims a capability the code does not have.

---

## 14. References

| Document | Path |
|---|---|
| Dump wire format, chunk records, resume, CPU snapshot record | [docs/DUMP_WIRE_FORMAT.md](docs/DUMP_WIRE_FORMAT.md) |
| SSH-2 / SFTP / SCP on 443 | [docs/SSH_SCP_443.md](docs/SSH_SCP_443.md) |
| Links, TCP behaviour, stream scheduling | [docs/TRANSPORT.md](docs/TRANSPORT.md) |
| Clean-room boundary | [docs/CLEAN_ROOM.md](docs/CLEAN_ROOM.md) |
| Remote-access boundary (pre-spec) | [docs/REMOTE_ACCESS.md](docs/REMOTE_ACCESS.md) |
| Wi-Fi findings and backend contract | [docs/WIFI.md](docs/WIFI.md) |
| Architecture | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) |
| Task completion matrix | [docs/TASK_STATUS.md](docs/TASK_STATUS.md) |
| Implementation plan | [PLAN.md](PLAN.md) |
| A11 memory map | `include/memory_map.h` |
| Exception entry and frame | `src/arch/arm64/start.S` |
| Fault dumper and AIC dispatch | `src/arch/arm64/exception.c` |
| Crypto primitives | `src/goat/`, `include/goat/` |
| TCP/IP stack | `src/net/tcp.c`, `include/net.h` |

External, for register values and protocol definitions only: ARM DDI 0487
(ARMv8-A), RFC 4251-4254 (SSH-2), RFC 8032 (Ed25519), RFC 8439
(ChaCha20-Poly1305), RFC 7748 (X25519), draft-ietf-secsh-filexfer (SFTP v3).

