# Phase 5: SEP Mailbox Client — Execution Plan

> **2026-10-10 audit status: NOT hardware-ready.** The C client is host-test
> scaffolding only. Production initialization now fails closed and performs
> no MMIO until the A11 mailbox resource base, FIFO offsets, and message
> protocol are joined from measured evidence. The prior ✅ labels below mean
> only that the corresponding code/test skeleton exists; they do not mean a
> validated SEP protocol or successful SEP transaction.

## Context

- **What this phase builds**: An AP-side client for the Apple ASC mailbox that talks to the SEP (S5L8960X, ARMv7-A) on A11 (t8015).
- **What it does NOT build**: The SEP-resident OS (drizzle on ARMv7-A). That is a separate image, built for ARMv7-A, delivered over the mailbox by the SEP Boot ROM copying an AP-staged payload into protected SEP RAM.
- **Current state**: `src/research/sepos.c` was a stub with hardcoded opcodes, no register map, no framing, and the mailbox base `0x23C000000` disagrees with the AGENTS.md measurement (`0x243000000` from the A11 AP ROM literal at file `0x1c190`).
- **Target**: Functional `sepos` shell commands (`ping`, `get_random`, `boot_tz0`, `status`, `memdump`) against real hardware, with a documented register map and a driver that can be unit-tested on the host.

---

## 1. Resolve the Mailbox Base Address

### 1.1 Discrepancy
| Source | Address | Evidence |
|--------|---------|----------|
| `include/soc/t8015.h:116` | `0x23C000000` | Inherited from `ipwndfu/device_platform.py` (geometry-only, no peripheral map) |
| AGENTS.md 2026-10-01 | `0x243000000` | 8-byte literal at file offset `0x1c190` in `SecureROM_t8015si_iBoot-3332.0.0.1.23.bin` |

### 1.2 Action
- The AP-ROM literal and the measured mailbox access window are distinct
  observations: `0x243000000` and `0x243008000`, respectively. Do not infer
  that either is the base expected by this driver's register offsets.
- Upstream Linux's `apple,t8015-asc-mailbox` profile independently specifies
  T8015 FIFO/control offsets (`A2I control 0x108`, `I2A control 0x10c`,
  send words `0x800/0x808`, receive words `0x830/0x838`). This disproves the
  contiguous message/doorbell map originally copied into this plan, but does
  not by itself identify the matching AP physical resource base or Apple's
  SEPOS command protocol.
- PongoOS's A11-specific `sep_setup()` derives `sep_reg_u` from the SEP
  DeviceTree `reg` and `gIOBase`, then places its 64-bit mailbox structure at
  `sep_reg_u + 0x8100`; its send words are at `+0x8800/+0x8808`, receive
  status at `+0x810c`, and receive words at `+0x8830/+0x8838`. The packed
  message is `[endpoint:8][tag:8][opcode:8][param:8][data:32]`. This is a
  strong implementation reference, but not a captured exchange on our
  target. See [PongoOS `sep.c`](https://github.com/checkra1n/PongoOS/blob/master/src/drivers/sep/sep.c).
- **Decision gate:** identify the exact T8015 mailbox resource base and
  correlate the upstream register profile with the measured ROM accesses
  before enabling AP MMIO. No hardware probe is currently available.

---

## 2. SEP Mailbox Register Map (`src/drivers/sep.c` + `include/sep.h`)

> The table below is the original unverified proposal, retained for history;
> it is not the PongoOS A11 register map and must not be used for hardware IO.

### 2.1 Required Registers (from pongoOS `sep.c` + Apple ASC Mailbox)
```c
// Offsets from mailbox base
#define SEP_AP2IOP_MSG0      0x800   // AP → IOP message low
#define SEP_AP2IOP_MSG1      0x804   // AP → IOP message high
#define SEP_AP2IOP_DB        0x808   // AP → IOP doorbell (write 1 to ring)
#define SEP_IOP2AP_MSG0      0x80C   // IOP → AP message low
#define SEP_IOP2AP_MSG1      0x810   // IOP → AP message high
#define SEP_IOP2AP_DB        0x814   // IOP → AP doorbell (read, then write 1 to ack)

// Status / control (exact offsets vary; pongoOS uses 0x400+)
#define SEP_STATUS           0x400   // Mailbox status register
#define SEP_IRQ_ENABLE       0x404   // IRQ enable
#define SEP_IRQ_STATUS       0x408   // IRQ status
#define SEP_IRQ_CLEAR        0x40C   // IRQ clear (write 1 to clear)
```

### 2.2 Deliverable
- New file `include/sep.h`: complete register map with bit definitions, sourced to pongoOS/Apple docs.
- New file `src/drivers/sep.c`: driver with:
  - `sep_init(base)` — maps the window, clears pending doorbells
  - `sep_send(opcode, payload, len)` — blocking send with timeout, returns reply or error
  - `sep_poll()` — non-blocking check for incoming messages (for future async use)
  - `sep_get_status()` — reads status register
- Unit test: `tests/sep_test.c` driven by `make host-test`, using a fake MMIO region.

**STATUS: HOST-TESTED SCAFFOLD; HARDWARE PATH DISABLED.** The initial offsets
were not the T8015 FIFO map. Production `sep_init()` now returns
`SEP_ERR_UNSUPPORTED` without retaining a usable MMIO pointer or touching
registers. The host fake-MMIO build is explicitly enabled with
`SEP_TEST_MMIO`.

---

## 3. Opcode Implementation (PongoOS A11 reference; not yet hardware-verified)

| Opcode | Name | Direction | Payload | Reply |
|--------|------|-----------|---------|-------|
| `0x01` | PongoOS `seprom_ping` | AP → SEPROM | param 0, data 0 | waits for a mailbox event; no distinct PONG opcode is identified here |
| `0x10` | Random request | AP → SEPROM | param 0, data 0 | SEPROM message opcode `0x74` (`0x10 + 100`), random word in data |
| `0x05` | Boot TZ0 | AP → SEPROM | param 0, data 0 | completion opcode `0xd2`; 64-bit PongoOS configures an integrity tree first |
| `0x06` | Load SEPOS | AP → SEPROM | mode in param, AP physical image page in data | opcode `0x6a` marks SEPROM handoff in PongoOS |
| `0x11` | Integrity-tree configuration | AP → SEPROM | tree size in data | completion opcode `0x75`; **not ART transfer** |
| `0xff` | SEPROM panic report | SEP → AP | response side | **not ping** |

### 3.1 Message Framing (PongoOS A11 SEPROM path)
- 64-bit message bytes: `[endpoint:8][tag:8][opcode:8][param:8][data:32]`.
- PongoOS uses endpoint `0xff`, tag `0`, then writes the packed 64-bit value
  to the A11 mailbox `snd0` and zero to `snd1`. This is FIFO transport, not a
  separate AP-to-IOP doorbell register sequence.
- PongoOS tests receive status bit `0x20000` for empty and reads `recv0` (and
  consumes `recv1`); do not treat any nonzero data word as proof of a reply.

### 3.2 Deliverable
- `sep_send_command()` in `sep.c` handles all five opcodes with proper framing.
- Timeout: 1 second for ping/random, 5 seconds for boot_tz0.
- Returns structured error codes (timeout, NAK, malformed reply).

**STATUS: RESEARCH-ONLY / INCOMPLETE.** The previous driver encoded the
wrong message and assumed doorbells. The checked-in host suite still exercises
that legacy fake transport only. Port the PongoOS A11 message/FIFO layout into
the test model, preserve the production no-MMIO guard, and do not infer NAK or
command completion behavior beyond the cited source.

---

## 4. Shell Integration (`src/shell/shell.c`)

### 4.1 Current Stubs (lines 983–998)
```c
sepos <ping|random|boot_tz0|status|memdump>
```

### 4.2 Required Implementation
- `sepos ping` → calls `sep_send_command(0xFF, ...)`, prints "SEP ping OK" or "SEP ping failed (timeout/NAK)"
- `sepos random` → calls `sep_send_command(0x10, ...)`, prints 32 bytes hex
- `sepos boot_tz0 [addr]` → if addr given, sends as payload; else uses default SEPOS load address from NAND slot 0
- `sepos send_sepos [slot]` → stages SEPOS from NAND slot, sends opcode 0x06
- `sepos status` → reads and prints mailbox status registers
- `sepos memdump <addr> <len>` → NOT YET SUPPORTED (requires SEPOS-side cooperation); print clear message

### 4.3 Help Text Update
Replace line 300 with accurate usage including `send_sepos`.

**STATUS: SHELL WRAPPERS PRESENT; TRANSPORT FAILS CLOSED.** The wrappers
report that the transport is disabled until the resource base and register
map are verified. No successful command has been observed on an A11 device.

---

## 5. SEPOS Image Staging (for `boot_tz0` / `send_sepos`)

### 5.1 Where SEPOS Comes From
- NAND firmware slot (written by `goat install <sepOS.g1> --slot N`)
- Or: host pushes SEPOS container via `goat push sepos.g1 --key-hex ... --run` (stages in SRAM)

### 5.2 Boot TZ0 Flow
1. Locate SEPOS image in SRAM/NAND (header gives load address + entry)
2. Compute physical address >> 12 (the mailbox expects page number)
3. `sep_send_command(0x05, &page_num, 4)`
4. Wait for ACK; SEP Boot ROM copies from AP RAM to SEP RAM, verifies, jumps

### 5.3 Deliverable
- `sep_find_sepos_image(slot)` in `sep.c` or `fw_store.c` — returns `(base, size, entry)`
- `sepos boot_tz0` shell command uses it automatically

**STATUS: ⏳ PENDING** — Basic `sep_boot_tz0()` exists but needs SEPOS image location logic.

---

## 6. Hardware Verification Checklist

| Test | Command | Expected |
|------|---------|----------|
| Mailbox reachable | `sepos status` | Registers read non-zero |
| Ping | `sepos ping` | "SEP ping OK" in <10 ms |
| Get Random | `sepos random` | 32 hex bytes, different each call |
| Boot TZ0 (no image) | `sepos boot_tz0` | NAK (no image staged) |
| Boot TZ0 (with image) | `goat install sepos.g1 --slot 0` then `sepos boot_tz0` | ACK, SEP re-enumerates |

**Gate**: all five rows pass on an A11 device before Phase 5 is complete.

---

## 7. Unit Tests (Host)

- `tests/sep_test.c`: fake MMIO at `0x23C000000`/`0x243000000`
  - `test_sep_ping_ok()` — mock reply PONG, assert success
  - `test_sep_ping_timeout()` — no reply, assert timeout error
  - `test_sep_get_random()` — mock 32-byte reply, verify bytes returned
  - `test_sep_framing()` — verify 64-bit message composition matches pongoOS
- Run via `make host-test` (added to `tests/Makefile`)

**STATUS: HOST TESTS PASS; SCOPE LIMITED.** Tests cover the fake transport and
the production no-MMIO guard. They do not validate the Apple protocol or
hardware behavior.

---

## 8. Documentation Updates

| File | Change |
|------|--------|
| `docs/SOCS.md` | Note SEP mailbase verified for t8015; add t8010/t8011 bases when known |
| `docs/TASK_STATUS.md` | Update Phase 5 row to ✅ with date |
| `include/soc/t8015.h` | Correct `SOC_T8015_MAILBOX_BASE` with source comment |
| `README.md` | Add `sepos` to command reference |

**STATUS: OPEN.** Keep `SOC_T8015_SEP_BASE` distinct from a resolved mailbox
resource base. The AP ROM literal alone does not verify FIFO semantics.

---

## 9. Dependencies & Ordering

```
1. Resolve mailbox base (device or cross-ref)          → 1 day
2. Write include/sep.h register map                    → 0.5 days
3. Write src/drivers/sep.c driver + unit tests         → 2 days
4. Integrate into shell (sepos command)                → 1 day
5. SEPOS staging + boot_tz0 flow                       → 1.5 days
6. Hardware verification on A11                        → 1 day (needs device)
7. Docs + host-test integration                        → 0.5 days
```

**Total**: ~7 days, gated on device access for step 1 and 6.

---

## 10. Out of Scope for Phase 5

- SEP-resident drizzle build (ARMv7-A, separate repo/branch)
- SEPOS memory dump protocol (requires SEPOS cooperation — opcode not in public docs)
- SSH/SCP transport for SEP dumps (Phase 8+)
- T8010/T8011 mailbox bases (no device to verify)
- usbliter8 SEP support (different exploit path)

---

## 11. Acceptance Criteria (from PLAN.md, made measurable)

```
research> sepos ping → "SEP ping OK" in <10 ms (3/3 runs)
research> sepos random → 32 hex bytes, different each run (3/3)
research> sepos boot_tz0 → "NAK: no SEPOS image staged"
research> goat install sepos.g1 --slot 0 → writes to NAND, verifies
research> sepos boot_tz0 → "ACK" + SEP re-enumerates (USB PID changes)
make host-test → sep_test passes
```

---

## 12. First Code Change

Create `include/sep.h` with the register map from Section 2.1, then `src/drivers/sep.c` with the driver skeleton. The existing `src/research/sepos.c` becomes a thin wrapper calling `sep_send()` and is eventually removed once the shell uses `sep.c` directly.

**STATUS: INCOMPLETE / RESEARCH ONLY.** Source files and fake-MMIO tests
exist, but the production path is deliberately disabled. Historical hardware
acceptance criteria below are not met.
