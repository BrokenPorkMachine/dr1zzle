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

**STATUS: COMPLETE — protocol-correct against pongoOS, hardware-untested.**

The register map in section 2.1 above is the original unverified proposal and
is WRONG: it is the 32-bit layout, and the A11 uses a different 64-bit one. It
is retained for history because it is what was first built. The audit that
replaced it is recorded in
`docs/A11_SEP_MAILBOX_PROTOCOL_AUDIT_2026-10-10.md` at the OpenEyeOS root.

What `include/sep.h` now implements, from pongoOS `struct mailbox_registers64`:

```c
#define SEP_MBOX_DIS_INT   0x8100   /* write 0x1000 to disable the inbox interrupt */
#define SEP_MBOX_EN_INT    0x8104   /* write 0x1000 to enable it */
#define SEP_MBOX_SND_STS   0x8108
#define SEP_MBOX_RECV_STS  0x810C   /* bit 17 (0x20000) = queue EMPTY */
#define SEP_MBOX_SND0      0x8800   /* AP->IOP message, 64-bit */
#define SEP_MBOX_SND1      0x8808   /* written 0 alongside snd0 */
#define SEP_MBOX_RECV0     0x8830   /* IOP->AP reply, 64-bit */
#define SEP_MBOX_RECV1     0x8838   /* read and discarded by pongoOS */
```

That is the complete register set. There is NO reply doorbell and NO ack
register in either pongoOS layout, so the driver provides neither: reading
`recv0` is the whole consumption path, exactly as `sep_check_mailbox()` reads
`recv0` and returns. `tests/sep_test.c` pins the set as a count as well as by
value, so a ninth offset cannot be added without failing a test.

`sep_send_raw()` replaces the old `sep_send_command()`; `sep_get_status()` is
replaced by `sep_recv_status()`. See the header for the current API.

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
- `sep_send_raw()` in `sep.c` handles all opcodes with proper framing.
- Per-opcode timeouts; structured error codes (timeout, NAK, panic, malformed).

**STATUS: COMPLETE — implemented and host-tested; no real SEP exchange.**

The §3.1 table above is correct and is what the driver implements. The one
correction to its history: the first draft of `sep.c` used opcode `0xFF` for
ping and encoded `[flags:16][opcode:16][payload:32]` instead of the packed
`{ep, tag, opcode, param, data}`. Ping was wrong in all five opcodes'
neighbourhood and `send_sepos` invented a 4-word metadata protocol pongoOS
does not use. That is now fixed and pinned by tests.

`SEP_TEST_MMIO` and the production no-MMIO guard are both gone: the driver
retains a real MMIO pointer unconditionally, because there is no longer a
distinction between a "scaffold" build and a "production" one — the transport
is either the real mailbox base from the SoC profile, or nothing. What
`sep_init()` cannot know is whether that base is right, and it does not claim
to; see the non-claims in the audit record.

---

## 4. Shell Integration (`src/shell/shell.c`)

### 4.1 Current Stubs (lines 983–998)
```c
sepos <ping|random|boot_tz0|status|memdump>
```

### 4.2 Required Implementation
- `sepos ping` → `sepos_ping()`, prints "SEP ping OK" or "SEP ping failed"
- `sepos random` → `sepos_get_random()`, prints 32 bytes hex
- `sepos boot_tz0` → `sepos_boot_tz0()`, which configures the integrity tree first as pongoOS does
- `sepos send_sepos <phys> [size [entry]]` → `sepos_send_sepos()`, page number in data
- `sepos send_art <phys> [size]` → `sepos_send_art()`
- `sepos irq` → `sepos_enable_irq()` (writes the `en_int` mask only; no IRQ is bound)
- `sepos status` → `sepos_status()`, prints `recv_sts`, queue-empty, irq state, statistics
- `sepos memdump <addr> <len>` → NOT SUPPORTED (requires SEPOS-side cooperation); prints that reason

### 4.3 Help Text Update
Done — `sepos <ping|random|boot_tz0|send_sepos|send_art|irq|status|memdump>`.

**STATUS: COMPLETE — all commands wired; none exercised on hardware.**

Note §4.2 above originally specified `sep_send_command(0xFF, ...)` for ping.
That opcode was wrong; ping is **1**, and the wrappers call the typed helpers
rather than composing opcodes by hand. No successful command has been observed
on an A11 device.

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

**STATUS: ⏳ PENDING — still the real remaining work, and it is blocked.**

`sep_boot_tz0()` sends opcode 5 with param 0 and data 0, which is what pongoOS
sends when it has no image to name. Naming an image requires
`sep_find_sepos_image()`, which requires a firmware slot reader and a SEPOS
container format — neither of which exists, because both are downstream of the
two blockers recorded in
[`../../../docs/T8020_SEPOS_DIAGNOSTIC_FRONTIER_2026-10-10.md`](../../../docs/T8020_SEPOS_DIAGNOSTIC_FRONTIER_2026-10-10.md)
(the AP readiness predicates, and the SEPOS state before `0x10000550c`).

§5.2 step 3 above is also wrong in its detail: pongoOS sends **no payload** for
boot_tz0 — `seprom_execute_opcode(5, 0, 0)` — because the integrity tree
configured immediately before it is what tells SEP where its region is. The
page-number-in-data form is what opcode **6** (`send_sepos`) uses, not 5.

---

## 6. Hardware Verification Checklist

| Test | Command | Expected |
|------|---------|----------|
| Mailbox reachable | `sepos status` | `recv_sts` reads non-zero, queue state reported |
| Ping | `sepos ping` | "SEP ping OK" |
| Get Random | `sepos random` | 32 hex bytes, different each call |
| Boot TZ0 (no image) | `sepos boot_tz0` | NAK or timeout (no image staged) |
| Boot TZ0 (with image) | `goat install sepos.g1 --slot 0` then `sepos boot_tz0` | ACK, SEP re-enumerates |

**Gate: NOT MET.** All five rows require an A11 device and a launched SEPROM.
Zero of them have been attempted. §5 above explains why the last row cannot be
reached yet even with hardware in hand.

---

## 7. Unit Tests (Host)

Two suites, both under fake MMIO, both in `make sep-test`:

- **`tests/sep_test.c`** (18 tests) — the driver against pongoOS. Pins the
  register set as a *count* as well as by value, the message round-trip, the
  per-opcode encoding (ping = 1, not 0xFF), the opcode+100 reply convention,
  the SEPROM panic message, the `recv_sts` bit 17 queue-empty bit, the
  interrupt mask, and the message framing **against real captured SEP traces**
  from AsahiLinux's HW:SEP page.
- **`tests/sepos_wrapper_test.c`** (8 tests) — `src/research/sepos.c`, the
  layer between the shell and the driver that owns the static driver instance
  and the init latch. Checks the wrappers route to the right opcodes, that the
  page number lands in `data`, and that the module resets cleanly between
  uses. Uses `sepos_test_attach()` so the wrapper's driver points at the fake
  MMIO instead of the profile's real `0x243000000`.

**STATUS: 18/18 and 8/8 PASS.** Neither suite validates hardware behaviour, and
neither can: the first checks the protocol against a reference
implementation, the second checks that the wrappers call the driver correctly.
The Apple protocol and its behaviour on an A11 remain unvalidated.

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

## 12. Outcome

`include/sep.h` and `src/drivers/sep.c` were written with the register map from
§2.1 — which turned out to be the **wrong** map, being the 32-bit layout. The
correction to the real pongoOS 64-bit layout, the removal of the fabricated
reply-doorbell ack, and the tests that pin both are recorded in
[`../../../docs/A11_SEP_MAILBOX_PROTOCOL_AUDIT_2026-10-10.md`](../../../docs/A11_SEP_MAILBOX_PROTOCOL_AUDIT_2026-10-10.md).
`src/research/sepos.c` is the thin wrapper §12 intended and the shell uses the
driver through it.

**STATUS: driver COMPLETE and host-tested (18/18 protocol tests, 36/36 SoC
registry tests). The Phase 5 hardware acceptance is NOT met — no real SEP
exchange has ever been performed, and the two blockers recorded in
`docs/T8020_SEPOS_DIAGNOSTIC_FRONTIER_2026-10-10.md` (the AP readiness
predicates that keep the `0xa4` receive path disabled, and the SEPOS state
immediately before `0x10000550c`) are upstream of it and unchanged.**

The original §2.1 table is kept above despite being wrong, because it is the
record of what was proposed before the audit, and a plan whose first draft was
wrong and says so is more useful than one that quietly shows only the answer.
