# Dump wire format

Two formats and one control protocol:

| Format | Carries |
|---|---|
| `DZ1` | any byte stream — memory, firmware, NAND pages, extracted files |
| `DZREGS1` | a CPU register snapshot, wrapped *inside* a `DZ1` stream |

Both are little-endian, unaligned-access tolerant, and versioned in their
magic so a receiver can refuse a format it does not know rather than
misparse it.

All offsets below are from the start of the record.

---

## 1. `DZ1` — the dump container

### 1.1 Stream shape

```
  header (72 bytes)
  chunk record 0
  chunk record 1
  ...
  trailer (64 bytes)
```

There is exactly one header, zero or more chunk records, and exactly one
trailer. A stream that ends without a trailer was cut off, and the receiver
must treat it as a failure rather than as a complete shorter file.

### 1.2 Header

| Off | Size | Field | Notes |
|----:|----:|-------|-------|
| 0 | 8 | magic | `"DZDUMP1\0"` = `44 5A 44 55 4D 50 31 00` |
| 8 | 2 | version | `1` |
| 10 | 2 | flags | bit 0 = truncated, bit 2 = contains secret material; others must be 0 |
| 12 | 4 | source_id | registry id from `dump_source_t.id` |
| 16 | 4 | chunk_size | bytes of payload per chunk record, 1..16384 |
| 20 | 1 | kind | `dump_kind_t` |
| 21 | 1 | status | `dump_status_t` |
| 22 | 2 | reserved | 0 |
| 24 | 8 | base | physical/virtual base for memory and firmware kinds, else 0 |
| 32 | 8 | total | expected payload length; `0xFFFFFFFFFFFFFFFF` when unknown |
| 40 | 32 | digest | SHA-256 of the whole payload, **all zero until the trailer** |

The zeroed digest field is deliberate and is the one part of this format
that looks like a bug and is not. The header is written before the payload is
read, so the digest cannot be known then. The alternative — reading the whole
source once to digest it and again to stream it — doubles every NAND read on
the device for no gain to the receiver, which has the trailer anyway. The
trailer carries the authoritative digest; the header field exists so a
receiver reading only the header can tell that the stream is unfinished.

`base` is metadata for the operator, not an instruction. A receiver must not
assume that `base + offset` is a valid address on the receiving host, and must
not write a dump to that address.

### 1.3 Chunk record

| Off | Size | Field | Notes |
|----:|----:|-------|-------|
| 0 | 4 | magic | `"DZC1"` = `44 5A 43 31` |
| 4 | 4 | seq | 0-based, monotonically increasing by 1 |
| 8 | 8 | offset | byte offset of this chunk's data within the payload |
| 16 | 4 | length | `1..chunk_size`; the final chunk may be short |
| 20 | 4 | crc32 | over `data` only, see §2 |
| 24 | length | data | the payload bytes |

A chunk of length 0 is invalid. A chunk whose `offset` does not equal
`seq * chunk_size` for a non-final chunk is invalid, and the receiver must
reject the stream rather than reassemble a shifted image.

Sequence and offset are both carried because they catch different mistakes:
a duplicated sequence number, and a gap. Either one alone would let a dropped
chunk through silently.

### 1.4 Trailer

| Off | Size | Field | Notes |
|----:|----:|-------|-------|
| 0 | 4 | magic | `"DZEND"` = `44 5A 45 4E 44` |
| 4 | 4 | seq | number of chunk records emitted |
| 8 | 8 | total | payload bytes emitted |
| 16 | 32 | digest | SHA-256 over the concatenation of all chunk `data` bytes |
| 48 | 1 | code | completion code, §1.5 |
| 49 | 15 | reserved | 0 |

A trailer with `total` less than the header's `total` is only valid with
completion code 1, 2, 3 or 5, and the header's truncated flag set.

### 1.5 Completion codes

| Code | Name | Meaning |
|----:|------|---------|
| 0 | complete | `total` bytes emitted, digest verified on device |
| 1 | aborted-host | receiver sent `DZABORT` |
| 2 | source-error | a read failed: NAND uncorrectable ECC, gated window, refused driver |
| 3 | link-error | socket closed, or retransmit budget exhausted |
| 4 | refused | source is secret and the session is not secret-cleared (§ SPEC.md 5.5) |
| 5 | truncated | fewer bytes than the source reports; reported, never padded |

Code 5 exists because "the device stopped talking" and "the device finished"
must not look the same to a receiver. Padding a short read to the advertised
length would produce a file that hashes to nothing and looks complete.

---

## 2. CRC32

IEEE 802.3, reflected, polynomial `0xEDB88320`, initial value `0xFFFFFFFF`,
final XOR `0xFFFFFFFF` — the CRC-32 of zlib, PNG and Ethernet. Computed over
the chunk `data` bytes only: not the chunk header, not the length field.

The receiver must verify a chunk's CRC before appending its data to the
running digest. Appending first and verifying later means a corrupted chunk
contributes to the digest, and the stream then fails the whole-file check
while the local copy is subtly wrong in a way that is much harder to localise.

---

## 3. Control protocol and resume

### 3.1 Where it runs

On the same TCP connection, in the reverse direction, from the receiver to
the device. One ASCII record per line, `\n` terminated:

```
DZACK <seq>\n      chunk received, CRC verified, appended to the digest
DZNAK <seq>\n      chunk bad or out of order; resend from this sequence
DZCHUNK <n>\n      change the chunk size to n (1..16384)
DZABORT\n          stop now
```

`<seq>` is decimal. Unknown records are ignored rather than fatal, so a
future control verb does not break an old device.

### 3.2 Behaviour

- **`DZACK`** is advisory. The device does not require it and does not buffer
  waiting for one. It exists so a receiver can pace itself and so the device
  can distinguish "still receiving" from "vanished".
- **`DZNAK <seq>`** rewinds the job: the chunk sequence resets to `seq`, the
  offset resets to `seq * chunk_size`, and the device's own digest accumulator
  is reset and rebuilt from there. The trailer digest therefore describes the
  *device's* view of what it sent, and the receiver is responsible for
  tracking which chunks it actually accepted. A receiver that NAKs a chunk it
  already appended to its own digest must drop its own copy first.
- **`DZABORT`** stops the job and emits a trailer with code 1.
- **Idle timeout.** No control record of any kind for 30 seconds ends the job
  with code 3. A peer that has stopped talking is not going to resume, and a
  half-open job holding a socket is worse than a failed one.
- **`DZCHUNK`** takes effect on the next chunk boundary. A chunk size larger
  than the link can carry in one frame is clamped with a warning rather than
  silently fragmented into a record the receiver must reassemble by hand.

### 3.3 Resume over SFTP

SFTP does not use this protocol. An SFTP `READ` is offset-addressed, so
resuming is the client reopening the handle and reading from the offset it
reached. The control protocol exists for the raw-stream path — the shell's
`dump stream <target>` into an SSH `exec` channel or a plain TCP session —
where the client is a script rather than a protocol implementation.

---

## 4. `DZREGS1` — CPU register snapshot

### 4.1 Shape

A `DZREGS1` record is the *payload* of a `DZ1` stream with
`kind = DUMP_KIND_CPU`. The outer framing is identical to any other dump; the
inner record identifies what the bytes mean. That double framing is
intentional — it means `dump regs` works over SFTP, over a raw stream, and
over the hex console without a third code path.

```
  header (48 bytes)
  frame (256 bytes)
  system-register list (16 bytes per entry)
  digest (32 bytes)
```

### 4.2 Header

| Off | Size | Field | Notes |
|----:|----:|-------|-------|
| 0 | 8 | magic | `"DZREGS1\0"` = `44 5A 52 45 47 53 31 00` |
| 8 | 2 | version | `1` |
| 10 | 2 | flags | bit 0 = staged in SRAM, bit 1 = frame incomplete |
| 12 | 1 | trigger | 0 = on demand, 1 = sync fault, 2 = SError, 3 = FIQ, 4 = watchdog |
| 13 | 3 | reserved | 0 |
| 16 | 8 | cntpct | raw `CNTPCT_EL0` cycles at capture |
| 24 | 8 | usec | `timer_now_us()` at capture |
| 32 | 4 | frame_bytes | 256 |
| 36 | 4 | sysregs | number of entries in the list |
| 40 | 8 | mpidr | `MPIDR_EL1`, identifies the capturing core |

### 4.3 The frame

256 bytes, `x0` at offset 0 and `x30` at offset 240, eight bytes each, in
register order. Offsets 248..255 are reserved and zero.

This is `SAVE_REGS` from `src/arch/arm64/start.S` copied verbatim: that macro
stores `x0`/`x1` at `[sp,#0]`, `x2`/`x3` at `[sp,#16]`, and so on with `x30`
at `[sp,#240]`, which is exactly this layout. No new save path exists, and
that is the reason the record is trustworthy — it is the frame the fault
handler already had, not a reconstruction taken afterwards.

The snapshot is taken of the core that called it. Capturing another core would
mean stopping it, and the other cores on this payload are either idle in
`wfe` or running firmware code this build does not own.

### 4.4 System-register list

16 bytes per entry: `u16 id`, `u16 reserved` (zero), `u64 value`.

A list rather than a fixed struct, for one reason: a register added in a later
version must not invalidate every capture taken before it. A receiver that
does not recognise an id skips 16 bytes and continues.

Ids defined by version 1:

| Id | Register |
|---:|----------|
| 0x0001 | `elr_el1` |
| 0x0002 | `spsr_el1` |
| 0x0003 | `esr_el1` |
| 0x0004 | `far_el1` |
| 0x0005 | `sp_el1` |
| 0x0006 | `tpidr_el1` |
| 0x0010 | `vbar_el1` |
| 0x0011 | `sctlr_el1` |
| 0x0012 | `ttbr0_el1` |
| 0x0013 | `ttbr1_el1` |
| 0x0014 | `tcr_el1` |
| 0x0015 | `mair_el1` |
| 0x0020 | `currentel` |
| 0x0021 | `midr_el1` |
| 0x0022 | `mpidr_el1` |
| 0x0023 | `cpacr_el1` |
| 0x0030 | `cntfrq_el0` |
| 0x0031 | `cntpct_el0` |
| 0x0032 | `daif` |
| 0x0033 | `nzcv` |
| 0x0040 | PMGR gate status (MMIO read) |
| 0x0041 | last AIC event, if the controller is up |

`midr_el1` and `mpidr_el1` are what turn a register dump into a diagnosis:
they say whether the fault was on a Monsoon or a Mistral core, and on which
one, which matters when only one core's behaviour is in question.

`cntfrq_el0` is carried rather than assumed because `timer_now_us()` is only
correct if the frequency is read from hardware rather than hard-coded, and a
snapshot that cannot be dated is a snapshot someone has to decode by hand.

### 4.5 Digest

The final 32 bytes are SHA-256 over everything from offset 0 to the end of
the system-register list. It exists so that a record staged in SRAM can be
checked for staleness: a snapshot left over from an earlier boot, or one
partly overwritten by a stray write, should fail this check rather than be
streamed to someone debugging a different fault.

---

## 5. The console (hex) path

Unchanged, and specified here only so the difference is on the record:

- 16 bytes per row, element width 1/2/4/8, optional ASCII column.
- Runs of identical rows collapse to `*` — **a console feature only**. The
  binary stream emits every byte.
- Capped at `DUMP_MAX_LENGTH` (1 MiB) per command.
- Progress every 4 KiB, because without it a 1 MiB dump over 115200 baud looks
  hung for two minutes.
