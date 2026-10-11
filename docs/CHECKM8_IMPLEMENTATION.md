# The checkm8 implementation in this tree

This is the record of what was built, what it is measured from, and what it
cannot yet do. The exploit is the A-series (A5–A11) SecureROM use-after-free in
the DFU buffer handling, described publicly in the eLab forensics analysis
*"Technical analysis of the checkm8 exploit"* (a1exdandy, from the Habr
original). That analysis is the specification this implementation was written
against; the constants it needs were measured here, from this project's own
SecureROM images and from runs of those images in this project's emulator.

The implementation lives in two places, deliberately:

| Where | What |
|---|---|
| `rpwn/rust/src/profile.rs` | the per-build measured constants, plus the tests that decode them back out of the images |
| `rpwn/rust/src/payload.rs`, `rpwn/rust/build.rs`, `rpwn/rust/payload/checkm8_payload.S` | the device side: the assembled payload source, the descriptor encoder, the fake page tables |
| `rpwn/rust/src/cm8.rs` | the stage sequence, the plan, and the refusals |
| `goat/goat` | the operator entry point: `./goat/goat pwn` runs `rpwn -p` |

`rpwn/rust/src/checkm8.rs` is a *port of the legacy Python tool* and is still
used for a real trigger attempt by default (`RPWN_CHECKM8_DRY_RUN=1` stops at
the measured stage boundary instead). The original path is the one this
document is about; it replaces the port when the trigger point below is
measured, and the vendored Python tree is already gone from the repository.

## The bug, and the six stages

SecureROM's DFU code frees its io buffer on `DFU_CLRSTATUS` without clearing the
global transfer state, so the next DFU round writes through a pointer to memory
the allocator has handed out again. The analysis turns that into code execution
in six stages, and this tree implements them in the same order:

1. **Heap feng shui.** A serial-descriptor request submitted asynchronously and
   cancelled a fraction of a millisecond later stays queued mid-transaction.
   The `leak`/`no_leak` pair and a USB reset leave a hole in the heap exactly
   where the next DFU round allocates.
2. **The UAF.** An incomplete DNLOAD makes the ROM allocate its io buffer and
   record the global transfer state; CLRSTATUS frees the buffer underneath it.
3. **The overwrite.** A later request written through the stale pointer
   corrupts a heap object at a measured offset.
4. **The payload.** DNLOAD blocks land in INSECURE_MEMORY.
5. **The chain.** A callback through the corrupted object.
6. **The shellcode.** It installs the pwndfu command handler.

Stages 1, 2 and 4 are plain DFU protocol and are implemented. Stage 3 is where
this tree stops and says so: `cm8.rs` returns `Error::Unmeasured` rather than
guessing.

## The measured constant set

Every constant carries a `Source`, and the tests re-derive each one by decoding
the image with capstone and matching the instruction *shape* the constant was
measured as. A value that does not decode is a failing test, not a wrong
exploit on a device that cannot be re-secured.

The A11 values (both builds), measured from `SecureROM_t8015si_iBoot-3332.0.0.1.{14,23}`:

| Constant | .14 | .23 |
|---|---|---|
| SecureROM base | 0x100000000 | same |
| INSECURE_MEMORY (DFU image) | 0x18001C000 | same |
| TTBR0 (its stage-1 root) | 0x18000C000 | same |
| vector table (VBAR) | 0x10001B988 | same |
| `dc civac, x0 ; ret` | 0x1000004E4 | same |
| `dmb sy ; ret` | 0x1000004F0 | same |
| `msr ttbr0_el1, x0 ; isb ; ret` | 0x10000045C | same |
| `dsb ; tlbi vmalle1 ; dsb ; isb ; ret` | 0x1000004AC | same |
| `mrs x0, sctlr_el1 ; ret` | 0x100000410 | same |
| context restore (the pivot) | 0x10000C1D0 | 0x10000C294 |
| context entry (TTBR0/SP/VBAR) | 0x100008020 | 0x1000080B8 |
| the callback pair load | 0x10000A8E4 | 0x100003E78 |

Two of those rows deserve a note, because both were wrong in an earlier draft
of this document and the tests are what caught it:

* **The A11 has two builds in the corpus and they are different images.** The
  USB/context region is at different addresses in each, so a profile that mixed
  them produced a chain whose gadget was not there. The device's own serial
  names the running firmware (`SRTG:[iBoot-3332.0.0.1.23]`), and that is what
  selects the profile; the CPID alone is not enough.
* **The context entry cannot be entered at its top on every build.** The `.14`
  build zeroes arithmetic registers before `mov x30, x29`, so entering at the
  routine's start is safe. The `.23` build zeroes `x1` early and would set
  TTBR0 to zero, so its `ctx_entry` is the `mov x30, x29` site instead — after
  the zeroing, before the `msr` block. The tests catch the difference because
  they decode the constant's shape, not its address.

The translation regime was measured from a *running* SecureROM (the project's
own emulator): `TTBR0 = 0x18000c000`, `TCR_EL1 = 0x1659ca51c` (36-bit VA,
16 KiB granule, two levels), `SCTLR_EL1 = 0x8100d` — M set, **WXN set**. The
table's own descriptors were read out of guest SRAM and are what the payload's
descriptor encoder reproduces bit for bit:

| descriptor | value | meaning |
|---|---|---|
| L1[128] @ 0x18000c400 | 0x00000001000006a5 | SecureROM, block, AP read-only, AttrIndx 1 |
| L2[7] @ 0x180010038 | 0x006000018001c627 | the payload window, page, AP read-write |

The only difference between an executable page and a non-executable one in this
ROM's table is `AP[2:1]` — which is exactly the bit WXN keys on. That is why
the payload page can be made runnable by making it read-only, and why the
shellcode (which has to write the ROM's globals) needs WXN cleared first.

## The chain this tree implements

One callback through the corrupted object's pair, and then the ROM's own
context-switch machinery:

```
callback(fn = pivot, arg0 = &ctx)
  pivot      restores x16..x30, x1 and SP from ctx, and returns to ctx_entry
  ctx_entry  sets TTBR0/SP/VBAR/ELR/SPSR from x1, and returns to x29
  stage2     runs with the payload page mapped read-execute (WXN does not block
             a page it has made read-only), clears WXN, restores the ROM's own
             table, and jumps to the shellcode
  shellcode  installs the pwndfu command handler
```

The chain needs no stack pivot and no ROP graph, because the two routines it
uses are the ROM's own context save/restore pair: one gives a controlled SP and
a new translation table, and the new table maps the payload page read-execute.
The fake table is a copy of the ROM's measured table with that single entry
changed.

`rpwn/rust/src/payload.rs` builds the fake tables (2048 L2 entries, one table
entry for the SRAM window, the ROM's own block descriptor carried across) and
lay out the context struct in the restore routine's own field order: `x1` at
`+0xf8` becomes SP *and* TTBR0, `x29` at `+0xe8` becomes the return address.

## What is not measured, and is not guessed

**The trigger point.** Which DFU round's request the corrupted pair belongs to
— and therefore when, relative to the payload DNLOAD, the callback fires — is a
runtime fact. The image's call graph does not answer it statically: the eight
`usb_device_io_request` completions are reached through the ROM's own request
queue walk, which is not statically reachable from the callback gadget's
callers, and the analysis shows that walk only as a screenshot. The honest
statement is that stages 1, 2 and 4 run and stage 3 does not, and `cm8.rs`
returns that as an error rather than shipping a chain that reaches the wrong
object.

`rpwn/rust/src/cm8.rs`'s `run()` therefore stops at `Stage::Overwrite` with
`Error::Unmeasured`, and `RPWN_CHECKM8_DRY_RUN=1` makes the whole tool stop at
the same boundary while collecting transport observations. The default path
uses the port's candidate layout, which is recorded as what it is: a port of the
legacy tool, kept until the trigger is measured.

**The remaining per-part measurements.** The shellcode's four writes (the two USB
configuration descriptor globals, the serial string descriptor, the interface
request handler pointer, and the trampoline destination) are per-part addresses
that have not been measured for the A11. `rpwn/rust/payload/checkm8_payload.S`
returns a status word instead of writing a plausible address, and the profile
tests gate on the constants that *are* measured.

## The external control

The A10 is the part the analysis documents end to end. A shape scan over the
A10 image in this corpus reproduces its published values — `dc_civac`
0x10000046C, `dmb` 0x100000478, the TTBR0 writer 0x1000003E4, the TLB
invalidation 0x100000434, the callback pair load 0x10000CC4C, INSECURE_MEMORY
0x1800B0000 and TTBR0 0x1800A0000 — and `profile.rs`'s
`measured_tests::the_a10_profile_reproduces_the_published_analysis` asserts
every one of them. That agreement over a *different* part than this tree's
payload target is what makes the derivation method trustworthy rather than one
instance of it.

## Running it

```sh
cargo build --release --manifest-path rpwn/rust/Cargo.toml --locked
cargo test  --release --manifest-path rpwn/rust/Cargo.toml   # 42 tests

./goat/goat pwn                    # exploit the attached DFU device
RPWN_CHECKM8_DRY_RUN=1 rpwn -p     # stop at the measured stage boundary
```

`goat pwn` prints the plan for the attached device first: the part, the build,
the stages, and any blocker. A part checkm8 cannot reach is refused before
anything is sent, and the message names what would be needed — the A12 and A13
are reached by usbliter8, which runs on an RP2350 board as the USB host rather
than on this host's USB stack, and that is the reason rather than a guess.
