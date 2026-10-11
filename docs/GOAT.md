# goat: booting a dr1zzle image on a device

goat's `kload` (and its synonym `send`) is the ktool step: it takes a built
dr1zzle image, gets it onto a device that is in DFU, and jumps the device into
it. checkra1n pushed pongoOS with a tool of its own; this is the same job for
the payload in `src/`, done through goat's own transport.

```
goat kload build/a11-payload.elf          # exploit if needed, boot, watch
```

## What it does

1. **Plan on the host.** The image is identified and turned into a plan —
   what goes where, and the entry point — before anything touches the device.
   A bad image fails here, not half-written into SRAM.
2. **Acquire the device.** DFU must be present. If the device is only in DFU
   and not yet exploited, `goat pwn` runs first (see [pwn](#exploiting)).
3. **Write.** The plan goes out over the pwndfu command channel in 0x1000-byte
   chunks, and is read back and compared byte for byte.
4. **Jump.** The device is told to execute the entry point, with the register
   convention below.
5. **Watch.** goat polls until the DFU interface disappears, which means the
   payload's own USB core came up.

## Input forms

| Form | Recognised by | Placement |
|------|---------------|-----------|
| `build/a11-payload.elf` | ELF magic, AArch64 `ET_EXEC` | program headers: each `PT_LOAD` is written at `p_paddr`, entry from `e_entry` |
| `build/a11-payload.bin` | anything else | flat image, staged at the linker's base `0x180000000`, entry `+0x1000` |
| `payload.g1` | a sealed GOAT container | verified, then decrypted on the host and booted at the container's own `loadBase` |

The ELF is the preferred form: it places both `PT_LOAD`s exactly where the
linker put them, including the gap in front of `.data`, and it cannot go stale
relative to the map the way an `objcopy`'d `.bin` can.

`--stage` moves an image wholesale (every segment and the entry shift by the
same amount) and `--entry` overrides the entry point. For an ELF, `--entry`
conflicting with `e_entry` is an error rather than a silent override: the ELF
knows its own entry, and a remembered `--entry` from an older build is how you
boot to the wrong place.

### Sealed containers

A `.g1` used with `kload` is verified and decrypted **on the host** — the AES
key never has to travel to the device, and the plaintext that lands in SRAM is
the same bytes any other image would use:

```
goat kload payload.g1 --key-hex <64 hex chars>
```

A container sealed with `--wrap` carries the key wrapped to its certificate:

```
goat kload payload.g1 --cert goat-key.json --key-from-cert
```

`--stage-container` instead writes the sealed container into the staging window
and stops. That mode is for the device-side loader, which is the only thing
that can enter it: the container's bytes are ciphertext, so `kload` refuses to
jump into them no matter what flags are given.

## Register convention

An image launched from pwndfu state is entered with (SPEC.md §3.1,
include/goat/goat.h):

| Register | Value | Meaning |
|----------|-------|---------|
| x0 | 0 | boot device tree; there is none to hand over from the SecureROM |
| x1 | `GOAT_LAUNCH_TAG` | `'goat'`, so a payload can tell who started it |
| x2 | 0 | staged container pointer; nothing is staged for the payload |

`start.S` clears `SCTLR.I` itself, so no host-side cache invalidation is
needed for the jump: whatever the boot firmware left in the I-cache for the
region is dropped by the payload's own entry.

## Exploiting

`kload` runs checkm8 itself when the device is in DFU but not yet exploited,
because that is one user-visible action ("put this image on my device"), not
two. The exploit is still the one delegated step — the Rust Goat command
boundary calls the Rust-native `rpwn` implementation used by `goat pwn`. Pass `--no-pwn` to
require an already-pwndfu device; a device that is not pwndfu is then an error,
and the message says
to run `goat pwn`.

```
cargo build --release --manifest-path rpwn/rust/Cargo.toml --locked
```

## Practical modes

| Flag | Effect |
|------|--------|
| `--run` / `--no-run` | jump to the entry, or write-and-verify only (default: jump) |
| `--pwn` / `--no-pwn` | exploit a DFU-only device first (default: yes) |
| `--wait N` | seconds to watch for the handoff; `0` does not wait (default 15) |
| `--verify` / `--no-verify` | read the image back and compare it (default: yes) |
| `--chunk N` | bytes per pwndfu write command (default `0x1000`) |
| `--stage A` / `--entry A` | explicit placement and entry point |
| `--stage-container` | write a sealed `.g1` into the staging window instead |
| `--key-hex` / `--key-file` / `--cert` + `--key-from-cert` | AES key for a sealed container |

Turn verification off only when a link is dropping long transfers and the
readback itself is the problem; the write then proceeds unverified.

## What the handoff does and does not prove

A payload that takes control re-enumerates with its own USB core, so
`05ac:1227` going away is real evidence that the image is running. It is not
evidence that the image is running *well*: a payload that never reaches its USB
init, or that faults on the first driver, leaves the DFU interface in place and
`kload` reports a timeout after `--wait` seconds. That is the honest signal
available from the host, and it is why the payload prints its bring-up on UART.

Nothing here has been run on an A11. The transfer path (control-transfer
sequence, command framing, `memcpy`/`memset`/`exec` opcodes, and the
`SRTG`-dependent load base) is pinned by the Rust RPWN profile table;
the A11 addresses (`0x180000000` SRAM, the entry at `+0x1000`) come from this
tree's linker script and `include/memory_map.h`.

## Tests

`make goat-test` runs the Rust Goat tests: container parsing, signature checks,
placement and window rejection, the container paths (plain, wrapped, staged,
tampered), and the device-side flow against a stub that records every write,
every readback, the register order of the jump, and the handoff poll.
