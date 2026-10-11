# RPWN — the Rust driver that replaces the legacy tool

This directory is where the device-side DFU driver lives. It replaced the
vendored Python tool that used to sit here (`ipwndfu/`, now removed): same
device work, this project's own implementation, with every constant it uses
measured from the SecureROM images in the corpus and from runs of those images
in this project's emulator.

```sh
cargo build --release --manifest-path rust/Cargo.toml --locked
cargo test  --release --manifest-path rust/Cargo.toml     # all suites
```

The binary lands at `rust/target/release/rpwn`. `goat` runs it for `goat pwn`,
finding it in that in-tree location automatically, so neither a PATH entry nor
an environment variable is needed after a build:

```sh
./goat/goat pwn                  # goat -> rpwn -p, found in-tree
GOAT_RPWN=/somewhere/rpwn ./goat/goat pwn   # or name it explicitly
```

If the binary is not there yet, `goat pwn` says so and prints the build line
rather than failing on a `No such file or directory` from the exec.

## Layout

| Path | What it is |
|---|---|
| `rust/src/profile.rs` | the per-**build** measured constants, and the tests that decode them back out of the images |
| `rust/src/payload.rs` | the descriptor encoder and the fake page-table builder |
| `rust/payload/checkm8_payload.S` | the device-side payload source, assembled by `rust/build.rs` |
| `rust/src/cm8.rs` | the original checkm8 stage sequence: plan, refusals, and where it stops |
| `rust/src/checkm8.rs` | the port of the legacy Python tool, kept for the parts and the trigger the measured path does not cover yet |

## The two A11 builds

The corpus carries two A11 SecureROM images and they are different images, not
two copies: the USB/context code sits at different addresses in each. `profile`
therefore carries both, and the device's own `SRTG:[iBoot-…]` serial fragment
picks between them — the CPID alone is not enough. Same reason the payload
source takes its per-part gadget addresses as build-time defines rather than
hard-coding one build's.

## What is measured, and what is not

[docs/CHECKM8_IMPLEMENTATION.md](../docs/CHECKM8_IMPLEMENTATION.md) is the
record. The short version: the gadget family, the translation regime, the
descriptor encoding and the callback primitive are measured and tested; the
point at which the corrupted object's callback fires is not, and `cm8.rs`
stops there instead of guessing.
