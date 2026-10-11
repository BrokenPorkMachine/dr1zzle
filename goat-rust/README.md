# Goat (Rust)

This crate is the Rust-native Goat command boundary. It owns the RP2350
`usbr34ker` workflow and dispatches Apple DFU work to the Rust `rpwn` binary.

Build with:

```sh
cargo build --release --manifest-path goat-rust/Cargo.toml --locked
```

The binary supports `usbr34ker list`, `usbr34ker flash`,
`usbr34ker walkthrough`, `inspect <container>`, `verify <container>`,
`unseal <container> --key-hex HEX`, and `pwn`. `verify` checks both the
embedded certificate self-signature and the container signature using the
certificate public key. `unseal` performs the same checks before decrypting.
The remaining sealing/container and
kload command families are being ported behind the same command boundary;
the legacy Python modules remain isolated until their Rust implementations
pass equivalent byte and transport tests.
