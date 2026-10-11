# Goat (Rust)

This crate is the Rust implementation of the Goat command line. The stable
repository entrypoint is `./goat/goat`; it runs this binary and never imports
the legacy Python command line.

Build with:

```sh
cargo build --release --manifest-path goat-rust/Cargo.toml --locked
```

The binary supports key generation, sealing, inspection, verification,
unsealing, ELF/raw image planning, TCP push/install/shell, RPWN handoff, and
the bundled usbr34ker firmware workflow. All host-side Goat behavior is Rust;
the `goat/` directory contains only payload assets and firmware.
