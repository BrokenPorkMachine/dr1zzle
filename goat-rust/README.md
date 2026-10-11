# Goat (Rust)

This crate is the Rust implementation of the Goat command line. The stable
repository entrypoint is `./goat/goat`; it runs this binary and never imports
the legacy Python command line.

Build with:

```sh
cargo build --release --manifest-path goat-rust/Cargo.toml --locked
```

The binary supports `usbr34ker list`, `usbr34ker flash`,
`usbr34ker walkthrough`, `inspect <container>`, `verify <container>`,
`unseal <container> --key-hex HEX`, and `pwn`. `verify` checks both the
embedded certificate self-signature and the container signature using the
certificate public key. `unseal` performs the same checks before decrypting.
The Python files under `goat/` are retained only as historical protocol and
test references; they are not an executable implementation or dispatch path.
