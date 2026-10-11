# RPWN (Rust)

An original Rust DFU driver and device tooling implementation. It is the Rust-native RPWN replacement for the legacy Python driver.

The CLI, its arguments, its output and the byte layouts it puts on the wire are all
intended to match the original exactly, so this can be dropped in wherever the legacy driver was used.

## Building

Requires libusb 1.0. On macOS, `brew install libusb` is enough (the port uses the system
libusb instead of the original's bundled `libusbfinder` dylibs, which only ever supported
macOS 10.8 – 10.15).

```sh
cargo build --release
```

The binary lands at `target/release/rpwn`.

## Usage

Identical to the original:

```
USAGE: rpwn [options]
Interact with an iOS device in DFU Mode.

Basic options:
  -p				USB exploit for pwned DFU Mode
  -x				install alloc8 exploit to NOR
  -f file			send file to device in DFU Mode
Advanced options:
  --demote			demote device to enable JTAG
  --boot			boot device
  --dump=address,length		dump memory to stdout
  --hexdump=address,length	hexdump memory to stdout
  --dump-rom			dump SecureROM
  --dump-nor=file		dump NOR to file
  --flash-nor=file		flash NOR (header and firmware only) from file
  --24kpwn			install 24Kpwn exploit to NOR
  --remove-24kpwn		remove 24Kpwn exploit from NOR
  --remove-alloc8		remove alloc8 exploit from NOR
  --decrypt-gid=hexdata		AES decrypt with GID key
  --encrypt-gid=hexdata		AES encrypt with GID key
  --decrypt-uid=hexdata		AES decrypt with UID key
  --encrypt-uid=hexdata		AES encrypt with UID key
```

Like the original, `nor-backups/`, `aes-keys/` and output files are resolved relative to
the current working directory, so run from the repository root.

## Layout

| Module | Ports |
| --- | --- |
| `main.rs` | the `RPWN` driver script |
| `cli.rs` | `getopt.getopt` semantics for this exact option table |
| `libusb.rs` | the pyusb libusb1 calls the exploits depend on, plus the raw async control transfers |
| `dfu.rs` | `dfu.py` |
| `recovery.rs` | `recovery.py` |
| `dfuexec.rs` | `dfuexec.py` (`PwnedDFUDevice`, on-device AES, NOR dump/flash) |
| `usbexec.rs` | `usbexec.py` (`PwnedUSBDevice`, `exec`/`memcpy` protocol) |
| `device_platform.rs` | `device_platform.py` |
| `nor.rs` | `nor.py` (IMG2 container) |
| `image3.rs` | `image3.py` |
| `image3_24kpwn.rs` | `image3_24Kpwn.py` |
| `alloc8.rs` | `alloc8.py` |
| `checkm8.rs` | `checkm8.py` |
| `limera1n.rs` | `limera1n.py` |
| `shatter.rs` | `SHAtter.py` |
| `steaks4uce.rs` | `steaks4uce.py` |
| `shellcode.rs` | `bin/*.bin` plus the shared `0xBAD0000N` constant substitution |
| `utilities.rs` | `utilities.py` plus hex, hashing and Python-slice helpers |

## Differences from the original

Behaviour-preserving where it matters, but worth knowing:

* **Shellcode is embedded.** `bin/*.bin` are pulled in with `include_bytes!` instead of
  being read from disk, so the binary no longer needs the repository root to send a
  payload. `n88ap-iBSS-4.3.5.img3` is still read from the working directory because it is
  user-supplied.
* **`libusbfinder` is gone.** It bundled pre-patched libusb builds for macOS 10.8–10.15;
  those OS versions predate the current libusb, which is used directly.
* **`openssl` and `xxd` are gone.** `utilities.py` shelled out to both. AES-CBC is
  implemented with the `aes` crate and the hex dump reproduces xxd's exact layout
  natively, so the port has no external process dependencies.
* **`libusb_write` → `libusb_bulk_transfer`.** The deprecated `libusb_read`/`libusb_write`
  helpers were removed from libusb; the Recovery Mode upload uses the modern equivalent.
* **RAII handles.** `dfu.release_device(device)` becomes a `Drop` on the device handle.

## Tests

```sh
cargo test
```

The suite covers the parts that can be checked without hardware, and pins the byte-exact
behaviour that the exploits depend on:

* `hex_dump` output compared against real `xxd` across empty, partial, full and
  binary input at several base addresses.
* `aes_decrypt` compared against real `openssl enc -aes-{128,256}-cbc -d -nopad`.
* Every checkm8 payload for all nine supported CPIDs builds, validating all
  `0xBAD0000N` placeholders and every size assertion the original made, and the
  `overwrite` buffers have their exact documented sizes (they are the `wLength` of a
  control transfer).
* The 24Kpwn forgery lands on exactly `0x24200` bytes with the shellcode and the 460
  SecureROM bytes reproduced verbatim.
* NOR round-trips through a synthetic image, and alloc8 installs and then removes
  cleanly to restore the original bytes.
* `getopt` behaviour, including that `-fimage.dfu` treats the rest of the token as the
  argument rather than as further flags.

Anything requiring a device attached — the USB transfer paths, `dfuexec`, `usbexec` and
the exploits themselves — can only be exercised against real hardware.
