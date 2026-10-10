# dr1zzle OpenSEP

`dr1zzle` is a clean-room, freestanding C boot-monitor foundation. It is built
around an independently-written libc (`libdrizzle`) and a safe QEMU Arm `virt`
development target. It does not include exploitation, signing bypasses, device
restore, Apple-specific hardware maps, or physical-device transport code.

## What works today

- Freestanding AArch64 startup, linker layout, and QEMU `virt` UART output
- A usable custom libc: strings, memory, ctype, integer conversion, bounded
  allocation, `qsort`, and bounded `snprintf`/`vsnprintf`
- An interactive QEMU monitor with `help`, `info`, `heap`, `net`, `clear`, and
  `reboot` stub commands
- A freestanding Ethernet/IPv4 core with ARP reply/learning, ICMP echo reply,
  UDP send/receive queues, endpoint helpers, DNS/NAT/TCP API stubs, and
  packet-path tests
- A transport-neutral Wi-Fi state/link driver with a tested fake-SDIO backend;
  silicon radio support still requires the board's bus and firmware contract
- Host unit tests for the libc, compiled against the dr1zzle headers/runtime
- On the A11 `src/` build: PMGR clocks/resets, GPIO pinmux, polling I2C and SPI
  masters, the watchdog, and AIC v1 interrupt dispatch — all implemented and
  artifact-tested, none yet run on silicon
- A completed specification for what this tree does not have yet: dumps as
  framed, checksummed streams, CPU register snapshots, and SSH/SCP on port
  443 ([SPEC.md](SPEC.md) v2.0)

## Quick start

```sh
make               # A11 core (build/a11-payload.bin) + firmware (build/firmware/dr1zzle.bin)
make deploy        # goat kload the core into a pwndfu'd device
make firmware-record  # the firmware wrapped as a NAND firmware record (dr1zzle.fw)
make profiles      # build the 256 KiB portable monitor profile
make profiles-qemu # boot the portable monitor on QEMU virt
make qemu          # display window plus interactive UART in this terminal
make qemu-headless # UART-only QEMU monitor
make profiles-test # sanitizer, linker-budget, and QEMU boot checks
make phase4-test   # host-test AES, APFS, and KBAG primitives
```

## Layout

- `include/` — public, self-contained libc headers
- `lib/` — freestanding libc implementation
- `kernel/` — portable monitor entry point and QEMU `virt` console
- `arch/aarch64/` — AArch64 reset entry and linker script
- `docs/` — clean-room boundaries, architecture, roadmap
- `src/` — the A11 payload tree: drivers, shell, research modules
- `SPEC.md` — master specification (v2.0), including dumps, snapshots and SSH/SCP

See [hardware profiles](docs/HARDWARE_PROFILES.md) for memory budgets and build
selection. The root default build targets the separate A11 `src/` tree; use the
`profiles` targets above for the portable monitor.

`scripts/run-qemu.sh` builds the portable monitor profile for QEMU. Its default
mode mirrors text to a 640×240 display window while keeping UART input and
output in the invoking terminal. Use `--headless` for the small UART-only
profile. Set `DR1ZZLE_QEMU_DISPLAY=default` if QEMU's Cocoa display backend is
unavailable. Press Ctrl-C to stop QEMU.

See [phase 4](docs/PHASE4.md) for the storage/crypto command reference and
hardware-verification boundaries.

Phase 4 storage/crypto code is now part of the root A11 build: NAND page
access, APFS metadata/B-tree extent reading, AES-256 known vectors, and bounded
KBAG parsing. NAND/AES register maps still require A11 silicon verification;
GID-derived key bytes are intentionally not printed by the shell.

The core peripheral layer is now complete as well: PMGR clocks/resets, GPIO
pinmux, a polling I2C master, a polling SPI master, the watchdog (disarmed at
boot on purpose), and the AIC v1 interrupt controller that replaced the old
poll-only IRQ dispatch. These are implemented and register-verified, but not
silicon-verified — each block prints what it read back, and each has a shell
command, so the first real transfer can be diagnosed without a debugger. See
[docs/TASK_STATUS.md](docs/TASK_STATUS.md) for the completion matrix.

See `docs/TASK_STATUS.md` for the current completion matrix for requested
bare-metal features.

Booting a built image on a device is `goat`'s job, and the A11 build is two
images now. The **core** (`make deploy`, i.e. `goat kload
build/a11-payload.elf`) is the login prompt: it brings up the console, NAND,
USB and the goatloader, then offers a menu. The **firmware**
(`build/firmware/dr1zzle.elf`/`.bin`) is the full monitor shell; it is laid
down on demand (`make deploy-firmware KEY_HEX=<hex>` seals it and pushes it
with `--run`, or the core menu loads a NAND slot with `run <n>`). The split
exists because the old single flat image outgrew the pwndfu command window —
see [the multi-stage design](docs/MULTISTAGE_DESIGN.md) for the layout, the
placement rule, and the firmware format. See [docs/GOAT.md](docs/GOAT.md)
for the register convention and the toggles (`--no-pwn`, `--no-run`,
`--stage-container`). Once the firmware is up it paints an on-screen menu
(fixed panel, output pane below it, pinned status line — see
[docs/MENU.md](docs/MENU.md)) and takes input on the serial console.

See [dumps and snapshots](docs/DUMP_WIRE_FORMAT.md) for the byte-level formats,
[SSH/SCP on 443](docs/SSH_SCP_443.md) for the remote-access protocol, and
[transport](docs/TRANSPORT.md) for link selection and the streaming scheduler.

## Status and scope

This is an intentionally narrow foundation, not a replacement for pongoOS. The portable monitor has validated data-only board profiles and enforced memory
budgets. Physical board adapters and silicon verification remain separate work. Keep physical-device support as a
  separate, explicitly reviewed project. The current boot image deliberately
avoids exploit delivery and physical-device payload packaging.

SSH/SCP is **specified, not implemented**. [SPEC.md](SPEC.md) v2.0 defines the
remote-access surface: SSH-2 with X25519, an Ed25519 host key and
ChaCha20-Poly1305, public-key authentication for a single operator account,
SFTP and legacy SCP over the dump registry, all on TCP 443, with the legacy
plaintext console on port 23 off by default. The repository still contains
**no** SSH code — none of the primitives in §6 of
[docs/SSH_SCP_443.md](docs/SSH_SCP_443.md) are written yet — and the QEMU
profile still has no network device, so end-to-end interop cannot be verified
here yet. What exists is the specification, the wire formats
([docs/DUMP_WIRE_FORMAT.md](docs/DUMP_WIRE_FORMAT.md)), and an implementation
order that puts every host-testable block first.

The same is true of the dump and register-snapshot subsystem: the source
registry and the hex dump path exist today, and the framing, chunking,
integrity checking and scheduling that make a 128 MB NAND dump trustworthy are
specified in [docs/DUMP_WIRE_FORMAT.md](docs/DUMP_WIRE_FORMAT.md) and
[docs/TRANSPORT.md](docs/TRANSPORT.md) rather than implemented.

See [remote access](docs/REMOTE_ACCESS.md) for the pre-spec boundary record
and [Wi-Fi](docs/WIFI.md) for the radio's status.

## Remote access today: the goatloader

The A11 payload runs one TCP server, always on, at `192.168.42.1:1234`. Both
the address and the port are pre-configured on both sides, so a remote
connection needs no setup:

```sh
python3 goat/cli.py push payload.g1 --key-hex ...           # stage a sealed container
python3 goat/cli.py push payload.g1 --key-hex ... --run     # stage and hand over
python3 goat/cli.py shell                                   # monitor console over TCP
```

The listener is bound during bring-up, before the shell starts, and there is no
interface that stops it: `goat push`, `goat shell` and the sealed-container flow
are all a conversation with it. See [goatloader](docs/GOATLOADER.md) for the
protocol, the authentication boundary, and what it deliberately does not do.
`make loader-test` covers the protocol on the host.

# dr1zzle
