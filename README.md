# dr1zzle

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
- Host unit tests for the libc, compiled against the dr1zzle headers/runtime

## Quick start

```sh
make test       # host verification for libdrizzle
make qemu       # build and launch the generic Arm development image
make qemu-smoke # boot QEMU, exercise monitor commands, verify output
```

## Layout

- `include/` — public, self-contained libc headers
- `lib/` — freestanding libc implementation
- `kernel/` — portable monitor entry point and QEMU `virt` console
- `arch/aarch64/` — AArch64 reset entry and linker script
- `docs/` — clean-room boundaries, architecture, and roadmap

See `docs/TASK_STATUS.md` for the current completion matrix for requested
bare-metal features.

## Status and scope

This is an intentionally narrow foundation, not a replacement for pongoOS. The
next useful steps are exception handling, a data-only board description, timer
support, and a testable command parser. Keep physical-device support as a
  separate, explicitly reviewed project. The current boot image deliberately
avoids exploit delivery and physical-device payload packaging.
