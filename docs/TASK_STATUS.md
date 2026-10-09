# Requested bare-metal task status

This file records what is complete in the active dr1zzle build used by the root
`Makefile`. The separate `src/` tree is not part of that build, so files there
do not count as completed dr1zzle features until they are integrated and tested.

| Task | Status | Evidence |
| --- | --- | --- |
| Vector table + EL1h entry | Partial | `arch/aarch64/start.S` installs `VBAR_EL1`/`VBAR_EL2`, but every vector currently branches to a halt loop. It is not a full EL1h dispatch table. |
| MMU identity map + device regions | Not complete | No MMU setup is built by the root `Makefile`. |
| UART PL011/S5L @ 115200 | Partial | QEMU PL011 polling console exists in `kernel/qemu_virt.c`; S5L UART and baud programming are not in the active build. |
| Timer CNTPCT_EL0 @ 24 MHz | Partial | QEMU target binds `drizzle_time_ms()` to `CNTPCT_EL0 / 24000`; no interrupt/timer driver. |
| Exception handlers Sync/IRQ/FIQ/SError | Not complete | Active vectors halt; no C exception handlers are wired. |
| Shell memdump/memwrite/time/reboot/help | Partial | Active monitor has `help`, `memdump`, `memwrite`, `time`, and a QEMU-safe `reboot` stub. `reboot` is not hardware reset. |
| USB PHY + DWC2 core init | Not complete | No USB PHY or DWC2 source is included by the active build. |
| CDC-ECM descriptors EP0/EP1/EP2 | Not complete | No CDC-ECM descriptors are present in the active build. |

Current verified commands:

- `make test`
- `make -B image`
- `make qemu-smoke`
