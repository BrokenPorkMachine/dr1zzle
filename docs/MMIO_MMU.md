# MMIO and MMU layer

The A11 payload now has two small interfaces for hardware access:
`include/mmio.h` provides ordered 8/16/32/64-bit transactions, and
`include/mmu.h` exposes the identity-map bring-up sequence.

Use the ordered accessors for standalone register transactions:

```c
mmio_write32(PMGR_BASE + 0x10, value);
uint32_t status = mmio_read32(UART_BASE + 0x18);
```

`mmio_barrier()` is a full `dsb sy` on AArch64. The relaxed variants only do a
volatile access and are for a sequence already enclosed by a driver-owned
barrier. The UART, USB, PMGR, timer polling, and display command paths use the
ordered accessors. Register layouts and bit meanings remain board-specific and
stay in their driver files.

`mmu_init()` clears static, 4 KiB-aligned tables, maps the A11 SRAM and device
windows, and programs MAIR, TCR, and TTBR0. It does not turn translation on.
The default map uses 4 KiB identity pages, normal write-back memory for SRAM,
and Device-nGnRnE read/write, execute-never memory for MMIO. SRAM remains
executable so an identity-mapped instruction fetch can continue after enabling
the MMU. MMIO is read/write because control registers must be writable.

Additional identity ranges may be added with `mmu_map_identity()` after
`mmu_init()` and before `mmu_enable()`. Mapping is rejected after enable, for
invalid attributes, overflowing ranges, or an attribute conflict with an
existing page. Unaligned base/size values are rounded outward to 4 KiB; callers
should provide page-aligned ranges when they need strict ownership boundaries.

`mmu_disable()` clears M, C, and I with barriers. Translation remains disabled
by default in `src/main.c` because the A11 table and peripheral addresses have
not been validated on silicon. Enable it only in a hardware test build with
`DR1ZZLE_ENABLE_MMU`.
