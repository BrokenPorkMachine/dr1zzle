#include <drizzle/hardware.h>
#include "qemu_budget.h"

/* QEMU virt with 128 MiB RAM. Only the arena is owned by this monitor.
 * Budgets describe resource ceilings, not a claim about physical AP support. */
#define QEMU_REGIONS \
    { {0x40000000u, 128u * 1024u * 1024u, DRIZZLE_RAM}, \
      {0x09000000u, 0x1000u, DRIZZLE_MMIO} }
const drizzle_hw_profile drizzle_hw_qemu_small = {
    DRIZZLE_HW_VERSION, "qemu-virt-small", 2, QEMU_REGIONS,
    0x40080000u, QEMU_SMALL_ARENA,
    {QEMU_SMALL_IMAGE, QEMU_SMALL_HEAP, QEMU_SMALL_STACK, QEMU_SMALL_RESERVE}
};
const drizzle_hw_profile drizzle_hw_qemu_monitor = {
    DRIZZLE_HW_VERSION, "qemu-virt-monitor", 2, QEMU_REGIONS,
    0x40080000u, QEMU_MONITOR_ARENA,
    {QEMU_MONITOR_IMAGE, QEMU_MONITOR_HEAP, QEMU_MONITOR_STACK, QEMU_MONITOR_RESERVE}
};
