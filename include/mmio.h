#ifndef DR1ZZLE_MMIO_H
#define DR1ZZLE_MMIO_H

#include <stdint.h>
#include <stdbool.h>

/*
 * MMIO accessors for the AArch64 payload.
 *
 * The volatile access prevents the compiler from removing or coalescing a
 * register transaction.  The barriers order the transaction against normal
 * memory and make writes visible before a caller starts polling a device.
 * Drivers should use the relaxed forms only for a sequence whose ordering is
 * supplied by an enclosing barrier.
 */
void mmio_barrier(void);

static inline uint8_t mmio_read8_relaxed(uintptr_t address) {
    return *(volatile uint8_t *)address;
}

static inline uint16_t mmio_read16_relaxed(uintptr_t address) {
    return *(volatile uint16_t *)address;
}

static inline uint32_t mmio_read32_relaxed(uintptr_t address) {
    return *(volatile uint32_t *)address;
}

static inline uint64_t mmio_read64_relaxed(uintptr_t address) {
    return *(volatile uint64_t *)address;
}

static inline void mmio_write8_relaxed(uintptr_t address, uint8_t value) {
    *(volatile uint8_t *)address = value;
}

static inline void mmio_write16_relaxed(uintptr_t address, uint16_t value) {
    *(volatile uint16_t *)address = value;
}

static inline void mmio_write32_relaxed(uintptr_t address, uint32_t value) {
    *(volatile uint32_t *)address = value;
}

static inline void mmio_write64_relaxed(uintptr_t address, uint64_t value) {
    *(volatile uint64_t *)address = value;
}

static inline uint8_t mmio_read8(uintptr_t address) {
    mmio_barrier();
    uint8_t value = mmio_read8_relaxed(address);
    mmio_barrier();
    return value;
}

static inline uint16_t mmio_read16(uintptr_t address) {
    mmio_barrier();
    uint16_t value = mmio_read16_relaxed(address);
    mmio_barrier();
    return value;
}

static inline uint32_t mmio_read32(uintptr_t address) {
    mmio_barrier();
    uint32_t value = mmio_read32_relaxed(address);
    mmio_barrier();
    return value;
}

static inline uint64_t mmio_read64(uintptr_t address) {
    mmio_barrier();
    uint64_t value = mmio_read64_relaxed(address);
    mmio_barrier();
    return value;
}

static inline void mmio_write8(uintptr_t address, uint8_t value) {
    mmio_barrier();
    mmio_write8_relaxed(address, value);
    mmio_barrier();
}

static inline void mmio_write16(uintptr_t address, uint16_t value) {
    mmio_barrier();
    mmio_write16_relaxed(address, value);
    mmio_barrier();
}

static inline void mmio_write32(uintptr_t address, uint32_t value) {
    mmio_barrier();
    mmio_write32_relaxed(address, value);
    mmio_barrier();
}

static inline void mmio_write64(uintptr_t address, uint64_t value) {
    mmio_barrier();
    mmio_write64_relaxed(address, value);
    mmio_barrier();
}

static inline void mmio_set32(uintptr_t address, uint32_t mask) {
    mmio_write32(address, mmio_read32(address) | mask);
}

static inline void mmio_clear32(uintptr_t address, uint32_t mask) {
    mmio_write32(address, mmio_read32(address) & ~mask);
}

/* Map a physical address range into the virtual address space.
 * va: virtual address
 * pa: physical address
 * size: size of the mapping
 * attr: memory attributes (0=Device, 1=Normal, 2=Normal NC, etc.)
 * perm: permissions (0=RW, 1=RO, 2=RWX, etc.)
 * uncache: whether to use uncacheable mapping
 */
void map_range(uint64_t va, uint64_t pa, uint64_t size, int attr, int perm, bool uncache);

#endif
