/*
 * MMIO barrier implementation for AArch64
 * Provides memory barrier for MMIO operations
 */

#include "mmio.h"

void mmio_barrier(void) {
    /* DSB SY - Data Synchronization Barrier
     * Ensures all explicit memory accesses before the barrier
     * are complete before any after the barrier. */
    __asm__ volatile("dsb sy" ::: "memory");
}