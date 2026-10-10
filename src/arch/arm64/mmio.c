#include "mmio.h"
#include "memory_map.h"

void mmio_barrier(void) {
#if defined(__aarch64__)
    /* Full-system ordering is conservative and works for the SoC fabric as
     * well as the CPU. The API is used at low frequency during bring-up. */
    __asm__ volatile("dsb sy" ::: "memory");
#else
    __atomic_signal_fence(__ATOMIC_SEQ_CST);
#endif
}

void map_range(uint64_t va, uint64_t pa, uint64_t size, int attr, int perm, bool uncache)
{
    (void)va; (void)pa; (void)size; (void)attr; (void)perm; (void)uncache;
    /* For now, identity mapping is already set up in the page tables.
     * This function would set up additional page table entries if needed.
     * The current implementation assumes 1:1 mapping for the device regions. */
}
