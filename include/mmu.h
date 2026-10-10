#ifndef DR1ZZLE_MMU_H
#define DR1ZZLE_MMU_H

#include <stdint.h>

enum mmu_memory_type {
    MMU_MEMORY_NORMAL = 0,
    MMU_MEMORY_DEVICE = 1
};

enum mmu_access {
    MMU_ACCESS_RW = 0,
    MMU_ACCESS_RO = 1
};

/* Build the identity map and program MAIR/TCR/TTBR0. Translation remains off. */
int mmu_init(void);

/* Add an identity-mapped range after mmu_init and before mmu_enable. */
int mmu_map_identity(uint64_t base, uint64_t size,
                     enum mmu_memory_type type, enum mmu_access access,
                     int executable);

void mmu_enable(void);
void mmu_disable(void);
int mmu_enabled(void);

#endif
