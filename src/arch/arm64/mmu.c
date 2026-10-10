#include "memory_map.h"
#include "mmu.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Four-level identity map.
 *
 * The previous version used a single 512-entry L0 table indexed by
 * (vaddr >> 39), which only describes the first 512GB of the A11 map and
 * therefore mapped nothing at all: SRAM sits at 0x180000000 and index 0
 * covered 0..0x80000000. It also wrote 2MB block descriptors into what it
 * treated as an L0 table, where the block size is 1GB.
 *
 * This walks L0 -> L1 -> L2 -> L3 and places 4KB page descriptors at L3.
 * Keeping the final mapping page-granular prevents a small MMIO window from
 * accidentally claiming the rest of its surrounding 2MB block.
 */

#define L0_ENTRIES   512
#define L1_ENTRIES   512
#define L2_ENTRIES   512
#define L3_ENTRIES   512

/* Room for the distinct table windows we touch. The current map needs 86 L3
 * tables (one per 2MB L2 window); leave headroom for future device ranges. */
#define MAX_L1_TABLES 4
#define MAX_L2_TABLES 16
#define MAX_L3_TABLES 128

static uint64_t l0_table[L0_ENTRIES] __attribute__((aligned(4096)));
static uint64_t l1_tables[MAX_L1_TABLES][L1_ENTRIES] __attribute__((aligned(4096)));
static uint64_t l2_tables[MAX_L2_TABLES][L2_ENTRIES] __attribute__((aligned(4096)));
static uint64_t l3_tables[MAX_L3_TABLES][L3_ENTRIES] __attribute__((aligned(4096)));

static unsigned int l1_used;
static unsigned int l2_used;
static unsigned int l3_used;
static int tables_ready;
static int tables_building;

/* Parallel record of which pool slot backs a given index, so lookups do not
 * have to compare descriptors. */
static struct {
    unsigned int index;
    uint64_t *table;
} l1_map[MAX_L1_TABLES];
static struct {
    unsigned int index;
    uint64_t *parent;
    uint64_t *table;
} l2_map[MAX_L2_TABLES];
static struct {
    unsigned int index;
    uint64_t *parent;
    uint64_t *table;
} l3_map[MAX_L3_TABLES];

typedef struct {
    uint64_t base;
    uint64_t size;
} region_t;

static const region_t device_regions[] = {
    { UART_BASE,       0x10000 },
    { TIMER_BASE,      0x10000 },
    { AIC_BASE,        0x10000 },
    { PMGR_BASE,       0x100000 },
    { MAILBOX_BASE,    0x10000 },
    { DCP_BASE,        0x40000 },
    { NOR_BASE,        0x1000000 },
    { BLOCK_BASE,      0x400000 },
    { NAND_BASE,       0x8000000 },
    { USB_BASE,        0x10000 },
    { WATCHDOG_BASE,   0x10000 },
    { GPIO_BASE,       0x100000 },
    { I2C_BASE,        0x10000 },
    { SPI_BASE,        0x10000 },
    { PMU_BASE,        0x10000 },
    { SPMI_BASE,       0x10000 },
    { THERMAL_BASE,    0x10000 },
    { USB_PHY_BASE,    0x10000 },
    { USB_MUX_BASE,    0x10000 },
    { USB_PD_BASE,     0x10000 },
    { PANEL_BASE,      0x10000 },
    { DSI_PHY_BASE,    0x10000 },
    { RASTER_BASE,     0x10000 },
    { TOUCH_BASE,      0x10000 },
    { AUDIO_BASE,      0x10000 },
    { BT_BASE,         0x10000 },
    { WIFI_BASE,       0x10000 },
    { CAMERA_BASE,     0x10000 },
    { SENSORHUB_BASE,  0x10000 },
    { ACE2_BASE,       0x10000 },
    { SECURE_ROM_BASE, 0x100000 },
};

#define DEVICE_REGION_COUNT (sizeof(device_regions) / sizeof(device_regions[0]))

/* AF (bit 10) is forced on for every stage-1 page descriptor here. */
#define AF               (1ULL << 10)

#define PAGE_DESC(pa, attr, ap, xn)                                     \
    (((pa) & ~(uint64_t)(PAGE_SIZE - 1)) | DESC_VALID | DESC_TABLE |    \
     AF | DESC_NS | DESC_ATTR_IDX(attr) | (ap) | (xn))

#define TABLE_DESC(ptr)                                                 \
    ((uint64_t)(ptr) | DESC_VALID | DESC_TABLE)

static uint64_t *l1_for(unsigned int index) {
    for (unsigned int i = 0; i < l1_used; i++) {
        if (l1_map[i].index == index) return l1_map[i].table;
    }
    if (l1_used >= MAX_L1_TABLES) return NULL;

    uint64_t *t = &l1_tables[l1_used][0];
    memset(t, 0, L1_ENTRIES * sizeof(uint64_t));
    l0_table[index] = TABLE_DESC(t);
    l1_map[l1_used].index = index;
    l1_map[l1_used].table = t;
    l1_used++;
    return t;
}

static uint64_t *l2_for(uint64_t *l1, unsigned int index) {
    for (unsigned int i = 0; i < l2_used; i++) {
        if (l2_map[i].parent == l1 && l2_map[i].index == index)
            return l2_map[i].table;
    }
    if (l2_used >= MAX_L2_TABLES) return NULL;

    uint64_t *t = &l2_tables[l2_used][0];
    memset(t, 0, L2_ENTRIES * sizeof(uint64_t));
    l1[index] = TABLE_DESC(t);
    l2_map[l2_used].index = index;
    l2_map[l2_used].parent = l1;
    l2_map[l2_used].table = t;
    l2_used++;
    return t;
}

static uint64_t *l3_for(uint64_t *l2, unsigned int index) {
    for (unsigned int i = 0; i < l3_used; i++) {
        if (l3_map[i].parent == l2 && l3_map[i].index == index)
            return l3_map[i].table;
    }
    if (l3_used >= MAX_L3_TABLES) return NULL;

    uint64_t *t = &l3_tables[l3_used][0];
    memset(t, 0, L3_ENTRIES * sizeof(uint64_t));
    l2[index] = TABLE_DESC(t);
    l3_map[l3_used].index = index;
    l3_map[l3_used].parent = l2;
    l3_map[l3_used].table = t;
    l3_used++;
    return t;
}

/* Map [vaddr, vaddr+size) with 4KB pages, identity only. 0 on success. */
static int map_pages(uint64_t vaddr, uint64_t paddr, uint64_t size,
                     uint64_t attr, uint64_t ap, int executable) {
    if (size == 0 || size > UINT64_MAX - vaddr) return -1;
    if (vaddr != paddr) return -1; /* identity map only */

    uint64_t start = vaddr & ~(uint64_t)(PAGE_SIZE - 1);
    uint64_t limit = vaddr + size;
    if (limit > UINT64_MAX - (PAGE_SIZE - 1)) return -1;
    uint64_t end = (limit + PAGE_SIZE - 1) & ~(uint64_t)(PAGE_SIZE - 1);

    if (end < start) return -1;

    for (uint64_t va = start; va < end; ) {
        unsigned int i0 = (unsigned int)((va >> 39) & 0x1FF);
        unsigned int i1 = (unsigned int)((va >> 30) & 0x1FF);
        unsigned int i2 = (unsigned int)((va >> 21) & 0x1FF);
        unsigned int i3 = (unsigned int)((va >> 12) & 0x1FF);

        uint64_t *l1 = l1_for(i0);
        if (!l1) return -1;

        uint64_t *l2 = l2_for(l1, i1);
        if (!l2) return -1;

        uint64_t *l3 = l3_for(l2, i2);
        if (!l3) return -1;

        uint64_t descriptor = PAGE_DESC(va, attr, ap,
                                        executable ? 0 : (DESC_PXN | DESC_UXN));
        if (l3[i3] != 0) {
            /* Overlap is only harmless when the descriptor is identical.
             * Silently retaining the first attribute can turn a device
             * register into cacheable memory or vice versa. */
            if (l3[i3] != descriptor) return -1;
            if (va == end - PAGE_SIZE) break;
            va += PAGE_SIZE;
            continue;
        }

        l3[i3] = descriptor;

        /* Avoid wrapping the loop counter for a caller-supplied range near
         * the top of the address space. */
        if (va == end - PAGE_SIZE) break;
        va += PAGE_SIZE;
    }
    return 0;
}

int mmu_map_identity(uint64_t base, uint64_t size,
                     enum mmu_memory_type type, enum mmu_access access,
                     int executable) {
    if (type != MMU_MEMORY_NORMAL && type != MMU_MEMORY_DEVICE)
        return -1;
    if (access != MMU_ACCESS_RW && access != MMU_ACCESS_RO)
        return -1;
    if ((!tables_building && !tables_ready) || mmu_enabled()) return -1;
    return map_pages(base, base, size, (uint64_t)type,
                      access == MMU_ACCESS_RO ? DESC_AP_RO : DESC_AP_RW,
                      executable);
}

int mmu_init(void) {
    if (mmu_enabled()) return -1;
    tables_ready = 0;
    tables_building = 1;
    memset(l0_table, 0, sizeof(l0_table));
    memset(l1_map, 0, sizeof(l1_map));
    memset(l2_map, 0, sizeof(l2_map));
    memset(l3_map, 0, sizeof(l3_map));
    l1_used = 0;
    l2_used = 0;
    l3_used = 0;

    /* SRAM: normal memory, read-write, executable. Payload, stack and heap
     * all live inside it. */
    if (mmu_map_identity(SRAM_BASE, SRAM_SIZE, MMU_MEMORY_NORMAL,
                         MMU_ACCESS_RW, 1) != 0) {
        tables_building = 0;
        return -1;
    }

    /* Every MMIO window: Device-nGnRnE, read-write, never executable. Device
     * drivers must be able to write control registers; the EL1 read-only
     * encoding would fault those writes once the MMU is enabled. */
    for (size_t i = 0; i < DEVICE_REGION_COUNT; i++) {
        if (mmu_map_identity(device_regions[i].base, device_regions[i].size,
                             MMU_MEMORY_DEVICE, MMU_ACCESS_RW, 0) != 0) {
            tables_building = 0;
            return -1;
        }
    }

    /* AttrIdx 0 = Normal WBWA, AttrIdx 1 = Device-nGnRnE. */
    uint64_t mair = ((uint64_t)MAIR_ATTR_DEVICE << 8) | MAIR_ATTR_NORMAL;
    __asm__ volatile("msr mair_el1, %0" :: "r"(mair) : "memory");

    /* T0SZ=25: 64-25 = 39 bits of VA indexed, i.e. 512 L0 entries each
     * covering 1GB. TG0=0 (4KB granule) is required because the walk
     * reaches L2. IPS=2 is a 40-bit physical address width.
     * IRGN0=ORGN0=1 (writeback), SH0=3 (inner shareable). */
    uint64_t tcr = (25ULL << 0)
                 | (3ULL  << 8)    /* SH0   = inner shareable */
                 | (1ULL  << 10)   /* ORGN0 = writeback */
                 | (1ULL  << 12)   /* IRGN0 = writeback */
                 | (0ULL  << 14)   /* TG0   = 4KB granule */
                 | (0ULL  << 23)   /* EPD   = 1 (no walk for faulting) */
                 | (2ULL  << 32);  /* IPS   = 40-bit PA */
    __asm__ volatile("msr tcr_el1, %0" :: "r"(tcr) : "memory");

    __asm__ volatile("msr ttbr0_el1, %0" :: "r"((uint64_t)l0_table) : "memory");
    __asm__ volatile("dsb ishst" ::: "memory");
    __asm__ volatile("isb" ::: "memory");
    __asm__ volatile("tlbi vmalle1; dsb sy; isb" ::: "memory");

    tables_building = 0;
    tables_ready = 1;
    return 0;
}

/* Enable translation and caches. Deliberately separate from mmu_init so
 * bring-up can run unmapped: if a descriptor is ever wrong, we find out from
 * a data abort we can print, rather than an instruction fetch that never
 * returns. */
void mmu_enable(void) {
    __asm__ volatile(
        "dsb  sy               \n"
        "mrs  x0, sctlr_el1   \n"
        "orr  x0, x0, #(1 << 0)  \n"   /* M */
        "orr  x0, x0, #(1 << 2)  \n"   /* C */
        "orr  x0, x0, #(1 << 12) \n"   /* I */
        "msr  sctlr_el1, x0    \n"
        "isb                    \n"
        ::: "x0", "memory");
}

void mmu_disable(void) {
    __asm__ volatile(
        "mrs  x0, sctlr_el1   \n"
        "bic  x0, x0, #(1 << 0)  \n"
        "bic  x0, x0, #(1 << 2)  \n"
        "bic  x0, x0, #(1 << 12) \n"
        "dsb  sy               \n"
        "msr  sctlr_el1, x0    \n"
        "isb                    \n"
        ::: "x0", "memory");
}

int mmu_enabled(void) {
    uint64_t sctlr;
    __asm__ volatile("mrs %0, sctlr_el1" : "=r"(sctlr));
    return (sctlr & 1u) != 0;
}
