#include "memory_map.h"
#include <stddef.h>

static uint64_t l0_table[512] __attribute__((aligned(4096)));

static const struct {
    uint64_t base;
    uint64_t size;
} device_regions[] = {
    { UART_BASE,        0x10000 },
    { TIMER_BASE,       0x10000 },
    { AIC_BASE,         0x10000 },
    { PMGR_BASE,        0x100000 },
    { MAILBOX_BASE,     0x10000 },
    { DCP_BASE,         0x40000 },
    { NOR_BASE,         0x1000000 },
    { BLOCK_BASE,       0x400000 },
    { NAND_BASE,        0x8000000 },
    { USB_BASE,         0x10000 },
    { WATCHDOG_BASE,    0x10000 },
    { GPIO_BASE,        0x100000 },
    { I2C_BASE,         0x10000 },
    { SPI_BASE,         0x10000 },
    { PMU_BASE,         0x10000 },
    { SPMI_BASE,        0x10000 },
    { THERMAL_BASE,     0x10000 },
    { USB_PHY_BASE,     0x10000 },
    { USB_MUX_BASE,     0x10000 },
    { USB_PD_BASE,      0x10000 },
    { PANEL_BASE,       0x10000 },
    { DSI_PHY_BASE,     0x10000 },
    { RASTER_BASE,      0x10000 },
    { TOUCH_BASE,       0x10000 },
    { AUDIO_BASE,       0x10000 },
    { BT_BASE,          0x10000 },
    { WIFI_BASE,        0x10000 },
    { CAMERA_BASE,      0x10000 },
    { SENSORHUB_BASE,   0x10000 },
    { ACE2_BASE,        0x10000 },
    { SECURE_ROM_BASE,  0x100000 },
};

static void map_block(uint64_t *l0, uint64_t vaddr, uint64_t paddr, uint64_t size, uint64_t attr_idx, uint64_t ap) {
    uint64_t block_attrs = DESC_VALID | DESC_BLOCK | DESC_AF | DESC_NG | DESC_NS |
                           DESC_ATTR_IDX(attr_idx) | ap | DESC_PXN | DESC_UXN;
    
    uint64_t start_idx = (vaddr >> 39) & 0x1FF;
    uint64_t num_blocks = (size + BLOCK_SIZE - 1) / BLOCK_SIZE;
    
    for (uint64_t i = 0; i < num_blocks; i++) {
        uint64_t idx = start_idx + i;
        if (idx < 512) {
            uint64_t pa = paddr + i * BLOCK_SIZE;
            l0[idx] = (pa & ~(BLOCK_SIZE - 1)) | block_attrs;
        }
    }
}

void mmu_init(void) {
    for (int i = 0; i < 512; i++) {
        l0_table[i] = 0;
    }

    map_block(l0_table, SRAM_BASE, SRAM_BASE, SRAM_SIZE, 0, DESC_AP_RW);

    for (size_t i = 0; i < sizeof(device_regions)/sizeof(device_regions[0]); i++) {
        map_block(l0_table, device_regions[i].base, device_regions[i].base,
                  device_regions[i].size, 1, DESC_AP_RO);
    }

    uint64_t mair = (MAIR_ATTR_DEVICE << 8) | MAIR_ATTR_NORMAL;
    __asm__ volatile("msr mair_el1, %0" :: "r"(mair));

    uint64_t tcr = (16ULL << 0) | (0ULL << 14) | (0ULL << 23) | (5ULL << 32);
    __asm__ volatile("msr tcr_el1, %0" :: "r"(tcr));

    __asm__ volatile("msr ttbr0_el1, %0" :: "r"((uint64_t)l0_table));

    __asm__ volatile("tlbi vmalle1; dsb sy; isb" ::: "memory");
}
