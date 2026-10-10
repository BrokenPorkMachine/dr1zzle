/*
 * Minimal NAND driver for Stage 1 only
 * Only provides nand_init, nand_read_page, nand_info
 */

#include "nand.h"
#include "mmio.h"

#define NAND_BASE_ADDR  0x200000000ULL

/* NAND Controller Registers (simplified) */
#define NAND_CTRL       0x00
#define NAND_STATUS     0x04
#define NAND_CMD        0x08
#define NAND_ADDR       0x0C
#define NAND_DATA       0x10

static nand_info_t g_nand_info = {0};

const nand_info_t *nand_info(void) {
    return &g_nand_info;
}

int nand_init(void) {
    /* Reset controller */
    mmio_write32(NAND_BASE_ADDR + NAND_CTRL, 0x1);
    
    /* Wait for ready */
    for (int i = 0; i < 1000; i++) {
        if (mmio_read32(NAND_BASE_ADDR + NAND_STATUS) & 0x1) break;
    }
    
    /* Read ID - simplified */
    mmio_write32(NAND_BASE_ADDR + NAND_CMD, 0x90);  /* Read ID command */
    mmio_write32(NAND_BASE_ADDR + NAND_ADDR, 0);    /* Address 0 */
    
    uint8_t id[5];
    for (int i = 0; i < 5; i++) {
        id[i] = mmio_read32(NAND_BASE_ADDR + NAND_DATA) & 0xFF;
    }
    
    /* Parse ID - simplified */
    g_nand_info.id_len = 5;
    for (int i = 0; i < 5; i++) g_nand_info.id[i] = id[i];
    
    /* Hardcode geometry for common A11 NAND */
    g_nand_info.geometry.page_size = 4096;
    g_nand_info.geometry.oob_size = 128;
    g_nand_info.geometry.pages_per_block = 64;
    g_nand_info.geometry.block_count = 4096;
    
    g_nand_info.initialized = 1;
    g_nand_info.verified = 1;
    
    return 0;
}

int nand_read_page(uint32_t block, uint32_t page, uint8_t *data, uint8_t *oob) {
    (void)oob;
    
    /* Send read command */
    mmio_write32(NAND_BASE_ADDR + NAND_CMD, 0x00);  /* Read 1st half */
    
    /* Send address: column (0) + row (block * pages_per_block + page) */
    uint32_t row = block * 64 + page;  /* pages_per_block = 64 */
    
    mmio_write32(NAND_BASE_ADDR + NAND_ADDR, 0);       /* Column 0 */
    mmio_write32(NAND_BASE_ADDR + NAND_ADDR, row & 0xFF);
    mmio_write32(NAND_BASE_ADDR + NAND_ADDR, (row >> 8) & 0xFF);
    mmio_write32(NAND_BASE_ADDR + NAND_ADDR, (row >> 16) & 0xFF);
    
    mmio_write32(NAND_BASE_ADDR + NAND_CMD, 0x30);  /* Read confirm */
    
    /* Wait for ready */
    for (int i = 0; i < 100000; i++) {
        if (mmio_read32(NAND_BASE_ADDR + NAND_STATUS) & 0x1) break;
    }
    
    /* Read data */
    for (uint32_t i = 0; i < 4096; i += 4) {
        uint32_t val = mmio_read32(NAND_BASE_ADDR + NAND_DATA);
        ((uint32_t*)data)[i/4] = val;
    }
    
    return 0;
}