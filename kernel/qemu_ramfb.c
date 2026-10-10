/* QEMU virt fw_cfg MMIO and the ramfb configuration file. */
#include <stdint.h>
#include <drizzle/display.h>

enum {
    FW_CFG_BASE = 0x09020000,
    FW_CFG_SELECTOR = FW_CFG_BASE + 8,
    FW_CFG_DMA = FW_CFG_BASE + 16,
    FW_CFG_FILE_DIR = 0x19,
    FW_CFG_DMA_SELECT = 8,
    FW_CFG_DMA_WRITE = 16,
    RAMFB_WIDTH = 640,
    RAMFB_HEIGHT = 240,
    RAMFB_STRIDE = RAMFB_WIDTH * 4,
    /* DRM_FORMAT_XRGB8888, fourcc 'XR24'. */
    RAMFB_FORMAT = 0x34325258
};

typedef struct {
    volatile uint32_t control;
    uint32_t length;
    uint64_t address;
} fw_cfg_dma_t;

static uint8_t fw_cfg_byte(void) {
    return *(volatile uint8_t *)(uintptr_t)FW_CFG_BASE;
}

static void fw_cfg_select(uint16_t key) {
    *(volatile uint16_t *)(uintptr_t)FW_CFG_SELECTOR = __builtin_bswap16(key);
}

static uint32_t fw_cfg_u32(void) {
    uint32_t value = 0;
    for (unsigned i = 0; i < 4; ++i) value = (value << 8) | fw_cfg_byte();
    return value;
}

static uint16_t fw_cfg_u16(void) {
    return ((uint16_t)fw_cfg_byte() << 8) | fw_cfg_byte();
}

static int ramfb_file(uint16_t *key) {
    fw_cfg_select(0);
    if (fw_cfg_byte() != 'Q' || fw_cfg_byte() != 'E' ||
        fw_cfg_byte() != 'M' || fw_cfg_byte() != 'U') return 0;

    fw_cfg_select(1);
    if (!(fw_cfg_byte() & 2)) return 0;

    fw_cfg_select(FW_CFG_FILE_DIR);
    uint32_t count = fw_cfg_u32();
    if (count > 128) return 0;
    for (uint32_t i = 0; i < count; ++i) {
        uint32_t size = fw_cfg_u32();
        uint16_t select = fw_cfg_u16();
        (void)fw_cfg_u16();
        const char name[] = "etc/ramfb";
        int match = 1;
        for (unsigned j = 0; j < 56; ++j) {
            uint8_t c = fw_cfg_byte();
            if (j < sizeof name) {
                if (c != (uint8_t)name[j]) match = 0;
            }
        }
        if (match && size == 28) {
            *key = select;
            return 1;
        }
    }
    return 0;
}

int qemu_display_init(void) {
    uint16_t key;
    if (!ramfb_file(&key)) return 0;
    if (!drizzle_display_memory_init()) return 0;

    const drizzle_display_config_t *fb = drizzle_display_memory_config();
    /* RAMFBCfg has seven packed, big-endian fields. */
    static uint32_t cfg[7];
    static fw_cfg_dma_t dma __attribute__((aligned(16)));
    uint64_t address = (uint64_t)(uintptr_t)fb->pixels;
    cfg[0] = __builtin_bswap32((uint32_t)(address >> 32));
    cfg[1] = __builtin_bswap32((uint32_t)address);
    cfg[2] = __builtin_bswap32(RAMFB_FORMAT);
    cfg[3] = 0;
    cfg[4] = __builtin_bswap32(RAMFB_WIDTH);
    cfg[5] = __builtin_bswap32(RAMFB_HEIGHT);
    cfg[6] = __builtin_bswap32(RAMFB_STRIDE);
    dma.control = __builtin_bswap32(((uint32_t)key << 16) | FW_CFG_DMA_SELECT | FW_CFG_DMA_WRITE);
    dma.length = __builtin_bswap32(sizeof cfg);
    dma.address = __builtin_bswap64((uint64_t)(uintptr_t)cfg);
    __asm__ volatile("dmb sy" ::: "memory");
    *(volatile uint64_t *)(uintptr_t)FW_CFG_DMA = __builtin_bswap64((uint64_t)(uintptr_t)&dma);
    for (unsigned i = 0; i < 1000000; ++i) {
        uint32_t status = __builtin_bswap32(dma.control);
        if (status == 0) return 1;
        if (status & 1) break;
    }
    drizzle_display_detach();
    return 0;
}
