/*
 * dr1zzle Stage 1 - Minimal Bootstrap (≤32 KB)
 * 
 * Purpose: Initialize critical hardware → find storage → load Stage 2
 * 
 * Constraints: ≤32 KB flat image, no VFS, no filesystem, minimal drivers
 */

#include "memory_map.h"
#include "mmio.h"
#include "uart.h"
#include "timer.h"
#include "nand.h"
#include "util.h"

/* ========================================================================
 * Stage 2 Header (placed at fixed NAND offset)
 * ======================================================================== */

#define STAGE2_NAND_OFFSET_BLOCKS   0x1000    /* 16 MB into NAND */
#define STAGE2_MAX_SIZE             (128 * 1024)  /* 128 KB max */
#define STAGE2_MAGIC                0x5354414732  /* "STAG2" */

typedef struct __attribute__((packed)) {
    uint64_t magic;                 /* STAGE2_MAGIC */
    uint32_t version;               /* Stage 2 format version */
    uint32_t size;                  /* Total size in bytes */
    uint32_t compressed_size;       /* Compressed size (0 = uncompressed) */
    uint32_t crc32;                 /* CRC32 of payload */
    uint32_t flags;                 /* Bit 0 = compressed (LZ4) */
    uint64_t load_address;          /* Where to load in SRAM */
    uint64_t entry_point;           /* Entry point offset from load_address */
    uint8_t  reserved[24];          /* Future expansion */
} stage2_header_t;

/* ========================================================================
 * Stage 1 Handoff to Stage 2
 * ======================================================================== */

typedef struct __attribute__((packed)) {
    uint64_t nand_base;             /* NAND controller base address */
    uint32_t nand_block_size;       /* NAND block size in bytes */
    uint32_t nand_pages_per_block;  /* Pages per block */
    uint64_t dram_base;             /* DRAM base (0 = not available) */
    uint64_t dram_size;             /* DRAM size in bytes */
    uint32_t sram_free_start;       /* First free SRAM byte after Stage 2 */
    uint32_t sram_free_size;        /* Free SRAM size in bytes */
    uint8_t  storage_bitmap;        /* Bit 0=NAND, 1=USB, 2=DRAM, 3=NET */
    uint8_t  reserved[7];
} stage1_handoff_t;

/* ========================================================================
 * Global State
 * ======================================================================== */

static stage1_handoff_t g_handoff = {0};
static uint8_t *g_heap_ptr = NULL;
static uint8_t *g_heap_end = NULL;

/* ========================================================================
 * Forward declarations
 * ======================================================================== */

int stage1_verify_stage2_header(const stage2_header_t *hdr);
uint32_t crc32(const void *data, size_t len);

/* ========================================================================
 * Minimal Heap (4 KB Bump Allocator)
 * ======================================================================== */

void stage1_heap_init(void) {
    extern char _heap_start[];
    extern char _heap_end[];
    g_heap_ptr = (uint8_t *)_heap_start;
    g_heap_end = (uint8_t *)_heap_end;
}

void *malloc(size_t size) {
    if (size == 0) return NULL;
    if (!g_heap_ptr) return NULL;
    
    /* Align to 8 bytes */
    size = (size + 7) & ~7;
    
    if (g_heap_ptr + size > g_heap_end) {
        return NULL;
    }
    
    void *ptr = g_heap_ptr;
    g_heap_ptr += size;
    return ptr;
}

void free(void *ptr) {
    (void)ptr;  /* Bump allocator - no individual free */
}

/* ========================================================================
 * Stage 2 Loading
 * ======================================================================== */

int stage1_nand_read_block(uint32_t block, uint32_t page, uint8_t *out) {
    if (nand_init() != 0) {
        uart_puts("stage1: NAND init failed\n");
        return -1;
    }
    
    return nand_read_page(block, page, out, NULL);
}

int stage1_load_stage2(void *dst) {
    uart_puts("stage1: Loading Stage 2 from NAND...\n");
    
    /* Read Stage 2 header from fixed NAND offset */
    if (stage1_nand_read_block(STAGE2_NAND_OFFSET_BLOCKS, 0, (uint8_t *)dst) != 0) {
        uart_puts("stage1: Failed to read Stage 2 header\n");
        return -1;
    }
    
    stage2_header_t *hdr = (stage2_header_t *)dst;
    
    if (stage1_verify_stage2_header(hdr) != 0) {
        return -1;
    }
    
    uart_puts("stage1: Stage 2 header valid: size="); uart_puts(utoa(hdr->size));
    uart_puts(" entry="); uart_puts(utoa_hex(hdr->entry_point));
    uart_puts(" load_addr="); uart_puts(utoa_hex(hdr->load_address));
    uart_puts("\n");
    
    /* Calculate payload location (after header) */
    uint8_t *payload_src = ((uint8_t *)dst) + 512;  /* Header is 512 bytes */
    uint8_t *payload_dst = (uint8_t *)hdr->load_address;
    
    /* Read remaining payload from NAND */
    size_t payload_size = hdr->size;
    size_t header_size = 512;
    size_t remaining = payload_size;
    uint8_t *src = payload_src;
    uint8_t *dst_ptr = payload_dst;
    
    const nand_info_t *info = nand_info();
    uint32_t pages_per_block = info->geometry.pages_per_block;
    uint32_t page_size = info->geometry.page_size;
    
    /* We already read first page (512 bytes of header + rest of first page) */
    size_t first_page_payload = page_size - header_size;
    if (remaining <= first_page_payload) {
        memcpy(dst_ptr, src, remaining);
        remaining = 0;
    } else {
        memcpy(dst_ptr, src, first_page_payload);
        dst_ptr += first_page_payload;
        src += first_page_payload;
        remaining -= first_page_payload;
        
        /* Read remaining full pages */
        uint32_t start_page = STAGE2_NAND_OFFSET_BLOCKS * pages_per_block + 1;
        uint32_t pages_needed = (remaining + page_size - 1) / page_size;
        
        for (uint32_t i = 0; i < pages_needed; i++) {
            size_t to_read = (remaining > page_size) ? page_size : remaining;
            if (nand_read_page(start_page / pages_per_block, start_page % pages_per_block, dst_ptr, NULL) != 0) {
                uart_puts("stage1: Failed to read payload page "); uart_puts(utoa(start_page)); uart_puts("\n");
                return -1;
            }
            dst_ptr += to_read;
            remaining -= to_read;
            start_page++;
        }
    }
    
    uart_puts("stage1: Stage 2 payload copied to "); uart_puts(utoa_hex((uint64_t)hdr->load_address)); uart_puts("\n");
    
    /* Verify payload */
    if (crc32((void *)hdr->load_address, hdr->size) != hdr->crc32) {
        uart_puts("stage1: Stage 2 CRC32 mismatch!\n");
        return -1;
    }
    
    uart_puts("stage1: Stage 2 CRC32 verified OK\n");
    return 0;
}

/* ========================================================================
 * USB DFU Fallback (Stub - not used in minimal Stage 1)
 * ======================================================================== */

int stage1_try_usb_dfu(void *dst) {
    (void)dst;
    uart_puts("stage1: USB DFU not implemented in minimal Stage 1\n");
    return -1;
}

/* ========================================================================
 * Stage 1 Main Entry
 * ======================================================================== */

void stage1_main(void) {
    uart_puts("\n=== dr1zzle Stage 1 Bootstrap ===\n");
    
    /* Initialize minimal heap (4 KB) */
    stage1_heap_init();
    uart_puts("stage1: Heap initialized\n");
    
    /* Initialize ONLY critical hardware for Stage 1:
     * - UART (for output)
     * - Timer (for timeouts)
     * - NAND (for loading Stage 2)
     * DO NOT initialize: PMGR, AIC, USB, GPIO, I2C, SPI, etc.
     * Those are Stage 2 responsibilities. */
    
    uart_early_init();
    uart_puts("stage1: UART initialized\n");
    
    timer_init();
    uart_puts("stage1: Timer initialized\n");
    
    /* Initialize NAND */
    if (nand_init() == 0) {
        uart_puts("stage1: NAND initialized\n");
        g_handoff.storage_bitmap |= 1;  /* NAND available */
        g_handoff.nand_base = NAND_BASE;
        const nand_info_t *info = nand_info();
        g_handoff.nand_block_size = info->geometry.block_count;  /* Use block_count as block identifier */
        g_handoff.nand_pages_per_block = info->geometry.pages_per_block;
    } else {
        uart_puts("stage1: NAND not available\n");
    }
    
    /* Check DRAM availability (simplified - just check if accessible) */
    g_handoff.dram_base = 0;
    g_handoff.dram_size = 0;  /* Not initialized in Stage 1 */
    g_handoff.storage_bitmap = 0;
    if (nand_init() == 0) g_handoff.storage_bitmap |= 1;
    
    /* Load Stage 2 */
    uint64_t stage2_load_addr = 0x180008000;  /* After Stage 1 (32 KB) */
    
    uart_puts("stage1: Loading Stage 2 to "); uart_puts(utoa_hex(stage2_load_addr)); uart_puts("\n");
    
    int ret = stage1_load_stage2((void *)stage2_load_addr);
    if (ret != 0) {
        uart_puts("stage1: NAND load failed, trying USB DFU...\n");
        int ret = stage1_try_usb_dfu((void *)0x180008000);
        if (ret != 0) {
            uart_puts("stage1: All load methods failed!\n");
            for (;;) { __asm__ volatile("wfe"); }
        }
    }
    
    /* Prepare handoff */
    g_handoff.sram_free_start = (uint32_t)0x180028000;  /* After Stage 2 (128 KB) */
    g_handoff.sram_free_size = 0x1801E8000 - 0x180028000;  /* Remaining SRAM */
    g_handoff.nand_base = NAND_BASE;
    const nand_info_t *ninfo = nand_info();
    if (ninfo) {
        g_handoff.nand_block_size = ninfo->geometry.block_count;  /* Use block_count as block identifier */
        g_handoff.nand_pages_per_block = ninfo->geometry.pages_per_block;
    }
    
    uart_puts("stage1: Stage 2 loaded, jumping...\n");
    uart_puts("stage1: Handoff - SRAM free: "); uart_puts(utoa_hex(g_handoff.sram_free_start));
    uart_puts(" size: "); uart_puts(utoa(g_handoff.sram_free_size)); uart_puts("\n");
    
    /* Jump to Stage 2 entry point */
    /* Stage 2 is loaded at 0x180008000, entry is at load_address + entry_point */
    stage2_header_t *hdr = (stage2_header_t *)0x180008000;
    uint64_t entry = stage2_load_addr + hdr->entry_point;
    
    uart_puts("stage1: Jumping to Stage 2 at "); uart_puts(utoa_hex(entry)); uart_puts("\n");
    
    /* Disable interrupts, jump */
    __asm__ volatile("msr daifset, #0xf" ::: "memory");
    
    typedef void (*stage2_entry_t)(stage1_handoff_t *);
    stage2_entry_t entry_fn = (stage2_entry_t)entry;
    entry_fn(&g_handoff);
    
    /* Should never reach here */
    for (;;) { __asm__ volatile("wfe"); }
}

/* ========================================================================
 * Exception Handler C Implementation
 * ======================================================================== */

void stage1_exception_handler_c(void *frame) {
    /* frame points to the saved registers on stack */
    uint64_t *regs = (uint64_t *)frame;
    uint64_t esr = regs[2];   /* x2 = ESR */
    uint64_t far = regs[3];   /* x3 = FAR */
    uint64_t elr = regs[4];   /* x4 = ELR */
    uint64_t sp = regs[5];    /* x5 = SP */

    uart_puts("\n=== STAGE 1 EXCEPTION ===\n");
    uart_puts("ESR: "); uart_puts(utoa_hex(esr)); uart_puts("\n");
    uart_puts("FAR: "); uart_puts(utoa_hex(far)); uart_puts("\n");
    uart_puts("ELR: "); uart_puts(utoa_hex(elr)); uart_puts("\n");
    uart_puts("SP:  "); uart_puts(utoa_hex(sp)); uart_puts("\n");
}