/*
 * dr1zzle Stage 2 - Asset Manager (≤128 KB)
 * 
 * Purpose: Initialize full environment → load/distribute assets → load Stage 3
 */

#include "memory_map.h"
#include "drivers.h"
#include "uart.h"
#include "timer.h"
#include "shell.h"
#include "util.h"
#include "secure_rom.h"
#include "sepos.h"
#include "nand_dump.h"
#include "memory_dump.h"
#include "iboot_dump.h"
#include "keybag.h"
#include "aes.h"
#include "ace2.h"
#include "wifi.h"
#include "kernel_patch.h"
#include "panic_log.h"
#include "net.h"
#include "goat/loader.h"
#include "vfs.h"
#include "vfs/apfs_vfs.h"
#include "exception.h"
#include "pmgr.h"
#include "timer.h"
#include "usb.h"
#include "display.h"
#include "console.h"
#include "exception.h"

/* ========================================================================
 * Stage 1 Handoff (from Stage 1 assembly)
 * ======================================================================== */

extern void stage2_main(void *handoff_ptr);

/* Forward declare Stage 1 handoff struct */
typedef struct {
    uint64_t nand_base;
    uint32_t nand_block_size;
    uint32_t nand_pages_per_block;
    uint64_t dram_base;
    uint64_t dram_size;
    uint32_t sram_free_start;
    uint32_t sram_free_size;
    uint8_t storage_bitmap;
    uint8_t reserved[7];
} stage1_handoff_t;

/* Global handoff pointer */
static void *g_stage1_handoff = NULL;

/* ========================================================================
 * Stage 2 Main Entry
 * ======================================================================== */

void stage2_main(void *handoff_ptr) {
    g_stage1_handoff = handoff_ptr;
    
    uart_puts("\n=== dr1zzle Stage 2 Asset Manager ===\n");
    
    /* Initialize full hardware environment */
    pmgr_init();
    uart_puts("stage2: PMGR initialized\n");
    
    uart_early_init();
    console_init();
    uart_puts("stage2: Console initialized\n");
    
    timer_init();
    uart_puts("stage2: Timer initialized\n");
    
    exception_init();
    uart_puts("stage2: Exception vectors installed\n");
    
    /* MMU stays off by default */
    
    /* Initialize GPIO */
    if (gpio_init() == 0) {
        uart_puts("gpio: initialized\n");
    }
    
    /* Initialize I2C */
    if (i2c_init(I2C_DEFAULT_HZ) == 0) {
        uart_puts("i2c: "); uart_puts(utoa(i2c_speed())); uart_puts("Hz\n");
    }
    
    /* Initialize SPI */
    spi_init();
    uart_puts("spi: initialized\n");
    
    /* Initialize Watchdog (disarmed) */
    watchdog_init();
    uart_puts("wdog: disarmed\n");
    
    /* Initialize USB */
    if (usb_init() == 0) {
        uart_puts("usb: DWC2 device mode up\n");
        if (irq_register(AIC_IRQ_USB_OTG, usb_irq_handler) == 0) {
            uart_puts("irq: dwc2 registered\n");
        }
    }
    
    /* Initialize Display */
    extern uint64_t g_boot_dtb;
    if (display_probe_device_tree(g_boot_dtb) == 0) {
        const display_info_t *di = display_info();
        uart_puts("display: fb 0x"); uart_puts(utoa_hex(di->base));
        uart_puts(" "); uart_puts(utoa(di->width)); uart_puts("x"); uart_puts(utoa(di->height));
        uart_puts(" "); uart_puts(utoa(di->bpp)); uart_puts("bpp\n");
        
        if (display_attach_discovered() == 0) {
            display_console_init(DISPLAY_RGB888(0xff, 0xff, 0xff),
                                 DISPLAY_RGB888(0x00, 0x00, 0x00));
            uart_puts("display: raster console up\n");
        }
    }
    
    /* Initialize Network */
    net_configure_static();
    
    int bind = goatloader_init();
    if (bind == 0) {
        uart_puts("goatloader: listening on ");
        {
            uint32_t ip = net_ip();
            uart_puts(utoa((ip >> 24) & 0xffu)); uart_putc('.');
            uart_puts(utoa((ip >> 16) & 0xffu)); uart_putc('.');
            uart_puts(utoa((ip >> 8) & 0xffu));  uart_putc('.');
            uart_puts(utoa(ip & 0xffu));
        }
        uart_puts(":"); uart_puts(utoa(GOATLOADER_PORT)); uart_puts(" (always on)\n");
    }
    
    /* Initialize VFS and APFS */
    vfs_init();
    apfs_vfs_register();
    
    /* Try to mount APFS from NAND */
    if (nand_init() == 0) {
        if (vfs_mount("nand", "/mnt/apfs", "apfs", 0, NULL) == 0) {
            uart_puts("vfs: APFS mounted on /mnt/apfs\n");
        } else {
            uart_puts("vfs: APFS mount failed\n");
        }
    }
    
    /* Initialize shell */
    uart_puts("Type 'help' for commands\n\n");
    shell_run();
    
    /* Should never reach here */
    for (;;) { __asm__ volatile("wfe"); }
}