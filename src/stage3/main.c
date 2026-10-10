/*
 * dr1zzle Stage 3 - Final Payload Entry Point
 * 
 * This is where the actual OS/runtime begins.
 * Loaded by Stage 2 into DRAM (preferred) or SRAM fallback.
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
#include "vfs.h"
#include "vfs/apfs_vfs.h"

/* ========================================================================
 * Stage 2 Handoff Structure
 * ======================================================================== */

typedef struct {
    uint64_t payload_entry;        /* Stage 3 entry point */
    uint64_t payload_size;         /* Total payload size */
    uint64_t dtb_ptr;              /* Device tree pointer */
    uint64_t initrd_ptr;           /* Initramfs pointer (0 = none) */
    uint64_t cmdline_ptr;          /* Kernel command line pointer */
    uint32_t storage_tiers;        /* Available storage tiers bitmap */
    void (*storage_read)(int tier, uint64_t offset, void *buf, size_t len);
} stage2_handoff_t;

/* Global handoff pointer */
static void *g_stage2_handoff = NULL;

/* ========================================================================
 * Stage 3 Main Entry - The Actual OS Starts Here
 * ======================================================================== */

void stage3_main(void *handoff_ptr) {
    g_stage2_handoff = handoff_ptr;
    stage2_handoff_t *handoff = (stage2_handoff_t *)handoff_ptr;
    
    /* Initialize full hardware environment */
    pmgr_init();
    uart_early_init();
    console_init();
    timer_init();
    exception_init();
    
    uart_puts("\n=== dr1zzle Stage 3 - Final Payload ===\n");
    uart_puts("stage3: Payload entry at "); uart_puts(utoa_hex(handoff->payload_entry)); uart_puts("\n");
    uart_puts("stage3: Payload size: "); uart_puts(utoa(handoff->payload_size)); uart_puts(" bytes\n");
    
    /* MMU setup if DRAM available */
    extern int mmu_init(void);
    extern void mmu_enable(void);
    
    /* Initialize all hardware */
    pmgr_init();
    uart_early_init();
    console_init();
    timer_init();
    exception_init();
    
    /* GPIO, I2C, SPI */
    if (gpio_init() == 0) uart_puts("gpio: ok\n");
    if (i2c_init(I2C_DEFAULT_HZ) == 0) uart_puts("i2c: ok\n");
    spi_init(); uart_puts("spi: ok\n");
    
    /* Watchdog */
    watchdog_init(); uart_puts("wdog: disarmed\n");
    
    /* USB */
    if (usb_init() == 0) {
        uart_puts("usb: ok\n");
        irq_register(AIC_IRQ_USB_OTG, usb_irq_handler);
    }
    
    /* Display */
    extern uint64_t g_boot_dtb;
    if (display_probe_device_tree(g_boot_dtb) == 0) {
        const display_info_t *di = display_info();
        if (display_attach_discovered() == 0) {
            display_console_init(DISPLAY_RGB888(0xff, 0xff, 0xff),
                                 DISPLAY_RGB888(0x00, 0x00, 0x00));
            uart_puts("display: ok\n");
        }
    }
    
    /* Network */
    net_configure_static();
    if (goatloader_init() == 0) {
        uart_puts("goatloader: ready\n");
    }
    
    /* VFS + APFS */
    vfs_init();
    apfs_vfs_register();
    
    if (nand_init() == 0) {
        vfs_mount("nand", "/mnt/apfs", "apfs", 0, NULL);
    }
    
    /* Initialize shell */
    uart_puts("\n=== dr1zzle Stage 3 Ready ===\n");
    uart_puts("Type 'help' for commands\n\n");
    
    shell_run();
    
    for (;;) { __asm__ volatile("wfe"); }
}

/* Payload entry point - called after Stage 3 initialization */
void payload_entry(void) {
    stage3_main(g_stage2_handoff);
}