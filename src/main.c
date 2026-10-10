#include "memory_map.h"
#include "drivers.h"
#include "uart.h"
#include "timer.h"
#include "shell.h"
#include "util.h"
#include "secure_rom.h"
#include "sepos.h"
#include "nand_dump.h"
#include "nand.h"
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

extern int mmu_init(void);
extern void mmu_enable(void);
extern void reboot(void);

/* g_boot_args / g_boot_dtb are defined in arch/arm64/globals.c, which every
 * image links. This file is the *firmware* entry point (the full monitor);
 * the core bootstrap has its own c_main in src/core/. */

#include "exception.h"
#include "pmgr.h"
#include "timer.h"
#include "usb.h"
#include "display.h"
#include "menu.h"
#include "console.h"

/* The previous c_main called mmu_init/uart_early_init/usb_init here while
 * start.S had already called mmu_init, uart_early_init and usb_init. DWC2
 * in particular cannot be soft-reset twice: the second GRSTCTL.CSRST lands
 * on an already-running core and the wait loops never observe AHBIDLE.
 * Bring-up now happens exactly once, here. */

/* Bring-up order is a dependency chain, not a list of peers:
 *
 *   pmgr      releases the clocks; nothing below can talk to a gated block
 *   uart      the console; every failure after this point reports itself
 *   timer     the counter every polling wait in this build depends on
 *   aic       the interrupt controller; a peripheral that is enabled with
 *             an unmasked line and no controller behind it will re-enter
 *             its own interrupt forever
 *   gpio      pin muxing; a peripheral that is still muxed to the
 *             bootloader's choice will not respond to a correct transfer
 *   i2c, spi  buses, polled
 *   watchdog  disarmed before anything else can hang: an armed watchdog
 *             resets the device while a transfer waits, which looks like a
 *             bus fault and costs an afternoon
 *   usb       the host data path
 *
 * Every peripheral init here is allowed to fail without stopping the
 * payload. A dead I2C bus must not cost the operator the shell that would
 * have let them find out why. */
void c_main(void) {
    /* Clocks and reset first: nothing below can talk to a peripheral that
     * is still gated off. */
    pmgr_init();

    uart_early_init();
    console_init();
    timer_init();
    exception_init();

    uart_puts("\n=== dr1zzle A11 payload ===\n");
    uart_puts("cntfrq=");
    uart_puts(utoa(timer_freq_hz() / 1000000ULL));
    uart_puts("MHz\n");

    /* MMU stays off by default. mmu_init() is correct but untested against
     * silicon; enabling it before that risks an instruction fetch fault we
     * cannot report. Flip DR1ZZLE_ENABLE_MMU in a debug build to try it. */
#ifdef DR1ZZLE_ENABLE_MMU
    if (mmu_init() == 0) {
        uart_puts("mmu: identity map installed, enabling\n");
        mmu_enable();
    } else {
        uart_puts("mmu: map failed, continuing unmapped\n");
    }
#endif

    if (gpio_init() == 0) {
        uart_puts("gpio: pin window live at 0x");
        uart_puts(utoa_hex(GPIO_BASE));
        uart_puts("\n");
    }

    if (i2c_init(I2C_DEFAULT_HZ) == 0) {
        uart_puts("i2c: ");
        uart_puts(utoa(i2c_speed()));
        uart_puts("Hz, divider ");
        uart_puts(utoa(i2c_divider()));
        uart_puts(", rev 0x");
        uart_puts(utoa_hex(i2c_revision()));
        uart_puts("\n");
    }

    spi_init();
    uart_puts("spi: ");
    uart_puts(utoa(spi_speed()));
    uart_puts("Hz, divider ");
    uart_puts(utoa(spi_divider()));
    uart_puts("\n");

    watchdog_init();
    uart_puts("wdog: ");
    uart_puts(watchdog_armed() ? "still armed -- disarm before arming on purpose\n"
                               : "disarmed\n");

    if (usb_init() == 0) {
        uart_puts("usb: DWC2 device mode up\n");
        /* The core is now configured and unmasked, so the line it lives on
         * can be claimed. Claiming earlier would deliver an interrupt into
         * a core that has not finished resetting its FIFOs. */
        if (irq_register(AIC_IRQ_USB_OTG, usb_irq_handler) == 0) {
            uart_puts("irq: dwc2 on AIC line ");
            uart_puts(utoa(AIC_IRQ_USB_OTG));
            uart_puts("\n");
        } else {
            uart_puts("irq: line ");
            uart_puts(utoa(AIC_IRQ_USB_OTG));
            uart_puts(" already claimed; dwc2 stays polled\n");
        }
    } else {
        uart_puts("usb: init failed, continuing without host console\n");
    }

    /* Display. The pipeline is already configured by the bootloader, so all
     * we do is find the framebuffer it left running and draw into it. If
     * there is no device tree there is nothing to discover from and the
     * console stays off -- the UART shell below is unaffected either way. */
    if (display_probe_device_tree(g_boot_dtb) == 0) {
        const display_info_t *di = display_info();
        uart_puts("display: fb 0x");
        uart_puts(utoa_hex(di->base));
        uart_puts(" ");
        uart_puts(utoa(di->width));
        uart_puts("x");
        uart_puts(utoa(di->height));
        uart_puts(" ");
        uart_puts(utoa(di->bpp));
        uart_puts("bpp\n");

        if (display_attach_discovered() == 0) {
            menu_init();
            uart_puts("display: menu up (fixed panel + output pane)\n");
        }
    } else {
        uart_puts("display: no device tree, raster console off\n");
    }

    /* Research stubs announce themselves; keep the log readable. */
    uart_puts("ace2/wifi: not implemented in this build\n");

    /* Initialize VFS and register APFS driver for on-demand asset loading */
    vfs_init();
    apfs_vfs_register();

    /* Try to mount APFS from NAND if available */
    if (nand_init() == 0) {
        if (vfs_mount("nand", "/mnt/apfs", "apfs", 0, NULL) == 0) {
            uart_puts("vfs: APFS mounted on /mnt/apfs\n");
        } else {
            uart_puts("vfs: APFS mount failed (no valid volume)\n");
        }
    }

    /* Addressing, then the server that listens on it.
     *
     * The address is a build-time constant (net.h), installed here so the
     * stack answers ARP for it from the very first frame rather than after
     * something asks. Nothing negotiates it: there is no DHCP client on a
     * point-to-point link, and the remote side's default is the same number,
     * so "easy to connect to" means nobody has to be told anything.
     *
     * The goatloader is bound before the shell starts because the shell's
     * idle loop is what services it, and because `goat push` can arrive
     * before anyone types a keystroke. It has no off switch -- see
     * docs/GOATLOADER.md -- which is a property of the module, not of this
     * call site. */
    net_configure_static();

    /* Unconditional: the result only decides what the log says. When the bind
     * fails -- four sockets, one already consumed by bring-up order -- the
     * idle loop re-arms the listener on its next pass, so a deferred bind is a
     * log line, not a missing server. */
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
        uart_puts(":");
        uart_puts(utoa(GOATLOADER_PORT));
        uart_puts(" (always on)\n");
        uart_puts("goatloader: goat push / goat shell / goat run all use it\n");
    } else {
        uart_puts("goatloader: bind deferred, retrying from the shell loop\n");
    }

    uart_puts("Type 'help' for commands\n\n");
    shell_run();
}
