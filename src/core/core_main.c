/* dr1zzle core: the bootstrap and menu.
 *
 * ---------------------------------------------------------------------------
 * Where this sits in the multi-stage split
 * ---------------------------------------------------------------------------
 *
 * The published payload used to be one flat image that brought up every
 * peripheral, linked every driver and ran the full monitor shell. It grew past
 * 0x18001C000, the top of the window `goat kload` can write through without
 * landing on the pwndfu command area, and stopped being loadable at all.
 *
 * The split keeps that one image's *reach* and drops its *size*:
 *
 *   core      this file. A bootstrap that brings up the console, NAND, USB and
 *             the goatloader, then offers a menu. It is small enough for the
 *             command window because it carries no feature code.
 *   firmware  a self-contained image for one kind of work (the full monitor, a
 *             dumping build, a diagnostics build). It is linked for the SRAM
 *             tail and laid down on demand, either from a NAND slot (fw_store.c)
 *             or over USB (`goat push --run`, which the goatloader handles).
 *
 * The core never needs to know what a firmware does. It knows where one lands,
 * how to check it, and how to enter it -- the same three facts the goat
 * container path already built for itself.
 *
 * Bring-up order is the same dependency chain main.c documents; the difference
 * is only that i2c/spi/display/wifi/vfs/shell are not here. A peripheral that
 * is not part of launching a firmware does not get powered up by the core, so
 * a firmware that wants it brings it up itself.
 */

#include <stdint.h>

#include "memory_map.h"
#include "drivers.h"
#include "uart.h"
#include "timer.h"
#include "util.h"
#include "string.h"
#include "pmgr.h"
#include "exception.h"
#include "usb.h"
#include "net.h"
#include "nand.h"
#include "console.h"
#include "goat/loader.h"
#include "firmware.h"

extern int  usb_init(void);
extern void reboot(void);

/* fw_store.c */
void            fw_store_scan(void);
int             fw_store_count(void);
const firmware_header_t *fw_store_slot(unsigned slot);
void            fw_run_slot(unsigned slot);

/* --- small helpers ------------------------------------------------------ */

static int parse_uint(const char *s, unsigned *out) {
    unsigned v = 0;
    int seen = 0;
    while (*s == ' ' || *s == '\t') s++;
    while (*s >= '0' && *s <= '9') {
        v = v * 10u + (unsigned)(*s - '0');
        s++;
        seen = 1;
    }
    if (!seen) return -1;
    *out = v;
    return 0;
}

/* Print `s` into a fixed column so the slot table lines up without printf. */
static void pad_line(const char *s, unsigned width) {
    unsigned n = 0;
    while (s[n] && n < width) { uart_putc(s[n]); n++; }
    while (n < width) { uart_putc(' '); n++; }
}

static void size_kb(uint32_t bytes) {
    uart_puts(utoa((bytes + 1023u) / 1024u));
    uart_puts(" KB");
}

/* --- menu --------------------------------------------------------------- */

static void banner(void) {
    uart_puts("\n=== dr1zzle core 0.2 ===\n");
    uart_puts("bootstrap + firmware menu; features live in firmware images\n\n");
}

static void list_firmwares(void) {
    uart_puts("firmware slots:\n");
    if (fw_store_count() == 0) {
        uart_puts("  (none on NAND)\n");
        uart_puts("  load one with:  goat push <firmware.g1> --run\n");
        return;
    }
    for (unsigned s = 0; s < FW_SLOT_COUNT; s++) {
        const firmware_header_t *h = fw_store_slot(s);
        if (!h) continue;
        uart_puts("  [");
        uart_puts(utoa(s));
        uart_puts("] ");
        pad_line(h->name, 14);
        uart_puts(" 0x");
        uart_puts(utoa_hex(h->load_base));
        uart_puts("  ");
        size_kb(h->size);
        uart_puts("\n");
    }
}

static void help(void) {
    uart_puts("commands:\n");
    uart_puts("  list        show firmware slots\n");
    uart_puts("  run <n>     load and enter firmware slot n\n");
    uart_puts("  goat        goatloader / USB status\n");
    uart_puts("  nand        NAND geometry (read-only)\n");
    uart_puts("  ver         build identity\n");
    uart_puts("  reboot      restart the SoC\n");
    uart_puts("  help        this text\n");
    uart_puts("\n");
    uart_puts("the full monitor (shell, dumps, display) lives in a firmware:\n");
    uart_puts("  goat push <firmware.g1> --run   stage and enter the monitor\n");
    uart_puts("  goat push <firmware.g1>         stage it, then `run <n>`\n");
    uart_puts("  goat shell                      drive this menu over the link\n");
}

static void show_goat(void) {
    goatloader_report();
}

static void show_nand(void) {
    const nand_info_t *n = nand_info();
    if (!n || !n->initialized) {
        uart_puts("nand: not initialised (no controller / not probed)\n");
        return;
    }
    uart_puts("nand: page ");
    uart_puts(utoa(n->geometry.page_size));
    uart_puts("B, oob ");
    uart_puts(utoa(n->geometry.oob_size));
    uart_puts("B, ");
    uart_puts(utoa(n->geometry.pages_per_block));
    uart_puts(" pages/block, ");
    uart_puts(utoa(n->geometry.block_count));
    uart_puts(" blocks\n");
    uart_puts("nand: ecc corrected=");
    uart_puts(utoa(n->ecc.corrected));
    uart_puts(" failed=");
    uart_puts(utoa(n->ecc.failed));
    uart_puts(" uncorrectable=");
    uart_puts(utoa(n->ecc.uncorrectable));
    uart_puts("\n");
}

static void show_version(void) {
    uart_puts("dr1zzle core 0.2 (bootstrap + menu)\n");
    uart_puts("firmware load base 0x");
    uart_puts(utoa_hex(FW_LOAD_BASE));
    uart_puts(", max ");
    size_kb(FW_MAX_SIZE);
    uart_puts("\n");
}

/* The menu never blocks on the network: while it waits for a keystroke it is
 * also the goatloader's service loop, so a push can arrive between menu
 * commands exactly as it could between shell commands in the old image. */
static int read_line(char *buf, unsigned cap) {
    unsigned n = 0;
    for (;;) {
        net_poll();
        goatloader_poll();

        int c = uart_getc();
        if (c < 0) continue;

        if (c == '\r' || c == '\n') { uart_putc('\n'); break; }
        if (c == 0x7f || c == 0x08) {
            if (n > 0) { n--; uart_puts("\b \b"); }
            continue;
        }
        if (c >= 0x20 && c < 0x7f && n + 1 < cap) {
            buf[n++] = (char)c;
            uart_putc((char)c);
        }
    }
    buf[n] = '\0';
    return (int)n;
}

static void dispatch(char *line) {
    char *verb = line;
    char *rest;

    while (*verb == ' ' || *verb == '\t') verb++;
    if (*verb == '\0') return;

    rest = verb;
    while (*rest && *rest != ' ' && *rest != '\t') rest++;
    if (*rest) { *rest++ = '\0'; while (*rest == ' ' || *rest == '\t') rest++; }

    if (strcmp(verb, "help") == 0 || strcmp(verb, "?") == 0) {
        help();
    } else if (strcmp(verb, "list") == 0) {
        list_firmwares();
    } else if (strcmp(verb, "run") == 0 || strcmp(verb, "boot") == 0) {
        unsigned slot;
        if (parse_uint(rest, &slot) != 0) {
            uart_puts("usage: run <slot>  (see `list`)\n");
        } else if (slot >= FW_SLOT_COUNT || !fw_store_slot(slot)) {
            uart_puts("no firmware in that slot\n");
        } else {
            fw_run_slot(slot);   /* returns only on error */
            uart_puts("run: firmware did not start\n");
        }
    } else if (strcmp(verb, "goat") == 0) {
        show_goat();
    } else if (strcmp(verb, "nand") == 0) {
        show_nand();
    } else if (strcmp(verb, "ver") == 0) {
        show_version();
    } else if (strcmp(verb, "reboot") == 0) {
        uart_puts("rebooting\n");
        timer_sleep_ms(50);
        reboot();
    } else {
        uart_puts("unknown command: ");
        uart_puts(verb);
        uart_puts("  (`help`)\n");
    }
}

/* The goatloader's `shell` verb feeds a command line here, with UART output
 * captured around the call (src/goat/loader.c:run_shell). In the core, "the
 * shell" is the menu, so a line from `goat shell` runs exactly as if it had
 * been typed at the menu prompt -- the remote console and the local one are
 * the same command set, not two that could drift. */
void shell_exec(const char *line) {
    char buf[128];
    size_t n = strlen(line);

    if (n >= sizeof buf) n = sizeof buf - 1;
    memcpy(buf, line, n);
    buf[n] = '\0';
    dispatch(buf);
}

/* The core's entry point. start.S is shared with the firmware build; each
 * image defines its own c_main, so the two never collide. */
void c_main(void) {
    static char line[128];

    pmgr_init();
    uart_early_init();
    console_init();
    timer_init();
    exception_init();

    banner();

    if (gpio_init() != 0) {
        uart_puts("core: gpio window not live\n");
    }

    watchdog_init();

    if (usb_init() == 0) {
        if (irq_register(AIC_IRQ_USB_OTG, usb_irq_handler) != 0) {
            uart_puts("core: usb irq line busy; dwc2 polled\n");
        }
    } else {
        uart_puts("core: usb init failed; goat push unavailable\n");
    }

    /* Address, then the server that listens on it. Same two calls the monitor
     * makes; the core just does it earlier than the firmware would. */
    net_configure_static();
    if (goatloader_init() == 0) {
        uint32_t ip = net_ip();
        uart_puts("goatloader: listening on ");
        uart_puts(utoa((ip >> 24) & 0xffu)); uart_putc('.');
        uart_puts(utoa((ip >> 16) & 0xffu)); uart_putc('.');
        uart_puts(utoa((ip >> 8) & 0xffu));  uart_putc('.');
        uart_puts(utoa(ip & 0xffu));
        uart_puts(":");
        uart_puts(utoa(GOATLOADER_PORT));
        uart_puts("\n");
    } else {
        uart_puts("goatloader: bind deferred; retrying from the menu loop\n");
    }

    /* NAND once; fw_store_scan only reads headers out of it. */
    nand_init();
    fw_store_scan();

    list_firmwares();
    uart_puts("\ntype `help` for commands\n");

    for (;;) {
        uart_puts("\ncore> ");
        read_line(line, sizeof line);
        dispatch(line);
    }
}
