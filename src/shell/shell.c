#include "uart.h"
#include "timer.h"
#include "shell.h"
#include "drivers.h"
#include "memory_map.h"
#include "mmio.h"
#include "util.h"
#include "string.h"
#include "secure_rom.h"
#include "sepos.h"
#include "nand_dump.h"
#include "nand.h"
#include "nand_export.h"
#include "firmware.h"
#include "fw_store.h"
#include "dashboard.h"
#include "memory_dump.h"
#include "iboot_dump.h"
#include "keybag.h"
#include "aes.h"
#include "ace2.h"
#include "wifi.h"
#include "kernel_patch.h"
#include "panic_log.h"
#include "usb.h"
#include "exception.h"
#include "pmgr.h"
#include "display.h"
#include "menu.h"
#include "net.h"
#include "goat/loader.h"
#include "vfs.h"
#include "dump.h"

/* VFS module and asset globals */
extern vfs_module_t g_modules[16];
extern uint32_t g_module_count;
extern vfs_asset_t g_assets[32];
extern uint32_t g_asset_count;
extern size_t g_asset_cache_size;

/* The firmware image's own extent, from the linker (linker/firmware.ld): the
 * bytes from FW_LOAD_BASE to __firmware_image_end are exactly what `goat seal`
 * wrapped, so `fw save` can write the running build back to NAND. */
extern char __firmware_image_end[];
extern void _start(void);

#define MAX_LINE 256

/* One reusable page + spare buffer for the NAND bring-up commands. A page can
 * be 16 KB, so this lives in .bss rather than on the firmware's 16 KB stack. */
static uint8_t g_nand_page[NAND_MAX_PAGE_BYTES];
static uint8_t g_nand_oob[NAND_MAX_OOB_BYTES];

/* The firmware's own load image: [FW_LOAD_BASE, __firmware_image_end) is exactly
 * what `goat seal` wrapped, which is what `fw install` writes back. */
extern char __firmware_image_end[];
extern void _start(void);

/* Case-insensitive string compare, for target names typed by hand:
 * `dump UID` and `dump uid` have to mean the same thing. */
static int ci_streq(const char *a, const char *b) {
    while (*a && *b) {
        char ca = *a, cb = *b;
        if (ca >= 'A' && ca <= 'Z') ca = (char)(ca + 32);
        if (cb >= 'A' && cb <= 'Z') cb = (char)(cb + 32);
        if (ca != cb) return 0;
        a++;
        b++;
    }
    return *a == 0 && *b == 0;
}

/* Decimal, for the command arguments that are naturally decimal (bus
 * speeds, seconds, line numbers). Stops at the first non-digit so it can be
 * used on a tokenised argument. */
static uint64_t parse_dec(const char *s) {
    uint64_t val = 0;
    for (const char *p = s; *p >= '0' && *p <= '9'; p++) {
        val = (val * 10) + (uint64_t)(*p - '0');
    }
    return val;
}

/* Parses a run of hex byte pairs ("9f0400") into `out`. Returns the count.
 * An odd trailing nibble is dropped rather than shifted into the next
 * byte, which would silently corrupt every byte after it. */
static int parse_bytes(const char *s, uint8_t *out, int max) {
    int len = 0;
    const char *p = s;
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) p += 2;

    while (*p && len < max) {
        uint8_t hi = 0, lo = 0;
        if (p[0] >= '0' && p[0] <= '9') hi = (uint8_t)(p[0] - '0');
        else if (p[0] >= 'a' && p[0] <= 'f') hi = (uint8_t)(p[0] - 'a' + 10);
        else if (p[0] >= 'A' && p[0] <= 'F') hi = (uint8_t)(p[0] - 'A' + 10);
        else break;
        p++;
        if (!*p) break;
        if (p[0] >= '0' && p[0] <= '9') lo = (uint8_t)(p[0] - '0');
        else if (p[0] >= 'a' && p[0] <= 'f') lo = (uint8_t)(p[0] - 'a' + 10);
        else if (p[0] >= 'A' && p[0] <= 'F') lo = (uint8_t)(p[0] - 'A' + 10);
        else break;
        p++;
        out[len++] = (uint8_t)((hi << 4) | lo);
    }
    return len;
}

static void print_bytes(const uint8_t *data, int len) {
    for (int i = 0; i < len; i++) {
        uart_puts(i == 0 ? "0x" : " 0x");
        uart_puts(utoa_hex(data[i]));
    }
}

/* The command loop itself. static: its two callers are the UART loop and
 * shell_exec() below, which is what the rest of the payload talks to. */
static void execute(char *line);

/* Forward declarations for stub functions */
static void boot_ios_kernel(uint64_t kernel_base, uint64_t initrd_addr, uint64_t initrd_size);
static void modload_module(const char *name);
static void autoboot_enable(uint64_t kernel_base);
static void autoboot_disable(void);
static void autoboot_status(void);

/* One command line, from either source. The UART loop calls it directly; the
 * goatloader calls it through this wrapper so a remote session runs the same
 * code rather than a parallel implementation of it. The copy exists because
 * `execute` tokenises in place and the caller's buffer must survive. */
void shell_exec(const char *line) {
    char copy[MAX_LINE];
    size_t index = 0;
    while (line[index] && index + 1u < sizeof copy) {
        copy[index] = line[index];
        index++;
    }
    copy[index] = 0;
    if (index) {
        menu_exec_begin();   /* mirror command output into the pane */
        execute(copy);
        menu_exec_end();
    }
}

static void execute(char *line) {
    char *argv[16];
    int argc = 0;
    char *p = line;
    while (*p && argc < 16) {
        while (*p == ' ') p++;
        if (!*p) break;
        argv[argc++] = p;
        while (*p && *p != ' ') p++;
        if (*p) *p++ = 0;
    }
    if (argc == 0) return;
    
/* ---- dashboard: placed, grouped, paired, locked surfaces ----------------- */
    else if (strcmp(argv[0], "dash") == 0) {
        if (argc < 2) {
            uart_puts("Usage:\n");
            uart_puts("  dash scope <domain>                 Set current work; other surfaces are not offered\n");
            uart_puts("  dash list                           List in-scope surfaces and placements\n");
            uart_puts("  dash place <n> <col> <row> <w> <h>  Position and size\n");
            uart_puts("  dash move <n> <dcol> <drow>         Move; groups and pairs follow\n");
            uart_puts("  dash group <a> <b>                  Move together as one unit\n");
            uart_puts("  dash ungroup <n>\n");
            uart_puts("  dash pair <a> <b>                   Keep b at a fixed offset from a\n");
            uart_puts("  dash unpair <n>\n");
            uart_puts("  dash lock <n> / unlock <n>          Locking one locks its group\n");
            uart_puts("  dash tile [domain]                  Auto-arrange in-scope surfaces\n");
            uart_puts("  dash draw                           Render onto the framebuffer\n");
            uart_puts("  dash reset\n");
            uart_puts("domains: global storage usb periph crypto memory net display sep system\n");
            return;
        }
        if (strcmp(argv[1], "scope") == 0 && argc >= 3) {
            dash_domain_t d = dash_domain_from_name(argv[2]);
            if (d >= DASH_DOM_COUNT) { uart_puts("dash: unknown domain\n"); return; }
            dash_set_scope(d);
            uart_puts("dash: scope=");
            uart_puts(dash_domain_name(dash_scope()));
            uart_puts("\n");
        }
        else if (strcmp(argv[1], "list") == 0) {
            dash_report();
        }
        else if (strcmp(argv[1], "place") == 0 && argc >= 7) {
            int rc = dash_place(argv[2], (uint16_t)parse_hex(argv[3]),
                                (uint16_t)parse_hex(argv[4]),
                                (uint16_t)parse_hex(argv[5]),
                                (uint16_t)parse_hex(argv[6]));
            if (rc != 0) { uart_puts("dash: "); uart_puts(dash_error_string(rc)); uart_putc('\n'); }
        }
        else if (strcmp(argv[1], "move") == 0 && argc >= 5) {
            int rc = dash_move(argv[2], (int)parse_hex(argv[3]),
                               (int)parse_hex(argv[4]));
            if (rc != 0) { uart_puts("dash: "); uart_puts(dash_error_string(rc)); uart_putc('\n'); }
        }
        else if (strcmp(argv[1], "group") == 0 && argc >= 4) {
            int rc = dash_group(argv[2], argv[3]);
            if (rc != 0) { uart_puts("dash: "); uart_puts(dash_error_string(rc)); uart_putc('\n'); }
        }
        else if (strcmp(argv[1], "ungroup") == 0 && argc >= 3) {
            dash_ungroup(argv[2]);
        }
        else if (strcmp(argv[1], "pair") == 0 && argc >= 4) {
            int rc = dash_pair(argv[2], argv[3]);
            if (rc != 0) { uart_puts("dash: "); uart_puts(dash_error_string(rc)); uart_putc('\n'); }
        }
        else if (strcmp(argv[1], "unpair") == 0 && argc >= 3) {
            dash_unpair(argv[2]);
        }
        else if (strcmp(argv[1], "lock") == 0 && argc >= 3) {
            int rc = dash_lock(argv[2]);
            if (rc != 0) { uart_puts("dash: "); uart_puts(dash_error_string(rc)); uart_putc('\n'); }
        }
        else if (strcmp(argv[1], "unlock") == 0 && argc >= 3) {
            dash_unlock(argv[2]);
        }
        else if (strcmp(argv[1], "tile") == 0) {
            if (argc >= 3) {
                dash_domain_t d = dash_domain_from_name(argv[2]);
                if (d < DASH_DOM_COUNT) dash_set_scope(d);
            }
            int rc = dash_tile();
            if (rc == 0) {
                dash_draw();
                uart_puts("dash: tiled in-scope surfaces\n");
            } else {
                uart_puts("dash: tile failed: ");
                uart_puts(dash_error_string(rc));
                uart_putc('\n');
            }
        }
        else if (strcmp(argv[1], "draw") == 0) {
            dash_draw();
            uart_puts("dash: drawn\n");
        }
        else if (strcmp(argv[1], "reset") == 0) {
            dash_reset();
            uart_puts("dash: reset\n");
        }
        else {
            uart_puts("Unknown dash command. Type 'dash'\n");
        }
    }
    if (strcmp(argv[0], "help") == 0) {
        uart_puts("dr1zzle monitor commands:\n");
        uart_puts("\n  screen\n");
        uart_puts("    menu                        - redraw the on-screen menu\n");
        uart_puts("    clear                       - wipe the screen, redraw menu, blank pane\n");
        uart_puts("    display                     - framebuffer geometry and menu state\n");
        uart_puts("    pattern                     - fill the panel with test bars\n");
        uart_puts("    mipi <sleep|wake|cmd n>     - MIPI DSI command channel\n");

        uart_puts("\n  console / link\n");
        uart_puts("    help                        - this list\n");
        uart_puts("    server status|sessions      - goatloader listener and sessions\n");
        uart_puts("    net                         - static IPv4 address and link state\n");
        uart_puts("    shell                       - confirm the interactive shell\n");

        uart_puts("\n  memory\n");
        uart_puts("    memdump <addr> <len>        - hex dump memory\n");
        uart_puts("    md8 <addr> [size]           - memory dump, 8-byte columns\n");
        uart_puts("    peek <addr> | poke <addr> <value> - 32-bit read / write\n");
        uart_puts("    memwrite <addr> <hex>       - write memory\n");
        uart_puts("    physdump <addr>             - dump one 16KB physical page\n");
        uart_puts("    find <start> <end> <pat>    - search memory for a pattern\n");
        uart_puts("    time | spin [ms] | reboot   - uptime, delay, restart to DFU\n");

        uart_puts("\n  dumps (read-only; see `dump list`)\n");
        uart_puts("    dump [list|<target>]        - registry entry / named source\n");
        uart_puts("    dump digest <target>        - SHA-256 over a named source\n");
        uart_puts("       targets: securerom sepos iboot llb kernelcache nand nor ace2\n");
        uart_puts("                sram dram baseband gid uid keybag apfs + register windows\n");
        uart_puts("    dump-securerom | dump-iboot | dump-sep | dump-sepos\n");
        uart_puts("    dump-dram | dump-sram | dump-nand | dump-baseband | dump-apfs\n");
        uart_puts("    dump-gid | dump-uid | dump-gid-uid | dump-memory <start> <end>\n");

        uart_puts("\n  storage / crypto\n");
        uart_puts("    nand <id|info|bad|read|dump|export> - NAND controller and pages\n");
        uart_puts("    nand erase <blk> | write <blk> <pg> <byte> | verify <blk> <pg> <byte>\n");
        uart_puts("    fw <list|save|install> <slot> [name] - write firmware to NAND\n");
        uart_puts("    apfs scan                   - locate APFS container and volume\n");
        uart_puts("    aes <cbc|ecb> <enc|dec> <128|192|256> <uid|gid0|gid1|iv+key> <data>\n");
        uart_puts("    keybag <img4_file>          - decrypt KBAG\n");
        uart_puts("    sepos <ping|random|boot_tz0|status|memdump> - SEP commands\n");
        uart_puts("    ace2 <init|dump|port n reset|enable|status> - ACE2/ACE3\n");
        uart_puts("    tz <info|lockdown|blackbird|tz0_set> - TrustZone TZ0/TZ1\n");
        uart_puts("    recfg <dump|sync|lock>      - recfg sequences\n");

        uart_puts("\n  platform\n");
        uart_puts("    wifi init|scan|list|select|connect|disconnect|dhcp|status|auto\n");
        uart_puts("    devinfo | memmap            - SoC facts and memory map\n");
        uart_puts("    regs <snapshot|show|clear>  - CPU register snapshot\n");
        uart_puts("    cache <clean|flush|inv> <addr> <len> - cache operations\n");
        uart_puts("    bootargs [args]             - show or set boot arguments\n");
        uart_puts("    dt <dump|walk>              - device tree operations\n");
        uart_puts("    kcall <addr> [args...]      - call a kernel function\n");
        uart_puts("    kpatch <addr> <orig> <new>  - patch a kernel byte\n");
        uart_puts("    patch-kernel <addr> <orig> <new> - patch kernel RAM\n");
        uart_puts("    panic [trigger]             - parse a panic log / trigger one\n");
        uart_puts("    usb | irqstat               - DWC2 status and unhandled IRQ count\n");
        uart_puts("    irq stat|list|map usb <n>   - AIC state and line remapping\n");
        uart_puts("    pmgr status|gate|ungate|reset <mask> - PMGR clocks and resets\n");
        uart_puts("    gpio read|set|in|out|func|raw <pin> - pin level, mux, config word\n");
        uart_puts("    i2c status|scan|read|wr|write|speed - I2C master\n");
        uart_puts("    spi status|id|xfer|speed|cs - SPI master\n");
        uart_puts("    wdog status|arm|kick|disarm - watchdog\n");
        uart_puts("    dash place|move|group|pair|lock|tile|report - placed surfaces\n");

        uart_puts("\n  not implemented (research placeholders)\n");
        uart_puts("    ramdisk bootr modload fdt linux_cmdline bootl spawn paging recursion\n");
    }
    else if (strcmp(argv[0], "server") == 0) {
        /* Status only, and that is deliberate. The listener is created at
         * bring-up before this shell starts, and `goat push`, `goat shell`
         * and the sealed-container flow are a conversation with it -- so
         * there is no "off" here to find. Asking for one is a command error,
         * answered with the reason, not a preference to honour. */
        if (argc < 2) {
            uart_puts("Usage: server <status|sessions>\n");
            uart_puts("The goatloader listener is always on; there is no off.\n");
            return;
        }
        if (strcmp(argv[1], "status") == 0 || strcmp(argv[1], "sessions") == 0) {
            goatloader_report();
        } else if (strcmp(argv[1], "off") == 0 || strcmp(argv[1], "stop") == 0 ||
                   strcmp(argv[1], "disable") == 0 || strcmp(argv[1], "down") == 0 ||
                   strcmp(argv[1], "kill") == 0) {
            /* goatloader_stop() prints the reason itself so the sentence
             * lives with the policy rather than at the call site. */
            (void)goatloader_stop();
        } else {
            uart_puts("Usage: server <status|sessions>\n");
        }
    }
    else if (strcmp(argv[0], "net") == 0) {
        net_report();
    }
    else if (strcmp(argv[0], "memdump") == 0) {
        if (argc < 3) { uart_puts("Usage: memdump <addr> <len>\n"); return; }
        uint64_t addr = parse_hex(argv[1]);
        uint64_t len = parse_hex(argv[2]);
        if (len > 4096) len = 4096;
        dump_memory_range(addr, addr + len);
    }
    else if (strcmp(argv[0], "memwrite") == 0) {
        if (argc < 3) { uart_puts("Usage: memwrite <addr> <hex>\n"); return; }
        uint64_t addr = parse_hex(argv[1]);
        uint8_t bytes[64];
        int len = parse_bytes(argv[2], bytes, (int)sizeof(bytes));

        for (int i = 0; i < len; i++) {
            *(volatile uint8_t *)(addr + i) = bytes[i];
        }
        uart_puts("Wrote "); uart_puts(utoa(len)); uart_puts(" bytes to "); uart_puts(utoa_hex(addr)); uart_puts("\n");
    }
    else if (strcmp(argv[0], "time") == 0) {
        uart_puts("Uptime: "); uart_puts(utoa(timer_now_ms())); uart_puts(" ms\n");
    }
    else if (strcmp(argv[0], "devinfo") == 0) {
        uart_puts("\n=== Device Information ===\n");
        uart_puts("SoC:        Apple A11 Bionic (T8015)\n");
        uart_puts("CPU:        2x Monsoon + 4x Mistral (ARMv8.3-A)\n");
        uart_puts("RAM:        LPDDR4X (2/3 GB)\n");
        uart_puts("SRAM:       0x180000000 - 0x1801E8000 (1.9 MB)\n");
        uart_puts("SecureROM:  0x100000000 - 0x10100000 (1 MB)\n");
        uart_puts("NAND:       NVMe-like @ 0x200000000\n");
        uart_puts("USB:        DWC2 OTG + ACE2\n");
        uart_puts("WiFi:       Broadcom BCM4357\n");
        uart_puts("SEP:        S5L8960X (ARMv7-A)\n");
        uart_puts("Boot:       checkm8 -> DFU -> dr1zzle\n");
        uart_puts("Payload:    dr1zzle A11 Research Payload\n");
        uart_puts("Build:      " __DATE__ " " __TIME__ "\n");
        uart_puts("============================\n\n");
    }
    else if (strcmp(argv[0], "memmap") == 0) {
        uart_puts("\n=== Memory Map ===\n");
        uart_puts("0x100000000 - 0x100FFFFF : SecureROM (1 MB)\n");
        uart_puts("0x180000000 - 0x1801E7FFF : SRAM (1.9 MB)\n");
        uart_puts("  0x180000000 - 0x1800007FF : Vector Table (2 KB)\n");
        uart_puts("  0x180000800 - ...         : .text / .rodata\n");
        uart_puts("  ...                       : .bss / heap / stack\n");
        uart_puts("  0x180100000 - 0x1801E7FFF : Goat staging (928 KB)\n");
        uart_puts("0x200000000 - ...           : NAND Controller\n");
        uart_puts("0x20A0C0000 - 0x20A0C0FFF : UART\n");
        uart_puts("0x20E100000 - 0x20E100FFF : Timer\n");
        uart_puts("0x232000000 - 0x2320FFFFF : PMGR\n");
        uart_puts("0x232100000 - 0x2321FFFFF : AIC\n");
        uart_puts("0x235000000 - 0x2350FFFFF : DCP\n");
        uart_puts("0x23C000000 - 0x23C0FFFFF : Mailbox (SEP)\n");
        uart_puts("0x250000000 - 0x2500FFFFF : USB (DWC2)\n");
        uart_puts("0x800000000 - 0xFFFFFFFFF : DRAM (2/3 GB)\n");
        uart_puts("==================\n\n");
    }
    else if (strcmp(argv[0], "regs") == 0) {
        if (argc < 2) {
            uart_puts("Usage: regs <snapshot|show|clear>\n");
            return;
        }
        if (strcmp(argv[1], "snapshot") == 0) {
            int nostage = (argc >= 3 && strcmp(argv[2], "nostage") == 0);
            regs_snapshot(nostage);
        } else if (strcmp(argv[1], "show") == 0) {
            regs_show();
        } else if (strcmp(argv[1], "clear") == 0) {
            regs_clear();
        } else {
            uart_puts("Unknown regs command. Use: snapshot, show, clear\n");
        }
    }
    else if (strcmp(argv[0], "cache") == 0) {
        if (argc < 4) { 
            uart_puts("Usage: cache <clean|flush|inv> <addr> <len>\n"); 
            return; 
        }
        uint64_t addr = parse_hex(argv[2]);
        uint64_t len = parse_hex(argv[3]);
        if (strcmp(argv[1], "clean") == 0) {
            for (uint64_t a = addr; a < addr + len; a += 64) {
                __asm__ volatile("dc cvac, %0" :: "r"(a));
            }
            __asm__ volatile("dsb sy" ::: "memory");
            uart_puts("cache: clean done\n");
        } else if (strcmp(argv[1], "flush") == 0) {
            for (uint64_t a = addr; a < addr + len; a += 64) {
                __asm__ volatile("dc cvac, %0" :: "r"(a));
            }
            for (uint64_t a = addr; a < addr + len; a += 64) {
                __asm__ volatile("ic ivau, %0" :: "r"(a));
            }
            __asm__ volatile("dsb sy; isb" ::: "memory");
            uart_puts("cache: flush (clean+invalidate) done\n");
        } else if (strcmp(argv[1], "inv") == 0 || strcmp(argv[1], "invalidate") == 0) {
            for (uint64_t a = addr; a < addr + len; a += 64) {
                __asm__ volatile("dc ivac, %0" :: "r"(a));
            }
            __asm__ volatile("dsb sy; isb" ::: "memory");
            uart_puts("cache: invalidate done\n");
        } else {
            uart_puts("Unknown cache op. Use: clean, flush, inv\n");
        }
    }
    else if (strcmp(argv[0], "bootargs") == 0) {
        extern char *g_boot_args;
        if (argc >= 2) {
            /* Set boot args */
            g_boot_args = argv[1];
            uart_puts("bootargs: set to '");
            uart_puts(g_boot_args);
            uart_puts("'\n");
        } else {
            uart_puts("bootargs: '");
            uart_puts(g_boot_args ? g_boot_args : "(none)");
            uart_puts("'\n");
        }
    }
    else if (strcmp(argv[0], "dt") == 0) {
        if (argc < 2) { uart_puts("Usage: dt <dump|walk>\n"); return; }
        if (strcmp(argv[1], "dump") == 0) {
            extern uint64_t g_boot_dtb;
            if (!g_boot_dtb) { uart_puts("dt: no device tree\n"); return; }
            uart_puts("dt: dumping device tree @ ");
            uart_puts(utoa_hex(g_boot_dtb));
            uart_puts("\n");
            /* Simple FDT dump - just header */
            uint32_t *fdt = (uint32_t *)g_boot_dtb;
            uart_puts("  magic: 0x"); uart_puts(utoa_hex(fdt[0])); uart_puts("\n");
            uart_puts("  totalsize: "); uart_puts(utoa(fdt[1])); uart_puts("\n");
            uart_puts("  off_dt_struct: "); uart_puts(utoa(fdt[2])); uart_puts("\n");
            uart_puts("  off_dt_strings: "); uart_puts(utoa(fdt[3])); uart_puts("\n");
            uart_puts("  off_mem_rsvmap: "); uart_puts(utoa(fdt[4])); uart_puts("\n");
            uart_puts("  version: "); uart_puts(utoa(fdt[5])); uart_puts("\n");
        } else if (strcmp(argv[1], "walk") == 0) {
            uart_puts("dt: walk not implemented yet\n");
        } else {
            uart_puts("Unknown dt command\n");
        }
    }
    else if (strcmp(argv[0], "find") == 0) {
        if (argc < 3) { 
            uart_puts("Usage: find <start> <end> <pattern_hex>\n"); 
            uart_puts("       find <start> <end> <byte1> <byte2> ...\n"); 
            return; 
        }
        uint64_t start = parse_hex(argv[1]);
        uint64_t end = parse_hex(argv[2]);
        uint8_t pattern[64];
        int plen = 0;
        
        if (argc == 4) {
            /* Single hex string */
            plen = parse_bytes(argv[3], pattern, 64);
        } else {
            /* Multiple byte args */
            for (int i = 3; i < argc && plen < 64; i++) {
                pattern[plen++] = (uint8_t)parse_hex(argv[i]);
            }
        }
        
        if (plen == 0) {
            uart_puts("find: no pattern bytes\n");
            return;
        }
        
        uart_puts("find: searching 0x"); uart_puts(utoa_hex(start));
        uart_puts(" - 0x"); uart_puts(utoa_hex(end));
        uart_puts(" for pattern (");
        uart_puts(utoa(plen));
        uart_puts(" bytes)...\n");
        
        int found = 0;
        for (uint64_t addr = start; addr + plen <= end; addr++) {
            int match = 1;
            for (int i = 0; i < plen; i++) {
                if (*(volatile uint8_t *)(addr + i) != pattern[i]) {
                    match = 0;
                    break;
                }
            }
            if (match) {
                uart_puts("  found at 0x"); uart_puts(utoa_hex(addr)); uart_puts("\n");
                found++;
                if (found >= 16) {
                    uart_puts("  ... (max 16 matches shown)\n");
                    break;
                }
            }
        }
        uart_puts("find: "); uart_puts(utoa(found)); uart_puts(" match(es)\n");
    }
    else if (strcmp(argv[0], "kcall") == 0) {
        if (argc < 2) { 
            uart_puts("Usage: kcall <addr> [arg0] [arg1] [arg2] [arg3]\n"); 
            return; 
        }
        uint64_t addr = parse_hex(argv[1]);
        uint64_t args[4] = {0, 0, 0, 0};
        for (int i = 0; i < 4 && (i + 2) < argc; i++) {
            args[i] = parse_hex(argv[i + 2]);
        }
        
        uart_puts("kcall: calling 0x"); uart_puts(utoa_hex(addr));
        uart_puts(" with args: ");
        for (int i = 0; i < 4; i++) {
            uart_puts("x"); uart_puts(utoa(i));
            uart_puts("=0x"); uart_puts(utoa_hex(args[i]));
            if (i < 3) uart_puts(", ");
        }
        uart_puts("\n");
        
        typedef uint64_t (*kfunc_t)(uint64_t, uint64_t, uint64_t, uint64_t);
        kfunc_t func = (kfunc_t)addr;
        uint64_t ret = func(args[0], args[1], args[2], args[3]);
        
        uart_puts("kcall: returned 0x"); uart_puts(utoa_hex(ret)); uart_puts("\n");
    }
    else if (strcmp(argv[0], "kpatch") == 0) {
        if (argc < 4) { uart_puts("Usage: kpatch <addr> <orig_hex> <new_hex>\n"); return; }
        uint64_t addr = parse_hex(argv[1]);
        uint8_t orig = parse_hex(argv[2]);
        uint8_t new = parse_hex(argv[3]);
        uint8_t current = *(volatile uint8_t *)addr;
        if (current != orig) {
            uart_puts("Warning: expected 0x"); uart_puts(utoa_hex(orig));
            uart_puts(" but found 0x"); uart_puts(utoa_hex(current)); uart_puts("\n");
        } else {
            *(volatile uint8_t *)addr = new;
            uint64_t va = addr;
            __asm__ volatile("dc cvac, %0" :: "r"(va));
            __asm__ volatile("ic ivau, %0" :: "r"(va));
            __asm__ volatile("dsb sy; isb" ::: "memory");
            uart_puts("Patched 0x"); uart_puts(utoa_hex(addr)); uart_puts("\n");
        }
    }
    else if (strcmp(argv[0], "reboot") == 0) {
        /* Two ways to reset, in order of how much they can go wrong.
         *
         * The watchdog reset is the one the hardware documents: arm WD1
         * with a bite time of zero and it resets the SoC normally. The
         * PMGR fallback in start.S asserts every reset line at once, which
         * is the right last resort when nothing else works and is a poor
         * first choice. */
        uart_puts("Rebooting via watchdog...\n");
        watchdog_reset();

        /* If the window is dead or the bit map is wrong, fall through to
         * the blanket reset. */
        uart_puts("watchdog reset did not take; resetting via PMGR\n");
        reboot();
    }
    else if (strcmp(argv[0], "dump") == 0) {
        /* Unified front-end over the dump registry in src/drivers/dump.c.
         * `dump` and `dump list` print the registry; any other argument is a
         * target name, matched case-insensitively so `dump UID` is `dump uid`.
         * Targets with a hand-written reader (NAND, APFS, ACE2, SEP) are
         * routed there; everything else is a flat physical range the engine
         * can read, or a named source that honestly reports it needs a
         * driver. */
        unsigned count = 0;
        const dump_target_t *targets = dump_targets(&count);

        if (argc < 2 || ci_streq(argv[1], "list")) {
            dump_targets_list();
            return;
        }

        int digest = 0;
        const char *name = argv[1];
        if (ci_streq(name, "digest") && argc >= 3) {
            digest = 1;
            name = argv[2];
        }

        const dump_target_t *t = 0;
        for (unsigned i = 0; i < count; i++) {
            if (ci_streq(targets[i].name, name)) {
                t = &targets[i];
                break;
            }
        }
        if (!t) {
            uart_puts("dump: unknown target '");
            uart_puts(name);
            uart_puts("'; try 'dump list'\n");
            return;
        }

        if (ci_streq(name, "nand") || ci_streq(name, "nandflash")) {
            if (digest) { uart_puts("dump: nand has no flat range to digest\n"); return; }
            dump_nand_all();
        }
        else if (ci_streq(name, "nandbad")) {
            uart_puts("dump: use 'nand bad <block>' for a bad-block scan\n");
        }
        else if (ci_streq(name, "apfs")) {
            if (digest) { uart_puts("dump: apfs has no flat range to digest\n"); return; }
            extract_apfs_files();
        }
        else if (ci_streq(name, "ace2")) {
            if (digest) { uart_puts("dump: ace2 has no flat range to digest\n"); return; }
            ace2_dump();
        }
        else if (ci_streq(name, "sep") || ci_streq(name, "sepos")) {
            if (digest) { uart_puts("dump: sepos has no flat range to digest\n"); return; }
            dump_sepos();
        }
        else if (t->status == DUMP_NO_DRIVER) {
            uart_puts("dump: ");
            uart_puts(t->name);
            uart_puts(" needs a driver: ");
            uart_puts(t->depends ? t->depends : "unimplemented");
            uart_putc('\n');
        }
        else if (digest) {
            dump_digest(t->base, t->length);
        }
        else {
            dump_opts_t opts = DUMP_OPTS_DEFAULT;
            dump_run(t->base, t->length, &opts);
        }
    }
    else if (strcmp(argv[0], "dump-securerom") == 0) {
        dump_secure_rom();
    }
    else if (strcmp(argv[0], "dump-sepos") == 0) {
        dump_sepos();
    }
    else if (strcmp(argv[0], "dump-memory") == 0) {
        if (argc < 3) { uart_puts("Usage: dump-memory <start> <end>\n"); return; }
        uint64_t start = parse_hex(argv[1]);
        uint64_t end = parse_hex(argv[2]);
        dump_memory_range(start, end);
    }
    else if (strcmp(argv[0], "dump-dram") == 0) {
        dump_dram();
    }
    else if (strcmp(argv[0], "dump-sram") == 0) {
        dump_sram();
    }
    else if (strcmp(argv[0], "dump-baseband") == 0) {
        dump_baseband();
    }
    else if (strcmp(argv[0], "dump-nand") == 0) {
        if (argc >= 3) {
            uint32_t start = parse_hex(argv[1]);
            uint32_t end = parse_hex(argv[2]);
            dump_nand_range(start, end);
        } else {
            dump_nand_all();
        }
    }
    else if (strcmp(argv[0], "dump-apfs") == 0) {
        extract_apfs_files();
    }
    else if (strcmp(argv[0], "dump-iboot") == 0) {
        dump_iboot();
    }
    else if (strcmp(argv[0], "dump-sep") == 0) {
        dump_sepos();
    }
    else if (strcmp(argv[0], "dump-gid") == 0) {
        dump_gid();
    }
    else if (strcmp(argv[0], "dump-uid") == 0) {
        dump_uid();
    }
    else if (strcmp(argv[0], "dump-gid-uid") == 0) {
        dump_gid();
        dump_uid();
    }
    else if (strcmp(argv[0], "aes") == 0) {
        if (argc < 3) { uart_puts("Usage: aes <encrypt|decrypt|test> <data>\n"); return; }
        if (strcmp(argv[1], "test") == 0) {
            aes_test();
        } else if (strcmp(argv[1], "decrypt") == 0) {
            uint8_t ciphertext[16], plaintext[16], iv[16] = {0};
            int length = parse_bytes(argv[2], ciphertext, (int)sizeof(ciphertext));
            if (length != 16) {
                uart_puts("Usage: aes decrypt <16-byte-ciphertext-hex>\n");
                return;
            }
            int rc = aes_crypt_block(AES_KEY_GID, 1, ciphertext, plaintext, iv);
            uart_puts(rc == 0 ? "aes: GID decrypt completed; plaintext withheld\n"
                              : "aes: GID decrypt failed\n");
        } else if (strcmp(argv[1], "encrypt") == 0) {
            aes_test();
        } else {
            aes_test();
        }
    }
    else if (strcmp(argv[0], "keybag") == 0) {
        if (argc < 2) { uart_puts("Usage: keybag <img4_data_hex>\n"); return; }
        uint8_t img4[128];
        int length = parse_bytes(argv[1], img4, (int)sizeof(img4));
        if (length == 0) {
            uart_puts("keybag: expected hexadecimal IMG4/KBAG bytes\n");
            return;
        }
        decrypt_keybag(img4, (uint32_t)length);
    }
    else if (strcmp(argv[0], "nand") == 0) {
        if (argc < 2) {
            uart_puts("Usage: nand <id|info|bad <blk>|read <blk> <pg>|dump <first> <last>\n");
            uart_puts("            nand erase <blk> | write <blk> <pg> <byte> | verify <blk> <pg> <byte>\n");
            return;
        }
        if (strcmp(argv[1], "id") == 0 || strcmp(argv[1], "info") == 0) {
            if (nand_init() != 0) {
                uart_puts("nand: controller/ID unavailable\n");
                return;
            }
            const nand_info_t *info = nand_info();
            uart_puts("nand: id=");
            for (uint32_t i = 0; i < info->id_len; i++) {
                uart_puts(i == 0u ? "" : ":");
                uart_puts(utoa_hex(info->id[i]));
            }
            uart_puts(" page="); uart_puts(utoa(info->geometry.page_size));
            uart_puts(" oob="); uart_puts(utoa(info->geometry.oob_size));
            uart_puts(" blocks="); uart_puts(utoa(info->geometry.block_count));
            uart_puts("\n");
            uart_puts("nand: ecc corrected="); uart_puts(utoa(info->ecc.corrected));
            uart_puts(" failed="); uart_puts(utoa(info->ecc.failed));
            uart_puts(" uncorrectable="); uart_puts(utoa(info->ecc.uncorrectable));
            uart_puts("\n");
            uart_puts("nand: write erased="); uart_puts(utoa(info->write.erased));
            uart_puts(" programmed="); uart_puts(utoa(info->write.programmed));
            uart_puts(" failed="); uart_puts(utoa(info->write.write_failed));
            uart_puts(" verify-failed="); uart_puts(utoa(info->write.verify_failed));
            uart_puts("\n");
        } else if (strcmp(argv[1], "bad") == 0) {
            if (argc < 3) { uart_puts("Usage: nand bad <block>\n"); return; }
            if (nand_init() != 0) { uart_puts("nand: unavailable\n"); return; }
            int bad = nand_is_bad_block((uint32_t)parse_hex(argv[2]));
            uart_puts(bad < 0 ? "nand: bad-block read failed\n"
                              : (bad ? "nand: BAD\n" : "nand: good\n"));
        } else if (strcmp(argv[1], "read") == 0) {
            if (argc < 4) { uart_puts("Usage: nand read <block> <page>\n"); return; }
            if (nand_init() != 0) { uart_puts("nand: unavailable\n"); return; }
            int rc = nand_read_page((uint32_t)parse_hex(argv[2]),
                                    (uint32_t)parse_hex(argv[3]),
                                    g_nand_page, g_nand_oob);
            uart_puts(rc == 0 ? "nand: page read OK; raw bytes withheld from UART\n"
                              : "nand: page read failed\n");
        } else if (strcmp(argv[1], "erase") == 0) {
            /* Low-level bring-up: prove a block erases before trusting the
             * slot writer. Destructive by construction; the block is named. */
            if (argc < 3) { uart_puts("Usage: nand erase <block>\n"); return; }
            if (nand_init() != 0) { uart_puts("nand: unavailable\n"); return; }
            uint32_t block = (uint32_t)parse_hex(argv[2]);
            int rc = nand_erase_block(block);
            if (rc == 0) {
                uart_puts("nand: erased block "); uart_puts(utoa(block)); uart_putc('\n');
            } else {
                uart_puts("nand erase: failed rc="); uart_puts(utoa((uint64_t)(int64_t)rc));
                uart_putc('\n');
            }
        } else if (strcmp(argv[1], "write") == 0 ||
                   strcmp(argv[1], "verify") == 0) {
            /* Fill a whole page with one byte and program (write) or read back
             * and compare (verify). A single-byte pattern is enough to catch a
             * stuck line or a bad plane without shipping a whole page of hex
             * down a 115200 link. */
            int writing = (argv[1][0] == 'w');
            if (argc < 5) {
                uart_puts(writing ? "Usage: nand write <block> <page> <byte>\n"
                                 : "Usage: nand verify <block> <page> <byte>\n");
                return;
            }
            if (nand_init() != 0) { uart_puts("nand: unavailable\n"); return; }
            const nand_info_t *info = nand_info();
            uint32_t block = (uint32_t)parse_hex(argv[2]);
            uint32_t page = (uint32_t)parse_hex(argv[3]);
            uint8_t fill = (uint8_t)parse_hex(argv[4]);
            memset(g_nand_page, fill, info->geometry.page_size);
            int rc;
            if (writing) {
                rc = nand_write_page(block, page, g_nand_page, 0);
                if (rc == 0) rc = nand_verify_page(block, page, g_nand_page, 0);
                uart_puts(rc == 0 ? "nand: page programmed and read back OK\n"
                                  : "nand: page program/verify FAILED\n");
            } else {
                rc = nand_verify_page(block, page, g_nand_page, 0);
                uart_puts(rc == 0 ? "nand: page matches\n" : "nand: page differs\n");
            }
            if (rc != 0) {
                uart_puts("nand: rc=");
                uart_puts(utoa((uint64_t)(int64_t)rc));
                uart_putc('\n');
            }
        } else if (strcmp(argv[1], "dump") == 0) {
            if (argc < 4) { uart_puts("Usage: nand dump <first-block> <last-block>\n"); return; }
            dump_nand_range((uint32_t)parse_hex(argv[2]),
                            (uint32_t)parse_hex(argv[3]));
        } else if (strcmp(argv[1], "export") == 0) {
            if (argc < 4) {
                uart_puts("Usage: nand export <first-block> <last-block>\n");
                return;
            }
            int rc = nand_export_range((uint32_t)parse_hex(argv[2]),
                                       (uint32_t)parse_hex(argv[3]));
            if (rc != 0) {
                uart_puts("nand export: failed rc=");
                uart_puts(utoa((uint64_t)rc));
                uart_putc('\n');
            }
        } else {
            uart_puts("Unknown nand command\n");
        }
    }
    else if (strcmp(argv[0], "apfs") == 0) {
        if (argc < 2 || strcmp(argv[1], "scan") != 0) {
            uart_puts("Usage: apfs scan\n");
            return;
        }
        extract_apfs_files();
    }
    else if (strcmp(argv[0], "fw") == 0) {
        /* Two directions onto NAND, one writer (src/core/fw_store.c):
         *   save     -- write the running firmware image to a slot
         *   install  -- write the staged goat container to a slot
         * The core's `fw install` is the same as install here; only the
         * firmware can `save`, because only the firmware is the image being
         * saved. */
        if (argc < 2) {
            uart_puts("Usage: fw <list|save <slot> [name]|install <slot> [name]>\n");
            uart_puts("  list     firmware slots on NAND\n");
            uart_puts("  save     write this running firmware into a slot\n");
            uart_puts("  install  write the staged goat container into a slot\n");
            return;
        }
        if (strcmp(argv[1], "list") == 0) {
            fw_store_scan();
            if (fw_store_count() == 0) { uart_puts("fw: no slots on NAND\n"); return; }
            for (unsigned s = 0; s < FW_SLOT_COUNT; s++) {
                const firmware_header_t *h = fw_store_slot(s);
                if (!h) continue;
                uart_puts("fw: [");
                uart_puts(utoa(s));
                uart_puts("] ");
                for (unsigned i = 0; i < 16u && h->name[i]; i++) uart_putc(h->name[i]);
                uart_puts(" size=");
                uart_puts(utoa(h->size));
                uart_puts(" base=0x");
                uart_puts(utoa_hex(h->load_base));
                uart_puts("\n");
            }
        } else if (strcmp(argv[1], "save") == 0) {
            /* Self-install: the bytes are this image's own
             * [FW_LOAD_BASE, __firmware_image_end), which the linker makes
             * exactly the .bin the build produced. */
            if (argc < 3) { uart_puts("Usage: fw save <slot> [name]\n"); return; }
            if (nand_init() != 0) { uart_puts("fw: NAND unavailable\n"); return; }
            uint32_t slot = (uint32_t)parse_hex(argv[2]);
            if (slot >= FW_SLOT_COUNT) { uart_puts("fw: slot out of range\n"); return; }
            const char *name = argc >= 4 ? argv[3] : "dr1zzle";
            uint32_t size = (uint32_t)((uintptr_t)__firmware_image_end -
                                       (uintptr_t)FW_LOAD_BASE);
            uint32_t entry_off = (uint32_t)((uintptr_t)&_start -
                                            (uintptr_t)FW_LOAD_BASE);
            uart_puts("fw: writing ");
            uart_puts(utoa(size));
            uart_puts(" bytes to slot ");
            uart_puts(utoa(slot));
            uart_puts("; erase + program + readback\n");
            int rc = fw_store_install(slot,
                                      (const uint8_t *)(uintptr_t)FW_LOAD_BASE,
                                      size, FW_LOAD_BASE, entry_off, name);
            if (rc == 0) {
                uart_puts("fw: slot ");
                uart_puts(utoa(slot));
                uart_puts(" saved; the core can `run ");
                uart_puts(utoa(slot));
                uart_puts("`\n");
            } else {
                uart_puts("fw: save failed rc=");
                uart_puts(utoa((uint64_t)(int64_t)rc));
                uart_putc('\n');
            }
        } else if (strcmp(argv[1], "install") == 0) {
            /* Staged-container install, like the core menu and `goat install`.
             * A firmware normally has nothing staged (the core owns the
             * listener), so this reports no-stage unless the operator staged
             * something first. */
            if (argc < 3) { uart_puts("Usage: fw install <slot> [name]\n"); return; }
            uint32_t slot = (uint32_t)parse_hex(argv[2]);
            if (slot >= FW_SLOT_COUNT) { uart_puts("fw: slot out of range\n"); return; }
            int rc = goatloader_install((unsigned)slot, argc >= 4 ? argv[3] : 0);
            if (rc == 0) {
                uart_puts("fw: installed to slot ");
                uart_puts(utoa(slot));
                uart_putc('\n');
            } else if (rc == -1) {
                uart_puts("fw: no key staged -- `goat push` first\n");
            } else if (rc == -2) {
                uart_puts("fw: no image staged -- `goat push` first\n");
            } else if (rc == -3) {
                uart_puts("fw: staged container failed verification\n");
            } else if (rc == -4) {
                uart_puts("fw: decryption failed\n");
            } else {
                uart_puts("fw: NAND write failed (bad block or no controller?)\n");
            }
        } else {
            uart_puts("Usage: fw <list|save <slot> [name]|install <slot> [name]>\n");
        }
    }
    else if (strcmp(argv[0], "ace2") == 0) {
        if (argc < 2) { uart_puts("Usage: ace2 <init|dump|port>\n"); return; }
        if (strcmp(argv[1], "init") == 0) {
            ace2_init();
        } else if (strcmp(argv[1], "dump") == 0) {
            ace2_dump();
        } else if (strcmp(argv[1], "port") == 0) {
            if (argc < 4) { uart_puts("Usage: ace2 port <n> <reset|enable|status>\n"); return; }
            int port = parse_hex(argv[2]);
            if (strcmp(argv[3], "reset") == 0) ace2_port_reset(port);
            else if (strcmp(argv[3], "enable") == 0) ace2_port_enable(port);
            else if (strcmp(argv[3], "status") == 0) ace2_dump_port_status(port);
            else uart_puts("Unknown port command\n");
        } else {
            uart_puts("Unknown ace2 command\n");
        }
    }
    else if (strcmp(argv[0], "sepos") == 0) {
        if (argc < 2) { uart_puts("Usage: sepos <ping|random|boot_tz0|status|memdump>\n"); return; }
        if (strcmp(argv[1], "ping") == 0) {
            if (sep_send_command(0xFF, 0, 0) == 0) uart_puts("SEP ping OK\n");
            else uart_puts("SEP ping failed\n");
        } else if (strcmp(argv[1], "random") == 0) {
            sep_send_command(0x10, 0, 0);
        } else if (strcmp(argv[1], "boot_tz0") == 0) {
            sep_send_command(0x05, 0, 0);
        } else if (strcmp(argv[1], "status") == 0) {
            sepos_status();
        } else if (strcmp(argv[1], "memdump") == 0) {
            if (argc < 4) { uart_puts("Usage: sepos memdump <addr> <len>\n"); return; }
            sepos_memdump(parse_hex(argv[2]), parse_hex(argv[3]));
        } else {
            uart_puts("Unknown sepos command\n");
        }
    }
    else if (strcmp(argv[0], "wifi") == 0) {
        if (argc < 2) { 
            uart_puts("Usage: wifi <init|scan|list|select|connect|disconnect|dhcp|status|auto>\n"); 
            return; 
        }
        if (strcmp(argv[1], "init") == 0) wifi_init();
        else if (strcmp(argv[1], "scan") == 0) {
            int noauto = (argc >= 3 && strcmp(argv[2], "noauto") == 0);
            wifi_scan(noauto);
        }
        else if (strcmp(argv[1], "list") == 0) wifi_display_networks();
        else if (strcmp(argv[1], "select") == 0) {
            if (argc < 3) { uart_puts("Usage: wifi select <index>\n"); return; }
            wifi_select((uint8_t)parse_dec(argv[2]));
        }
        else if (strcmp(argv[1], "connect") == 0) {
            if (argc < 3) { uart_puts("Usage: wifi connect <ssid> [passphrase]\n       wifi connect [passphrase]  (uses selected network)\n"); return; }
            wifi_connect(argv[2], argc >= 4 ? argv[3] : "");
        }
        else if (strcmp(argv[1], "disconnect") == 0) wifi_disconnect();
        else if (strcmp(argv[1], "dhcp") == 0) wifi_dhcp();
        else if (strcmp(argv[1], "status") == 0) wifi_status();
        else if (strcmp(argv[1], "auto") == 0) {
            if (argc < 3) { uart_puts("Usage: wifi auto <on|off>\n"); return; }
            wifi_auto_connect(argv[2]);
        }
        else uart_puts("Unknown wifi command\n");
    }
    else if (strcmp(argv[0], "patch-kernel") == 0) {
        if (argc < 4) { uart_puts("Usage: patch-kernel <addr> <orig_hex> <new_hex>\n"); return; }
        uint64_t addr = parse_hex(argv[1]);
        uint8_t orig = parse_hex(argv[2]);
        uint8_t new = parse_hex(argv[3]);
        uint8_t current = *(volatile uint8_t *)addr;
        if (current != orig) {
            uart_puts("Warning: expected 0x"); uart_puts(utoa_hex(orig));
            uart_puts(" but found 0x"); uart_puts(utoa_hex(current)); uart_puts("\n");
        } else {
            *(volatile uint8_t *)addr = new;
            uint64_t va = addr;
            __asm__ volatile("dc cvac, %0" :: "r"(va));
            __asm__ volatile("ic ivau, %0" :: "r"(va));
            __asm__ volatile("dsb sy; isb" ::: "memory");
            uart_puts("Patched 0x"); uart_puts(utoa_hex(addr)); uart_puts("\n");
        }
    }
    else if (strcmp(argv[0], "panic") == 0) {
        if (argc >= 2 && strcmp(argv[1], "trigger") == 0) {
            uart_puts("panic: triggering panic...\n");
            for (;;) { __asm__ volatile("wfe"); }
        } else {
            parse_panic_log();
        }
    }
    else if (strcmp(argv[0], "peek") == 0) {
        if (argc < 2) { uart_puts("Usage: peek <addr>\n"); return; }
        uint64_t addr = parse_hex(argv[1]);
        uint32_t val = *(volatile uint32_t *)addr;
        uart_puts("0x"); uart_puts(utoa_hex(addr)); uart_puts(": 0x"); uart_puts(utoa_hex(val)); uart_puts("\n");
    }
    else if (strcmp(argv[0], "poke") == 0) {
        if (argc < 3) { uart_puts("Usage: poke <addr> <value>\n"); return; }
        uint64_t addr = parse_hex(argv[1]);
        uint32_t val = parse_hex(argv[2]);
        *(volatile uint32_t *)addr = val;
        uart_puts("wrote 0x"); uart_puts(utoa_hex(val)); uart_puts(" to 0x"); uart_puts(utoa_hex(addr)); uart_puts("\n");
    }
    else if (strcmp(argv[0], "md8") == 0) {
        if (argc < 2) { uart_puts("Usage: md8 <addr> [size]\n"); return; }
        uint64_t addr = parse_hex(argv[1]);
        uint64_t size = argc >= 3 ? parse_hex(argv[2]) : 0x20;
        if (size > 4096) size = 4096;
        dump_memory_range(addr, addr + size);
    }
    else if (strcmp(argv[0], "physdump") == 0) {
        if (argc < 2) { uart_puts("Usage: physdump <addr>\n"); return; }
        uint64_t addr = parse_hex(argv[1]);
        /* Align to page boundary */
        addr &= ~0x3FFF;
        dump_memory_range(addr, addr + 0x4000);
    }
    else if (strcmp(argv[0], "spin") == 0) {
        uint64_t ms = argc >= 2 ? parse_dec(argv[1]) : 1000;
        uart_puts("spin: "); uart_puts(utoa(ms)); uart_puts(" ms\n");
        timer_sleep_ms((uint32_t)ms);
        uart_puts("spin: done\n");
    }
    else if (strcmp(argv[0], "ramdisk") == 0) {
        uart_puts("ramdisk: not implemented - use goatloader for container loading\n");
    }
    else if (strcmp(argv[0], "bootr") == 0) {
        if (argc < 2) {
            uart_puts("Usage: bootr <kernel_base> [initrd_addr] [initrd_size]\n");
            uart_puts("  Boots iOS kernelcache at kernel_base\n");
            return;
        }
        uint64_t kernel_base = parse_hex(argv[1]);
        uint64_t initrd_addr = argc >= 3 ? parse_hex(argv[2]) : 0;
        uint64_t initrd_size = argc >= 4 ? parse_hex(argv[3]) : 0;
        boot_ios_kernel(kernel_base, initrd_addr, initrd_size);
    }
    else if (strcmp(argv[0], "modload") == 0) {
        if (argc < 2) {
            uart_puts("Usage: modload <module_name>\n");
            uart_puts("  Loads a module (kpf, etc.) from goatloader staging area\n");
            return;
        }
        modload_module(argv[1]);
    }
    else if (strcmp(argv[0], "fdt") == 0) {
        uart_puts("fdt: not implemented - use dt dump\n");
    }
    else if (strcmp(argv[0], "linux_cmdline") == 0) {
        uart_puts("linux_cmdline: not implemented - use bootargs\n");
    }
    else if (strcmp(argv[0], "bootl") == 0) {
        uart_puts("bootl: not implemented - Linux boot not supported\n");
    }
    else if (strcmp(argv[0], "spawn") == 0) {
        uart_puts("spawn: not implemented - usermode not supported\n");
    }
    else if (strcmp(argv[0], "paging") == 0) {
        uart_puts("paging: not implemented - MMU not enabled by default\n");
    }
    else if (strcmp(argv[0], "recursion") == 0) {
        uart_puts("recursion: stack guard test not implemented\n");
    }
    else if (strcmp(argv[0], "shell") == 0) {
        /* The shell is already running - this is a no-op for UART.
         * Over TCP, the goatloader provides the same shell. */
        uart_puts("Already in interactive shell\n");
    }
    else if (strcmp(argv[0], "autoboot") == 0) {
        if (argc < 2) {
            uart_puts("Usage: autoboot <on|off|status> [kernel_base]\n");
            return;
        }
        if (strcmp(argv[1], "on") == 0) {
            uint64_t kernel_base = argc >= 3 ? parse_hex(argv[2]) : 0x800000000;
            autoboot_enable(kernel_base);
        } else if (strcmp(argv[1], "off") == 0) {
            autoboot_disable();
        } else if (strcmp(argv[1], "status") == 0) {
            autoboot_status();
        } else {
            uart_puts("Unknown autoboot command\n");
        }
    }
    else if (strcmp(argv[0], "usb") == 0) {
        usb_debug_dump();
    }
    else if (strcmp(argv[0], "irqstat") == 0) {
        uart_puts("unhandled IRQs: ");
        uart_puts(utoa(irq_unhandled_count()));
        uart_puts(" (handled ");
        uart_puts(utoa(irq_total_count()));
        uart_puts(")\n");
    }
    else if (strcmp(argv[0], "display") == 0) {
        const display_info_t *di = display_info();
        const display_fb_t *f = display_fb();
        uart_puts("discovered: ");
        if (di->found) {
            uart_puts("base=0x"); uart_puts(utoa_hex(di->base));
            uart_puts(" "); uart_puts(utoa(di->width));
            uart_puts("x"); uart_puts(utoa(di->height));
            uart_puts(" stride="); uart_puts(utoa(di->stride_bytes));
            uart_puts(" depth="); uart_puts(utoa(di->bpp));
        } else {
            uart_puts("none (no device tree)");
        }
        uart_puts("\nattached: ");
        if (f) {
            uart_puts(utoa(f->width));
            uart_puts("x"); uart_puts(utoa(f->height));
        } else {
            uart_puts("no");
        }
        uart_puts("\nmenu: ");
        uart_puts(menu_active() ? "panel + output pane" : "off");
        uart_puts("\n");
    }
    else if (strcmp(argv[0], "pattern") == 0) {
        /* Fill the panel with a colour-bar pattern. This is the check that
         * the framebuffer we adopted is in fact the one being scanned out:
         * if the geometry were wrong you would see the corruption rather
         * than clean bars. */
        if (!display_fb()) {
            uart_puts("no framebuffer attached; run 'display'\n");
            return;
        }
        static const uint32_t bars[8] = {
            0xffffffff, 0xff00ffff, 0xff00ff00, 0xff0000ff,
            0xffffff00, 0xffff00ff, 0xff00ffff, 0xff000000,
        };
        const display_fb_t *f = display_fb();
        uint32_t bar_w = f->width / 8;
        for (uint32_t i = 0; i < 8; i++) {
            display_fb_fill_rect(i * bar_w, 0, bar_w, f->height, bars[i]);
        }
        uart_puts("pattern: 8 vertical bars, ");
        uart_puts(utoa(bar_w));
        uart_puts("px wide\n");
    }
    else if (strcmp(argv[0], "clear") == 0) {
        /* Wipe the whole framebuffer and redraw the menu on a fresh canvas,
         * then blank the output pane. `display_console_clear` only repainted
         * a full-screen console the firmware no longer uses, which is why the
         * screen appeared not to clear. */
        menu_redraw();
        uart_puts("clear\n");
    }
    else if (strcmp(argv[0], "menu") == 0) {
        menu_redraw();
        uart_puts("menu: redrawn\n");
    }
    else if (strcmp(argv[0], "mipi") == 0) {
        if (argc < 3) { uart_puts("Usage: mipi <sleep|wake|cmd <n>>\n"); return; }
        if (strcmp(argv[1], "sleep") == 0) {
            uart_puts(display_mipi_command(0x28) == 0 ? "mipi: sleep ok\n"
                                                      : "mipi: sleep timed out\n");
        } else if (strcmp(argv[1], "wake") == 0) {
            uart_puts(display_mipi_command(0x11) == 0 ? "mipi: wake ok\n"
                                                     : "mipi: wake timed out\n");
        } else if (strcmp(argv[1], "cmd") == 0) {
            if (display_mipi_command(parse_hex(argv[2])) == 0)
                uart_puts("mipi: command ok\n");
            else
                uart_puts("mipi: command timed out\n");
        } else {
            uart_puts("Unknown mipi command\n");
        }
    }
    /* ---- Phase 3 peripherals ------------------------------------------- */
    else if (strcmp(argv[0], "gpio") == 0) {
        if (argc < 2) {
            uart_puts("Usage: gpio <read|set|in|out|func|raw> ...\n");
            return;
        }

        if (strcmp(argv[1], "read") == 0 || strcmp(argv[1], "dump") == 0) {
            if (argc < 3) { uart_puts("Usage: gpio read <pin>\n"); return; }
            gpio_dump((unsigned)parse_dec(argv[2]));
        }
        else if (strcmp(argv[1], "set") == 0) {
            if (argc < 4) { uart_puts("Usage: gpio set <pin> <0|1>\n"); return; }
            unsigned pin = (unsigned)parse_dec(argv[2]);
            int value = (int)parse_dec(argv[3]);
            gpio_set(pin, value);
            uart_puts("gpio: pin "); uart_puts(utoa(pin));
            uart_puts(" -> "); uart_puts(utoa(value)); uart_puts("\n");
        }
        else if (strcmp(argv[1], "in") == 0) {
            if (argc < 3) { uart_puts("Usage: gpio in <pin>\n"); return; }
            unsigned pin = (unsigned)parse_dec(argv[2]);
            gpio_direction_input(pin);
            uart_puts("gpio: pin "); uart_puts(utoa(pin));
            uart_puts(" level "); uart_puts(utoa(gpio_get(pin))); uart_puts("\n");
        }
        else if (strcmp(argv[1], "out") == 0) {
            if (argc < 4) { uart_puts("Usage: gpio out <pin> <0|1>\n"); return; }
            unsigned pin = (unsigned)parse_dec(argv[2]);
            gpio_direction_output(pin, (int)parse_dec(argv[3]));
            uart_puts("gpio: pin "); uart_puts(utoa(pin));
            uart_puts(" output\n");
        }
        else if (strcmp(argv[1], "func") == 0) {
            if (argc < 4) { uart_puts("Usage: gpio func <pin> <0-3>\n"); return; }
            unsigned pin = (unsigned)parse_dec(argv[2]);
            unsigned func = (unsigned)parse_dec(argv[3]);
            gpio_set_func(pin, func);
            uart_puts("gpio: pin "); uart_puts(utoa(pin));
            uart_puts(" func "); uart_puts(utoa(func)); uart_puts("\n");
        }
        else if (strcmp(argv[1], "raw") == 0) {
            /* Full access to the configuration word: the escape hatch for
             * the fields the named helpers do not cover (pulls, drive
             * strength, the lock bit). */
            if (argc < 3) { uart_puts("Usage: gpio raw <pin> [hex]\n"); return; }
            unsigned pin = (unsigned)parse_dec(argv[2]);
            if (argc < 4) {
                uart_puts(utoa_hex(gpio_read_config(pin)));
                uart_puts("\n");
                return;
            }
            gpio_write_config(pin, (uint32_t)parse_hex(argv[3]));
            uart_puts("gpio: pin "); uart_puts(utoa(pin));
            uart_puts(" cfg=0x"); uart_puts(utoa_hex(gpio_read_config(pin)));
            uart_puts("\n");
        }
        else {
            uart_puts("Unknown gpio command\n");
        }
    }
    else if (strcmp(argv[0], "i2c") == 0) {
        if (argc < 2) { uart_puts("Usage: i2c <status|scan|read|write|wr|speed>\n"); return; }

        if (strcmp(argv[1], "status") == 0) {
            i2c_dump();
        }
        else if (strcmp(argv[1], "scan") == 0) {
            uint8_t found[112];
            int n = i2c_scan(found, (int)sizeof(found));
            if (n < 0) {
                uart_puts("i2c: scan failed, bus error\n");
                return;
            }
            uart_puts("i2c: "); uart_puts(utoa(n));
            uart_puts(n == 1 ? " device\n" : " devices\n");
            for (int i = 0; i < n && i < (int)sizeof(found); i++) {
                uart_puts("  0x"); uart_puts(utoa_hex(found[i])); uart_puts("\n");
            }
        }
        else if (strcmp(argv[1], "read") == 0) {
            if (argc < 4) { uart_puts("Usage: i2c read <addr7> [len]\n"); return; }
            uint8_t addr = (uint8_t)parse_hex(argv[2]);
            uint8_t buf[I2C_MAX_READ];
            int len = argc > 3 ? (int)parse_hex(argv[3]) : 1;
            if (len <= 0) len = 1;
            if (len > (int)sizeof(buf)) len = (int)sizeof(buf);
            int err = i2c_read(addr, buf, (uint16_t)len);
            if (err != 0) {
                uart_puts("i2c: read failed: ");
                uart_puts(i2c_strerror(err));
                uart_puts("\n");
                return;
            }
            print_bytes(buf, len);
            uart_puts("\n");
        }
        else if (strcmp(argv[1], "wr") == 0) {
            /* Write-then-read: the register read pattern, which needs a
             * repeated start rather than two independent transactions. */
            if (argc < 5) { uart_puts("Usage: i2c wr <addr7> <reg hex> <len>\n"); return; }
            uint8_t addr = (uint8_t)parse_hex(argv[2]);
            uint8_t tx[I2C_MAX_WRITE];
            int txn = parse_bytes(argv[3], tx, (int)sizeof(tx));
            if (txn == 0) { uart_puts("i2c: no register bytes\n"); return; }
            uint8_t rx[I2C_MAX_READ];
            int rxn = (int)parse_hex(argv[4]);
            if (rxn <= 0) rxn = 1;
            if (rxn > (int)sizeof(rx)) rxn = (int)sizeof(rx);
            int err = i2c_write_read(addr, tx, (uint16_t)txn, rx, (uint16_t)rxn);
            if (err != 0) {
                uart_puts("i2c: wr failed: ");
                uart_puts(i2c_strerror(err));
                uart_puts("\n");
                return;
            }
            print_bytes(rx, rxn);
            uart_puts("\n");
        }
        else if (strcmp(argv[1], "write") == 0) {
            if (argc < 4) { uart_puts("Usage: i2c write <addr7> <hex...>\n"); return; }
            uint8_t addr = (uint8_t)parse_hex(argv[2]);
            uint8_t buf[I2C_MAX_WRITE];
            int len = parse_bytes(argv[3], buf, (int)sizeof(buf));
            if (len == 0) { uart_puts("i2c: no bytes to write\n"); return; }
            int err = i2c_write(addr, buf, (uint16_t)len);
            if (err != 0) {
                uart_puts("i2c: write failed: ");
                uart_puts(i2c_strerror(err));
                uart_puts("\n");
                return;
            }
            uart_puts("i2c: wrote "); uart_puts(utoa(len));
            uart_puts(" bytes to 0x"); uart_puts(utoa_hex(addr)); uart_puts("\n");
        }
        else if (strcmp(argv[1], "speed") == 0) {
            if (argc < 3) { uart_puts("Usage: i2c speed <hz>\n"); return; }
            uint32_t hz = (uint32_t)parse_dec(argv[2]);
            if (i2c_set_speed(hz) != 0) {
                uart_puts("i2c: cannot represent ");
                uart_puts(utoa(hz));
                uart_puts("Hz from a ");
                uart_puts(utoa(i2c_ref_clk()));
                uart_puts("Hz reference\n");
                return;
            }
            uart_puts("i2c: "); uart_puts(utoa(i2c_speed()));
            uart_puts("Hz, divider "); uart_puts(utoa(i2c_divider()));
            uart_puts("\n");
        }
        else {
            uart_puts("Unknown i2c command\n");
        }
    }
    else if (strcmp(argv[0], "spi") == 0) {
        if (argc < 2) { uart_puts("Usage: spi <status|id|xfer|speed|cs>\n"); return; }

        if (strcmp(argv[1], "status") == 0) {
            spi_dump();
        }
        else if (strcmp(argv[1], "id") == 0) {
            uint8_t id[3];
            int err = spi_read_id(id);
            if (err != 0) {
                uart_puts("spi: id failed: ");
                uart_puts(spi_strerror(err));
                uart_puts("\n");
                return;
            }
            uart_puts("spi: id "); print_bytes(id, (int)sizeof(id));
            uart_puts("\n");
        }
        else if (strcmp(argv[1], "xfer") == 0) {
            if (argc < 3) { uart_puts("Usage: spi xfer <hex...>\n"); return; }
            /* Buffers sized for something a person types, not for the
             * controller's maximum: two SPI_MAX_WORDS buffers would eat
             * half the stack from an interactive shell. */
            uint8_t buf[256];
            int len = parse_bytes(argv[2], buf, (int)sizeof(buf));
            if (len == 0) { uart_puts("spi: no bytes to shift\n"); return; }
            uint8_t rx[256];
            int err = spi_xfer(buf, rx, (uint32_t)len);
            if (err != 0) {
                uart_puts("spi: xfer failed: ");
                uart_puts(spi_strerror(err));
                uart_puts("\n");
                return;
            }
            uart_puts("spi: tx "); print_bytes(buf, len); uart_puts("\n");
            uart_puts("spi: rx "); print_bytes(rx, len); uart_puts("\n");
        }
        else if (strcmp(argv[1], "speed") == 0) {
            if (argc < 3) { uart_puts("Usage: spi speed <hz>\n"); return; }
            (void)spi_set_speed((uint32_t)parse_dec(argv[2]));
            uart_puts("spi: "); uart_puts(utoa(spi_speed()));
            uart_puts("Hz, divider "); uart_puts(utoa(spi_divider()));
            uart_puts("\n");
        }
        else if (strcmp(argv[1], "cs") == 0) {
            if (argc < 3) { uart_puts("Usage: spi cs <0|1>\n"); return; }
            int level = (int)parse_dec(argv[2]);
            spi_cs(level);
            uart_puts("spi: cs "); uart_puts(utoa(level)); uart_puts("\n");
        }
        else {
            uart_puts("Unknown spi command\n");
        }
    }
    else if (strcmp(argv[0], "wdog") == 0) {
        if (argc < 2) { uart_puts("Usage: wdog <status|arm|kick|disarm>\n"); return; }

        if (strcmp(argv[1], "status") == 0) {
            watchdog_dump();
        }
        else if (strcmp(argv[1], "arm") == 0) {
            if (argc < 3) { uart_puts("Usage: wdog arm <seconds>\n"); return; }
            uint32_t sec = (uint32_t)parse_dec(argv[2]);
            watchdog_arm(sec);
            uart_puts("wdog: armed for "); uart_puts(utoa(sec));
            uart_puts("s; a missed kick resets the SoC\n");
        }
        else if (strcmp(argv[1], "kick") == 0) {
            watchdog_kick();
            uart_puts("wdog: kicked, ");
            uart_puts(utoa(watchdog_time_left_s()));
            uart_puts("s left\n");
        }
        else if (strcmp(argv[1], "disarm") == 0) {
            watchdog_disarm();
            uart_puts("wdog: disarmed\n");
        }
        else {
            uart_puts("Unknown wdog command\n");
        }
    }
    else if (strcmp(argv[0], "vfs") == 0) {
        if (argc < 2) {
            uart_puts("Usage: vfs <mount|unmount|ls|cat|load|modules|assets|prune>\n");
            return;
        }
        if (strcmp(argv[1], "mount") == 0) {
            if (argc < 5) { uart_puts("Usage: vfs mount <source> <target> <fstype> [flags]\n"); return; }
            uint32_t flags = argc >= 6 ? parse_hex(argv[5]) : 0;
            int ret = vfs_mount(argv[2], argv[3], argv[4], flags, NULL);
            if (ret == 0) uart_puts("vfs: mounted\n"); else uart_puts("vfs: mount failed\n");
        }
        else if (strcmp(argv[1], "unmount") == 0) {
            if (argc < 3) { uart_puts("Usage: vfs unmount <target>\n"); return; }
            int ret = vfs_unmount(argv[2]);
            if (ret == 0) uart_puts("vfs: unmounted\n"); else uart_puts("vfs: unmount failed\n");
        }
        else if (strcmp(argv[1], "ls") == 0) {
            const char *path = argc >= 3 ? argv[2] : "/";
            struct vfs_dir *dir;
            if (vfs_opendir(path, &dir) != 0) { uart_puts("vfs: opendir failed\n"); return; }
            struct vfs_dirent ent;
            while (vfs_readdir(dir, &ent) == 0) {
                if (!ent.d_name[0]) break;
                uart_puts(ent.d_name); uart_puts("\n");
            }
            vfs_closedir(dir);
        }
        else if (strcmp(argv[1], "cat") == 0) {
            if (argc < 3) { uart_puts("Usage: vfs cat <path>\n"); return; }
            struct vfs_file *file;
            if (vfs_open(argv[2], VFS_O_RDONLY, &file) != 0) { uart_puts("vfs: open failed\n"); return; }
            uint8_t buf[256];
            ssize_t n;
            while ((n = vfs_read(file, buf, sizeof(buf))) > 0) {
                for (int i = 0; i < n; i++) uart_putc(buf[i]);
            }
            vfs_close(file);
        }
        else if (strcmp(argv[1], "load") == 0) {
            if (argc < 3) { uart_puts("Usage: vfs load <path>\n"); return; }
            vfs_asset_t *asset = vfs_asset_load(argv[2], 0);
            if (asset) {
                uart_puts("vfs: loaded "); uart_puts(asset->path); uart_puts(" (");
                uart_puts(utoa(asset->size)); uart_puts(" bytes)\n");
            } else {
                uart_puts("vfs: load failed\n");
            }
        }
        else if (strcmp(argv[1], "modules") == 0) {
            uart_puts("Loaded modules:\n");
            for (uint32_t i = 0; i < 16; i++) {
                if (g_modules[i].handle) {
                    uart_puts("  "); uart_puts(g_modules[i].name);
                    uart_puts(" @ "); uart_puts(utoa_hex((uint64_t)g_modules[i].entry)); uart_puts("\n");
                }
            }
        }
        else if (strcmp(argv[1], "assets") == 0) {
            uart_puts("Loaded assets:\n");
            for (uint32_t i = 0; i < g_asset_count; i++) {
                if (g_assets[i].data) {
                    uart_puts("  "); uart_puts(g_assets[i].path);
                    uart_puts(" "); uart_puts(utoa(g_assets[i].size)); uart_puts(" bytes ref=");
                    uart_puts(utoa(g_assets[i].refcount)); uart_puts("\n");
                }
            }
            uart_puts("Cache size: "); uart_puts(utoa(g_asset_cache_size)); uart_puts(" bytes\n");
        }
        else if (strcmp(argv[1], "prune") == 0) {
            size_t max = argc >= 3 ? parse_hex(argv[2]) : 65536;
            vfs_asset_cache_prune(max);
            uart_puts("vfs: cache pruned to "); uart_puts(utoa(max)); uart_puts(" bytes\n");
        }
        else {
            uart_puts("Unknown vfs command\n");
        }
    }
    else if (strcmp(argv[0], "irq") == 0) {
        if (argc < 2) { uart_puts("Usage: irq <stat|list|map>\n"); return; }

        if (strcmp(argv[1], "stat") == 0) {
            uart_puts("irq: ");
            uart_puts(utoa(irq_total_count()));
            uart_puts(" handled, ");
            uart_puts(utoa(irq_unhandled_count()));
            uart_puts(" unclaimed\n");
        }
        else if (strcmp(argv[1], "list") == 0 || strcmp(argv[1], "dump") == 0) {
            aic_dump();
            for (unsigned int irq = 0; irq < AIC_MAX_IRQ; irq++) {
                irq_handler_t h = irq_lookup(irq);
                if (h == 0) continue;
                uart_puts("irq: line ");
                uart_puts(utoa(irq));
                uart_puts(" -> 0x");
                uart_puts(utoa_hex((uint64_t)(uintptr_t)h));
                uart_puts("\n");
            }
        }
        else if (strcmp(argv[1], "map") == 0) {
            /* Move a source onto another line at runtime. The only source
             * the payload wires is the DWC2 core, and its line number is
             * the one value in this bring-up that cannot be derived from
             * anything the build can read -- it comes from the device
             * tree. Correcting it from a shell beats a rebuild. */
            if (argc < 4) { uart_puts("Usage: irq map usb <line>\n"); return; }
            if (strcmp(argv[2], "usb") != 0) {
                uart_puts("irq: only 'usb' can be remapped in this build\n");
                return;
            }
            unsigned int line = (unsigned)parse_dec(argv[3]);
            irq_unregister(AIC_IRQ_USB_OTG);
            if (irq_register(line, usb_irq_handler) != 0) {
                uart_puts("irq: line ");
                uart_puts(utoa(line));
                uart_puts(" is already claimed\n");
                return;
            }
            uart_puts("irq: dwc2 now on line ");
            uart_puts(utoa(line));
            uart_puts("\n");
        }
        else {
            uart_puts("Unknown irq command\n");
        }
    }
    else if (strcmp(argv[0], "pmgr") == 0) {
        if (argc < 2) { uart_puts("Usage: pmgr <status|gate|ungate|reset>\n"); return; }

        if (strcmp(argv[1], "status") == 0) {
            uart_puts("pmgr: gate_status=0x");
            uart_puts(utoa_hex(pmgr_clock_state()));
            uart_puts(" (bit set == clock gated off)\n");
        }
        else if (strcmp(argv[1], "gate") == 0) {
            if (argc < 3) { uart_puts("Usage: pmgr gate <mask>\n"); return; }
            uint32_t mask = (uint32_t)parse_hex(argv[2]);
            pmgr_gate(mask);
            uart_puts("pmgr: gate_status=0x");
            uart_puts(utoa_hex(pmgr_clock_state()));
            uart_puts("\n");
        }
        else if (strcmp(argv[1], "ungate") == 0) {
            if (argc < 3) { uart_puts("Usage: pmgr ungate <mask>\n"); return; }
            uint32_t mask = (uint32_t)parse_hex(argv[2]);
            pmgr_ungate(mask);
            uart_puts("pmgr: gate_status=0x");
            uart_puts(utoa_hex(pmgr_clock_state()));
            uart_puts("\n");
        }
        else if (strcmp(argv[1], "reset") == 0) {
            /* Pulses exactly the bits named, unlike `reboot`. Asserting a
             * reset line is a device-specific action, so a blanket mask is
             * not what this command does. */
            if (argc < 3) { uart_puts("Usage: pmgr reset <mask>\n"); return; }
            uint32_t mask = (uint32_t)parse_hex(argv[2]);
            pmgr_reset_device(mask);
            uart_puts("pmgr: reset 0x");
            uart_puts(utoa_hex(mask));
            uart_puts(" pulsed\n");
        }
        else {
            uart_puts("Unknown pmgr command\n");
        }
    }
    else if (strcmp(argv[0], "tz") == 0) {
        tz_cmd(argv[0], argc >= 2 ? argv[1] : "");
    }
    else if (strcmp(argv[0], "aes") == 0) {
        if (argc < 2) {
            uart_puts("Usage: aes <cbc|ecb> <enc|dec> <128|192|256> <uid|gid0|gid1|iv+key> <data>\n");
            uart_puts("Example: aes cbc dec 256 uid <ciphertext>\n");
            uart_puts("Example: aes cbc dec 256 <iv+key_hex> <ciphertext>\n");
            return;
        }
        /* Forward to aes_cmd from aes_a9.c */
        extern void aes_cmd(const char *cmd, char *args);
        char args[256] = "";
        for (int i = 1; i < argc; i++) {
            if (i > 1) strcat(args, " ");
            strcat(args, argv[i]);
        }
        aes_cmd(argv[0], args);
    }
    else if (strcmp(argv[0], "recfg") == 0) {
        if (argc < 2) {
            uart_puts("Usage: recfg <dump|sync|lock>\n");
            return;
        }
        recfg_cmd(argv[0], argc >= 2 ? argv[1] : "");
    }
    else {
        uart_puts("Unknown command. Type 'help'\n");
    }
}

/* Stub functions for kernel patching/booting */
static void boot_ios_kernel(uint64_t kernel_base, uint64_t initrd_addr, uint64_t initrd_size) {
    (void)kernel_base; (void)initrd_addr; (void)initrd_size;
    uart_puts("boot_ios_kernel: not implemented - requires iBoot environment\n");
}

static void modload_module(const char *name) {
    (void)name;
    uart_puts("modload: not implemented - use goatloader for module loading\n");
}

static void autoboot_enable(uint64_t kernel_base) {
    (void)kernel_base;
    uart_puts("autoboot: not implemented\n");
}

static void autoboot_disable(void) {
    uart_puts("autoboot: not implemented\n");
}

static void autoboot_status(void) {
    uart_puts("autoboot: not implemented\n");
}

void shell_run(void) {
    uart_puts("\n=== A11 Research Payload v0.1 ===\n");
    uart_puts("Type 'help' for commands\n\n");
    uart_puts("\nresearch> ");

    int line_len = 0;
    static char line_buf[256];
    for (;;) {
        /* Service the stack before looking at the keyboard, not after. A
         * remote session has to be answered while this loop is otherwise
         * idle, and the two calls that do it are the same ones the bring-up
         * path uses: net_poll() delivers the frames the bulk-OUT path
         * buffered and services the socket timers, and goatloader_poll()
         * accepts connections and answers them. Neither blocks. */
        net_poll();
        goatloader_poll();

        int c = uart_getc();
        if (c < 0) continue;

        if (c == '\r' || c == '\n') {
            uart_putc('\n');
            line_buf[line_len] = 0;
            if (line_len > 0) {
                /* Command output mirrors into the on-screen pane while this
                 * runs; the echo above and the prompt below stay serial-only,
                 * so the menu never scrolls when a command is issued. */
                menu_exec_begin();
                execute(line_buf);
                menu_exec_end();
            }
            uart_puts("\nresearch> ");
            line_len = 0;
        }
        else if (c == 0x08 || c == 0x7F) {
            if (line_len > 0) {
                line_len--;
                line_buf[line_len] = 0;
                uart_puts("\b \b");
            }
        }
        else if (c >= 32 && c <= 126) {
            if (line_len < 255) {
                line_buf[line_len++] = c;
                uart_putc(c);
            }
        }
    }
}
