#include "uart.h"
#include "timer.h"
#include "shell.h"
#include "memory_map.h"
#include "util.h"
#include "string.h"
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

#define MAX_LINE 256

static uint64_t parse_hex(const char *s) {
    const char *p = s;
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) p += 2;
    uint64_t val = 0;
    while (*p) {
        char c = *p++;
        uint8_t v;
        if (c >= '0' && c <= '9') v = c - '0';
        else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
        else break;
        val = (val << 4) | v;
    }
    return val;
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
    
    if (strcmp(argv[0], "help") == 0) {
        uart_puts("Commands:\n");
        uart_puts("  memdump <addr> <len>        - Hex dump memory\n");
        uart_puts("  memwrite <addr> <hex>       - Write memory\n");
        uart_puts("  time                        - Show uptime\n");
        uart_puts("  reboot                      - Reboot to DFU\n");
        uart_puts("  dump-securerom              - Dump SecureROM (1MB)\n");
        uart_puts("  dump-sepos                  - Dump SEPOS via SEP mailbox\n");
        uart_puts("  dump-memory <start> <end>   - Dump memory range\n");
        uart_puts("  dump-dram                   - Dump DRAM\n");
        uart_puts("  dump-sram                   - Dump SRAM\n");
        uart_puts("  dump-baseband               - Dump baseband memory\n");
        uart_puts("  dump-nand [start] [end]     - Dump NAND range\n");
        uart_puts("  dump-apfs                   - Extract APFS files\n");
        uart_puts("  dump-iboot                  - Dump iBoot\n");
        uart_puts("  dump-sep                    - Dump SEP memory\n");
        uart_puts("  dump-gid                    - Dump GID key\n");
        uart_puts("  dump-uid                    - Dump UID key\n");
        uart_puts("  dump-gid-uid                - Dump both GID/UID\n");
        uart_puts("  aes <encrypt|decrypt> <data> - AES test\n");
        uart_puts("  keybag <img4_file>          - Decrypt KBAG\n");
        uart_puts("  ace2 init                   - Initialize ACE2/ACE3\n");
        uart_puts("  ace2 dump                   - Dump ACE2 registers\n");
        uart_puts("  ace2 port <n> <reset|enable|status> - ACE2 port control\n");
        uart_puts("  sepos <ping|random|boot_tz0|status|memdump> - SEP commands\n");
        uart_puts("  wifi init|scan|status       - WiFi commands\n");
        uart_puts("  patch-kernel <addr> <orig> <new> - Patch kernel RAM\n");
        uart_puts("  panic                       - Parse panic log\n");
        uart_puts("  time                        - Show uptime\n");
        uart_puts("  reboot                      - Reboot to DFU\n");
        uart_puts("  help                        - This list\n");
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
        int len = 0;
        
        const char *p = argv[2];
        if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) p += 2;
        while (*p && len < 64) {
            uint8_t hi = 0, lo = 0;
            if (p[0] >= '0' && p[0] <= '9') hi = p[0] - '0';
            else if (p[0] >= 'a' && p[0] <= 'f') hi = p[0] - 'a' + 10;
            else if (p[0] >= 'A' && p[0] <= 'F') hi = p[0] - 'A' + 10;
            else break;
            p++;
            if (!*p) break;
            if (p[0] >= '0' && p[0] <= '9') lo = p[0] - '0';
            else if (p[0] >= 'a' && p[0] <= 'f') lo = p[0] - 'a' + 10;
            else if (p[0] >= 'A' && p[0] <= 'F') lo = p[0] - 'A' + 10;
            else break;
            p++;
            bytes[len++] = (hi << 4) | lo;
        }
        
        for (int i = 0; i < len; i++) {
            *(volatile uint8_t *)(addr + i) = bytes[i];
        }
        uart_puts("Wrote "); uart_puts(utoa(len)); uart_puts(" bytes to "); uart_puts(utoa_hex(addr)); uart_puts("\n");
    }
    else if (strcmp(argv[0], "time") == 0) {
        uart_puts("Uptime: "); uart_puts(utoa(timer_now_ms())); uart_puts(" ms\n");
    }
    else if (strcmp(argv[0], "reboot") == 0) {
        uart_puts("Rebooting to DFU...\n");
        reboot();
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
            /* Parse ciphertext hex */
            aes_decrypt_gid(ciphertext, plaintext, iv);
            uart_puts("Decrypted: "); uart_puts(utoa_hex(*(uint64_t *)plaintext)); uart_puts("\n");
        } else if (strcmp(argv[1], "encrypt") == 0) {
            aes_test();
        } else {
            aes_test();
        }
    }
    else if (strcmp(argv[0], "keybag") == 0) {
        if (argc < 2) { uart_puts("Usage: keybag <img4_data_hex>\n"); return; }
        decrypt_keybag((const uint8_t *)argv[1], strlen(argv[1]));
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
        if (argc < 2) { uart_puts("Usage: wifi <init|scan|status>\n"); return; }
        if (strcmp(argv[1], "init") == 0) wifi_init();
        else if (strcmp(argv[1], "scan") == 0) wifi_scan();
        else if (strcmp(argv[1], "status") == 0) wifi_status();
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
        parse_panic_log();
    }
    else {
        uart_puts("Unknown command. Type 'help'\n");
    }
}

void shell_run(void) {
    uart_puts("\n=== A11 Research Payload v0.1 ===\n");
    uart_puts("Type 'help' for commands\n\n");
    uart_puts("\nresearch> ");
    
    int line_len = 0;
    static char line_buf[256];
    while (1) {
        int c = uart_getc();
        if (c < 0) continue;
        
        if (c == '\r' || c == '\n') {
            uart_putc('\n');
            line_buf[line_len] = 0;
            if (line_len > 0) {
                execute(line_buf);
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
