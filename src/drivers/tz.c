/* TrustZone driver for A11 (T8015).
 *
 * Based on pongoOS tz.c
 */

#include "tz.h"
#include "uart.h"
#include "mmio.h"
#include "memory_map.h"
#include "string.h"
#include "util.h"
#include <stdbool.h>

static volatile uint32_t *gTZRegbase;

void tz_setup(void)
{
    /* TZ0/TZ1 registers are at IOBASE + 0x480 for non-A7 SoCs */
    gTZRegbase = (volatile uint32_t*)(IO_BASE + 0x480);
}

void tz_lockdown(void)
{
    bool have_tz0 = gTZRegbase[0] != 0;
    bool have_tz1 = gTZRegbase[2] != 0;

    if (have_tz0) gTZRegbase[4] = 1;
    if (have_tz1) gTZRegbase[5] = 1;

    uart_puts("tz: lockdown ");
    uart_puts(have_tz0 ? "TZ0 " : "");
    uart_puts(have_tz1 ? "TZ1 " : "");
    uart_puts("\n");
}

bool tz_blackbird(void)
{
    if (gTZRegbase[4]) {
        uart_puts("tz: registers are locked\n");
        return false;
    }
    /* Enable blackbird bit (bit 20) */
    gTZRegbase[0] |= 0x100000;
    uart_puts("tz: blackbird enabled\n");
    return true;
}

void tz0_set(uint64_t base, uint64_t end)
{
    if (gTZRegbase[4]) {
        uart_puts("tz: registers are locked\n");
        return;
    }

    /* Shift right by 12 bits for register values */
    gTZRegbase[0] = (uint32_t)(base >> 12);
    gTZRegbase[1] = (uint32_t)(end >> 12);

    uart_puts("tz: TZ0 set base=0x"); uart_puts(utoa_hex(base));
    uart_puts(" end=0x"); uart_puts(utoa_hex(end)); uart_puts("\n");
}

void *tz0_calculate_encrypted_block_addr(uint64_t offset)
{
    uint64_t offset_block = (offset & ~0x1FULL);
    offset_block <<= 1; /* * 2 */
    return (void*)(0xC00000000ULL + offset_block);
}

bool tz0_is_locked(void)
{
    return gTZRegbase[4] != 0;
}

uint64_t tz0_base(void)
{
    return ((uint64_t)gTZRegbase[0] << 12) + 0x800000000ULL;
}

uint64_t tz0_size(void)
{
    return (uint64_t)(gTZRegbase[1] - gTZRegbase[0] + 1) << 12;
}

/* Shell command handlers */
static void tz_command(const char *cmd, char *args)
{
    (void)cmd; (void)args;
    uint32_t raw[4];
    uint32_t shift = 12;

    raw[0] = gTZRegbase[0];
    raw[1] = gTZRegbase[1];
    raw[2] = gTZRegbase[2];
    raw[3] = gTZRegbase[3];

    uint64_t real[4];
    real[0] = ((uint64_t)raw[0] << shift) + 0x800000000ULL;
    real[1] = (((uint64_t)raw[1] + 1) << shift) + 0x800000000ULL;
    real[2] = ((uint64_t)raw[2] << shift) + 0x800000000ULL;
    real[3] = (((uint64_t)raw[3] + 1) << shift) + 0x800000000ULL;

    uart_puts("TZ0 (");
    uart_puts(gTZRegbase[4] ? "locked" : "unlocked");
    uart_puts("):\n");
    uart_puts("    base: "); uart_puts(utoa_hex(raw[0])); uart_puts(" ("); uart_puts(utoa_hex(real[0])); uart_puts(")\n");
    uart_puts("    end:  "); uart_puts(utoa_hex(raw[1])); uart_puts(" ("); uart_puts(utoa_hex(real[1])); uart_puts(")\n\n");

    uart_puts("TZ1 (");
    uart_puts(gTZRegbase[5] ? "locked" : "unlocked");
    uart_puts("):\n");
    uart_puts("    base: "); uart_puts(utoa_hex(raw[2])); uart_puts(" ("); uart_puts(utoa_hex(real[2])); uart_puts(")\n");
    uart_puts("    end:  "); uart_puts(utoa_hex(raw[3])); uart_puts(" ("); uart_puts(utoa_hex(real[3])); uart_puts(")\n\n");
}

static void tz0_set_cmd(const char *cmd, char *args)
{
    (void)cmd;
    if (!*args) {
        uart_puts("tz0_set usage: tz0_set [base] [end]\n");
        return;
    }
    char *arg1 = args;
    while (*arg1 && *arg1 != ' ') arg1++;
    if (*arg1) *arg1++ = 0;
    while (*arg1 == ' ') arg1++;
    if (!*arg1) {
        uart_puts("tz0_set usage: tz0_set [base] [end]\n");
        return;
    }

    uint64_t base = parse_hex(args);
    uint64_t end = parse_hex(arg1);
    tz0_set(base, end);
}

static void tz_lockdown_cmd(const char *cmd, char *args)
{
    (void)cmd; (void)args;
    tz_lockdown();
}

static void tz_blackbird_cmd(const char *cmd, char *args)
{
    (void)cmd; (void)args;
    if (tz_blackbird()) {
        uart_puts("tz: blackbird enabled\n");
    }
}

void tz_cmd(const char *cmd, char *args)
{
    char *arguments = args;
    while (*arguments == ' ') arguments++;
    if (!*arguments) {
        uart_puts("tz usage: tz [info|lockdown|blackbird|tz0_set]\n");
        return;
    }

    char *subcmd = arguments;
    while (*arguments && *arguments != ' ') arguments++;
    if (*arguments) *arguments++ = 0;
    while (*arguments == ' ') arguments++;

    if (strcmp(subcmd, "info") == 0) {
        tz_command(cmd, arguments);
    } else if (strcmp(subcmd, "lockdown") == 0) {
        tz_lockdown_cmd(cmd, arguments);
    } else if (strcmp(subcmd, "blackbird") == 0) {
        tz_blackbird_cmd(cmd, arguments);
    } else if (strcmp(subcmd, "tz0_set") == 0) {
        tz0_set_cmd(cmd, arguments);
    } else {
        uart_puts("tz: unknown subcommand "); uart_puts(subcmd); uart_puts("\n");
        uart_puts("tz usage: tz [info|lockdown|blackbird|tz0_set]\n");
    }
}