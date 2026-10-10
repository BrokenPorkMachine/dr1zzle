/* A11 (T8015) Recfg SoC-specific implementation.
 *
 * Based on pongoOS recfg_soc.c
 */

#include "recfg.h"
#include "recfg_soc.h"
#include "uart.h"
#include "mmio.h"
#include "memory_map.h"
#include "util.h"
#include "string.h"

#define RECFG_VOLATILE volatile

static bool recfg_supported(void)
{
    // A11 (T8015) supports recfg
    return true;
}

typedef struct {
    bool patchedIORVBAR;
    bool patchedAES;
} cb_arg_t;

static int recfg_soc_r32(void *a, uint64_t *addr, uint32_t *mask, uint32_t *data, bool *retry, uint8_t *recnt)
{
    (void)retry; (void)recnt;
    cb_arg_t *arg = a;
    uint64_t ad = *addr;
    uint32_t msk = *mask;

    // Patch AES read for A11
    if (arg->patchedAES && ad == 0x2352D0000ULL && (msk & 0x7) != 0) {
        uart_puts("Patching Recfg AES read\n");
        *data = (*data & ~0x7) | (mmio_read32(0x2352D0000ULL) & 0x7 & msk);
        return kRecfgUpdate;
    }
    return kRecfgSuccess;
}

static int recfg_soc_w32(void *a, uint64_t *addr, uint32_t *data)
{
    cb_arg_t *arg = a;
    uint64_t ad = *addr;
    if (ad == 0x2352D0000ULL) {
        uart_puts("Patching Recfg AES write\n");
        *data = mmio_read32(0x2352D0000ULL) & 0x7;
        arg->patchedAES = true;
        return kRecfgUpdate;
    }
    return kRecfgSuccess;
}

static int recfg_soc_r64(void *a, uint64_t *addr, uint64_t *mask, uint64_t *data, bool *retry, uint8_t *recnt)
{
    (void)retry; (void)recnt;
    cb_arg_t *arg = a;
    uint64_t ad = *addr;
    uint64_t msk = *mask;

    // IORVBAR addresses for A11
    static const uint64_t iorvbar_addrs[] = {
        0x208450000, 0x208550000, 0x208050000,
        0x208150000, 0x208250000, 0x208350000, 0
    };

    for (const uint64_t *ptr = iorvbar_addrs; *ptr != 0; ++ptr) {
        uint64_t iorvbar = *ptr;
        if (arg->patchedIORVBAR && ad == iorvbar && (msk & 0x0000FFFFFFFFFFFFULL) != 0) {
            uart_puts("Patching Recfg IORVBAR read\n");
            *data = (*data & ~0x0000FFFFFFFFFFFFULL) |
                    (mmio_read64(iorvbar) & 0x0000FFFFFFFFFFFFULL & msk);
            return kRecfgUpdate;
        }
    }
    return kRecfgSuccess;
}

static int recfg_soc_w64(void *a, uint64_t *addr, uint64_t *data)
{
    cb_arg_t *arg = a;
    uint64_t ad = *addr;

    static const uint64_t iorvbar_addrs[] = {
        0x208450000, 0x208550000, 0x208050000,
        0x208150000, 0x208250000, 0x208350000, 0
    };

    for (const uint64_t *ptr = iorvbar_addrs; *ptr != 0; ++ptr) {
        uint64_t iorvbar = *ptr;
        if (ad == iorvbar) {
            uart_puts("Patching Recfg IORVBAR write\n");
            *data = mmio_read64(iorvbar) & 0x0000FFFFFFFFFFFFULL;
            arg->patchedIORVBAR = true;
            return kRecfgUpdate;
        }
    }
    return kRecfgSuccess;
}

static bool recfg_locked = false;

static uint64_t recfg_map(uint64_t seq_base, uint64_t seq_size)
{
    // Map the SRAM region if not already mapped
    extern void map_range(uint64_t va, uint64_t pa, uint64_t size, int attr, int perm, bool uncache);
    if ((seq_base & ~0x3FFFULL) < 0x180200000ULL) {
        // Map uncached
        map_range(seq_base & ~0x3FFFULL, seq_base & ~0x3FFFULL, 0x10000, 2, 0, true);
        // Also adjust max size if we actually can
        uint64_t size = (seq_base & ~0x3FFFULL) + 0x10000 - seq_base;
        if (size < seq_size) {
            seq_size = size;
        }
    }
    return seq_size;
}

static void get_sram_bounds(uint64_t *sram_base, uint64_t *sram_end)
{
    // For A11, recfg is in SRAM at 0x235F00000 - 0x235F10000
    *sram_base = 0x235F00000ULL;
    *sram_end = 0x235F10000ULL;
}

void recfg_soc_sync(void)
{
    if (!recfg_supported()) {
        return;
    }
    if (recfg_locked) {
        return;
    }
    uart_puts("Patching Recfg sequence\n");

    uint64_t sram_base, sram_end;
    get_sram_bounds(&sram_base, &sram_end);

    // Recfg config table is at SRAM base + offset from aop_cfg_table
    // For A11, aop_cfg_table is at 0x2352C0200
    uint64_t cfg_base = 0x2352C0200ULL;
    volatile uint32_t *table = (volatile uint32_t*)cfg_base;

    cb_arg_t arg = {};
    recfg_cb_t cb = {
        .r32 = &recfg_soc_r32,
        .r64 = &recfg_soc_r64,
        .w32 = &recfg_soc_w32,
        .w64 = &recfg_soc_w64,
    };

    for (size_t i = 0; i < 8; ++i) {
        uint64_t seq_base = (uint64_t)table[i] << 4;
        size_t seq_size = sram_end - seq_base;
        seq_size = recfg_map(seq_base, seq_size);

        if (recfg_check((void*)seq_base, seq_size, NULL, false) == kRecfgSuccess) {
            arg.patchedIORVBAR = false;
            arg.patchedAES = false;
            int r = recfg_walk((void*)seq_base, seq_size, &cb, &arg);
            if (r != kRecfgSuccess && r != kRecfgUpdate) {
                uart_puts("recfg_walk returned error: ");
                uart_puts(utoa(r));
                uart_puts("\n");
            }
        }
    }
    __asm__ volatile("dsb sy");
    uart_puts("Recfg done\n");
}

void recfg_soc_lock(void)
{
    if (!recfg_supported()) {
        return;
    }
    if (recfg_locked) {
        return;
    }
    recfg_soc_sync();

    uint64_t sram_base, sram_end;
    get_sram_bounds(&sram_base, &sram_end);
    uint64_t lockdown_max = sram_base + 0x200000;
    if (sram_end < lockdown_max) {
        lockdown_max = sram_end;
    }
    uint64_t min = sram_base + 0x200; // aop_cfg_table offset
    uint64_t max = min + 0x20;
    volatile uint32_t *table = (volatile uint32_t*)min;
    uint64_t seq_max = max;

    for (size_t i = 0; i < 8; ++i) {
        uint64_t seq_base = (uint64_t)table[i] << 4;
        if (seq_base >= sram_base && seq_base <= lockdown_max) {
            if (seq_base < min) min = seq_base;
            if (seq_base > seq_max) seq_max = seq_base;
        }
    }
    if (seq_max > max) {
        size_t seq_size = lockdown_max - seq_max;
        size_t off = 0;
        if (recfg_check((void*)seq_max, seq_size, &off, false) != kRecfgSuccess) {
            off = 0;
        }
        max = seq_max + off + 4;
    }
    if (max % 0x40 == 0) max -= 0x40;

    // Write lock registers
    // aop_sram_lock_range at 0x235000200
    // aop_sram_lock_set at 0x235000204
    // aop_cfg_lock at 0x2352C0214
    uint32_t lock_val = ((((max - sram_base) >> 6) & 0x7FFF) << 16) | (((min - sram_base) >> 6) & 0x7FFF);
    mmio_write32(0x235000200ULL, lock_val);
    mmio_write32(0x235000204ULL, 1);
    mmio_write32(0x2352C0214ULL, 1);
    __asm__ volatile("dsb sy");
    uart_puts("Recfg locked\n");
    recfg_locked = true;
}

// Shell commands
static void recfg_cmd_help(const char *cmd, char *args);
static void recfg_cmd_dump(const char *cmd, char *args);
static void recfg_cmd_sync(const char *cmd, char *args);
static void recfg_cmd_lock(const char *cmd, char *args);

static void recfg_cmd_help(const char *cmd, char *args)
{
    (void)cmd; (void)args;
    uart_puts("recfg usage: recfg [subcommand]\nsubcommands:\n");
    uart_puts("  help  | show usage\n");
    uart_puts("  dump  | print recfg sequences\n");
    uart_puts("  sync  | flush MMIO changes to recfg sequences\n");
    uart_puts("  lock  | sync and lock recfg sequences\n");
}

static int recfg_end_cb(void *a)
{
    (void)a;
    uart_puts("    end\n");
    return kRecfgSuccess;
}

static int recfg_delay_cb(void *a, uint32_t *delay)
{
    (void)a;
    uart_puts("    delay ");
    uart_puts(utoa(*delay));
    uart_puts("\n");
    return kRecfgSuccess;
}

static int recfg_read32_cb(void *a, uint64_t *addr, uint32_t *mask, uint32_t *data, bool *retry, uint8_t *recnt)
{
    (void)a;
    uart_puts("    rd32 0x"); uart_puts(utoa_hex(*addr));
    uart_puts(" & 0x"); uart_puts(utoa_hex(*mask));
    uart_puts(" == 0x"); uart_puts(utoa_hex(*data));
    if (*retry) {
        uart_puts(", retry = "); uart_puts(utoa(*recnt));
    }
    uart_puts("\n");
    return kRecfgSuccess;
}

static int recfg_read64_cb(void *a, uint64_t *addr, uint64_t *mask, uint64_t *data, bool *retry, uint8_t *recnt)
{
    (void)a;
    uart_puts("    rd64 0x"); uart_puts(utoa_hex(*addr));
    uart_puts(" & 0x"); uart_puts(utoa_hex(*mask));
    uart_puts(" == 0x"); uart_puts(utoa_hex(*data));
    if (*retry) {
        uart_puts(", retry = "); uart_puts(utoa(*recnt));
    }
    uart_puts("\n");
    return kRecfgSuccess;
}

static int recfg_write32_cb(void *a, uint64_t *addr, uint32_t *data)
{
    (void)a;
    uart_puts("    wr32 0x"); uart_puts(utoa_hex(*addr));
    uart_puts(" = 0x"); uart_puts(utoa_hex(*data));
    uart_puts("\n");
    return kRecfgSuccess;
}

static int recfg_write64_cb(void *a, uint64_t *addr, uint64_t *data)
{
    (void)a;
    uart_puts("    wr64 0x"); uart_puts(utoa_hex(*addr));
    uart_puts(" = 0x"); uart_puts(utoa_hex(*data));
    uart_puts("\n");
    return kRecfgSuccess;
}

static void recfg_cmd_dump(const char *cmd, char *args)
{
    (void)cmd; (void)args;
    uint64_t sram_base, sram_end;
    get_sram_bounds(&sram_base, &sram_end);
    uint64_t cfg_base = 0x2352C0200ULL;
    volatile uint32_t *table = (volatile uint32_t*)cfg_base;
    bool sram_locked = mmio_read32(0x235000204ULL) != 0;
    bool cfg_locked = mmio_read32(0x2352C0214ULL) != 0;
    uint32_t lock_val = mmio_read32(0x235000200ULL);
    uint64_t lock_from = sram_base + ((lock_val & 0xFFFF) << 6);
    uint64_t lock_to = sram_base + (((lock_val >> 16) & 0xFFFF) << 6) + 0x40;

    uart_puts("CFG table: 0x"); uart_puts(utoa_hex(cfg_base));
    uart_puts(" ("); uart_puts(cfg_locked ? "locked" : "unlocked"); uart_puts(")\n");
    uart_puts("SRAM base: 0x"); uart_puts(utoa_hex(sram_base));
    uart_puts(" ("); uart_puts(sram_locked ? "locked" : "unlocked"); uart_puts(")\n");
    if (lock_to <= lock_from) {
        uart_puts("SRAM lock range: none ("); uart_puts(sram_locked ? "locked" : "unlocked"); uart_puts(")\n");
    } else {
        uart_puts("SRAM lock range: 0x"); uart_puts(utoa_hex(lock_from));
        uart_puts("-0x"); uart_puts(utoa_hex(lock_to));
        uart_puts(" ("); uart_puts(sram_locked ? "locked" : "unlocked"); uart_puts(")\n");
    }

    recfg_cb_t cb = {
        .end     = recfg_end_cb,
        .delay   = recfg_delay_cb,
        .r32     = recfg_read32_cb,
        .r64     = recfg_read64_cb,
        .w32     = recfg_write32_cb,
        .w64     = recfg_write64_cb,
    };

    for (size_t i = 0; i < 8; ++i) {
        uint64_t seq_base = (uint64_t)table[i] << 4;
        size_t seq_size = sram_end - seq_base;
        seq_size = recfg_map(seq_base, seq_size);
        uart_puts("Recfg seq "); uart_puts(utoa(i));
        uart_puts(": 0x"); uart_puts(utoa_hex(seq_base)); uart_puts("\n");

        if (recfg_check((void*)seq_base, seq_size, NULL, true) == kRecfgSuccess) {
            int r = recfg_walk((void*)seq_base, seq_size, &cb, NULL);
            if (r != kRecfgSuccess) {
                uart_puts("recfg_walk("); uart_puts(utoa(i));
                uart_puts(") returned: "); uart_puts(utoa(r)); uart_puts("\n");
            }
        }
    }
}

static void recfg_cmd_sync(const char *cmd, char *args)
{
    (void)cmd; (void)args;
    if (recfg_locked) {
        uart_puts("Sorry, recfg sequences are already locked.\n");
        return;
    }
    recfg_soc_sync();
}

static void recfg_cmd_lock(const char *cmd, char *args)
{
    (void)cmd; (void)args;
    if (recfg_locked) {
        uart_puts("Recfg sequences are already locked.\n");
        return;
    }
    recfg_soc_lock();
}

void recfg_cmd(const char *cmd, char *args)
{
    char *arguments = args;
    while (*arguments == ' ') arguments++;
    if (*arguments == '\0') {
        recfg_cmd_help(cmd, arguments);
        return;
    }
    // Skip the subcommand
    while (*arguments && *arguments != ' ') arguments++;
    while (*arguments == ' ') arguments++;

    if (strcmp(args, "dump") == 0) {
        recfg_cmd_dump(cmd, arguments);
    } else if (strcmp(args, "sync") == 0) {
        recfg_cmd_sync(cmd, arguments);
    } else if (strcmp(args, "lock") == 0) {
        recfg_cmd_lock(cmd, arguments);
    } else if (strcmp(args, "help") == 0) {
        recfg_cmd_help(cmd, arguments);
    } else {
        uart_puts("recfg: invalid command "); uart_puts(args); uart_puts("\n");
        recfg_cmd_help(cmd, arguments);
    }
}

void recfg_soc_setup(void)
{
    if (!recfg_supported()) {
        return;
    }
    /* The recfg commands are registered in shell.c's execute function and help text */
}