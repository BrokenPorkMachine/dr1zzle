/* Memory and firmware dump engine.
 *
 * ---------------------------------------------------------------------------
 * What "dump" means here
 * ---------------------------------------------------------------------------
 *
 * With the MMU off and a 1:1 identity mapping, this CPU can read anything the
 * SoC lets it read: SRAM, the SecureROM window at 0x100000000, DRAM, and the
 * device register windows in memory_map.h. The engine in this file is that
 * read path plus formatting, and nothing else. It reads 16 bytes per row,
 * groups them into a caller-chosen element width, and can collapse runs of
 * identical rows so a megabyte of padding does not print a megabyte.
 *
 * The interesting targets are NOT in that set. NAND flash contents, SEP
 * processor memory, GID/UID key material and keybags all sit behind either a
 * driver whose register map has not been checked against silicon or a key the
 * user has to supply. Those are listed as named targets with a status, so the
 * menu tells the truth about what a given command will do instead of printing
 * whatever an unimplemented stub prints.
 *
 * Reads are never issued for NO_DRIVER targets: a read from an unpowered
 * window on this SoC is not guaranteed to return garbage, it can hang. The
 * one exception is the NAND controller window itself, which is a real MMIO
 * window in the map and is dumped as such.
 */

#include "dump.h"
#include "memory_map.h"
#include "uart.h"
#include "util.h"
#include "string.h"
#include "goat/sha256.h"
#include "goat/util.h"

/* DRAM geometry. The kernel image base of 0x800000000 is the A11 load address
 * the firmware uses; the 1GB extent is the part of the DRAM map this payload
 * can address, not the fitted RAM. Both are marked UNVERIFIED for that
 * reason. */
#define DRAM_BASE   0x800000000ULL
#define DRAM_SIZE   0x80000000ULL

/* iBoot and the kernelcache are loaded into DRAM by the boot chain. Their
 * addresses are where the published A11 boot flow puts them, not where this
 * payload has confirmed them. */
#define IBOOT_BASE     0x800000000ULL
#define IBOOT_SIZE     0x400000ULL
#define IBOOT_LLB_SIZE 0x80000ULL
#define KCACHE_SIZE    0x2000000ULL

/* How much of a read range to checksum while dumping, in bytes. */
#define DUMP_CHUNK 4096

static const dump_target_t targets[] = {
    /* --- dumped by this engine, today ---------------------------------- */
    { "sram", "payload SRAM: image, bss, heap, stack", 0,
      SRAM_BASE, SRAM_SIZE, DUMP_READY },
    { "securerom", "SecureROM image window", 0,
      SECURE_ROM_BASE, SECURE_ROM_SIZE, DUMP_READY },
    { "nandregs", "NAND controller register window", 0,
      NAND_BASE, 0x1000, DUMP_READY },
    { "pmgr", "PMGR clock/reset register window", 0,
      PMGR_BASE, 0x1000, DUMP_READY },
    { "dwc2", "DWC2 USB core register window", 0,
      USB_BASE, 0x1000, DUMP_READY },
    { "aic", "interrupt controller register window", 0,
      AIC_BASE, 0x1000, DUMP_READY },
    { "ace2", "ACE2 register window", 0,
      ACE2_BASE, 0x1000, DUMP_READY },
    { "mailbox", "SEP mailbox register window", 0,
      MAILBOX_BASE, 0x1000, DUMP_READY },
    { "nor", "NOR controller register window", 0,
      NOR_BASE, 0x1000, DUMP_READY },

    /* --- readable, but the geometry is a published guess ---------------- */
    { "dram", "DRAM from the kernel image base", 0,
      DRAM_BASE, DRAM_SIZE, DUMP_UNVERIFIED },
    { "iboot", "iBoot image in DRAM", 0,
      IBOOT_BASE, IBOOT_SIZE, DUMP_UNVERIFIED },
    { "llb", "low-level bootloader at the iBoot base", 0,
      IBOOT_BASE, IBOOT_LLB_SIZE, DUMP_UNVERIFIED },
    { "kernelcache", "kernelcache image in DRAM", 0,
      DRAM_BASE, KCACHE_SIZE, DUMP_UNVERIFIED },

    /* --- exposed, but not implementable until something exists ---------- */
    { "nand", "NAND flash contents (all blocks)", "verified NAND command interface",
      0, 0, DUMP_NO_DRIVER },
    { "nandbad", "bad-block table scan", "verified NAND command interface",
      0, 0, DUMP_NO_DRIVER },
    { "apfs", "APFS container/volume/file extraction", "NAND read plus APFS parser",
      0, 0, DUMP_NO_DRIVER },
    { "sep", "SEP processor memory", "SEP mailbox dump protocol",
      0, 0, DUMP_NO_DRIVER },
    { "sepos", "SEP processor memory (SEPOS)", "SEP mailbox dump protocol",
      0, 0, DUMP_NO_DRIVER },
    { "norflash", "NOR flash contents", "verified NOR/SPI read command interface",
      0, 0, DUMP_NO_DRIVER },
    { "baseband", "baseband memory image", "baseband attach and address map",
      0, 0, DUMP_NO_DRIVER },
    { "panic", "kernel panic log block", "panic log address in DRAM",
      0, 0, DUMP_NO_DRIVER },
    { "gid", "GID key material", "AES/GID access path verified on silicon",
      0, 0, DUMP_NO_DRIVER },
    { "uid", "UID key material", "AES/GID access path verified on silicon",
      0, 0, DUMP_NO_DRIVER },
    { "keybag", "IMG4 keybag (KBAG) decrypt", "AES engine plus GID key",
      0, 0, DUMP_NO_DRIVER },
    { "img4", "IMG4 payload extraction", "IMG4 parser plus NAND read",
      0, 0, DUMP_NO_DRIVER },
};

#define TARGET_COUNT (sizeof(targets) / sizeof(targets[0]))

const dump_target_t *dump_targets(unsigned *count) {
    if (count) *count = (unsigned)TARGET_COUNT;
    return targets;
}

const dump_target_t *dump_target_find(const char *name) {
    if (!name) return 0;
    for (unsigned i = 0; i < TARGET_COUNT; i++) {
        if (strcmp(targets[i].name, name) == 0) return &targets[i];
    }
    return 0;
}

void dump_targets_list(void) {
    uart_puts("dump targets:\n");
    for (unsigned i = 0; i < TARGET_COUNT; i++) {
        const dump_target_t *t = &targets[i];
        uart_puts("  ");
        uart_puts(t->name);
        /* Column-align the descriptions. */
        int pad = 14 - (int)strlen(t->name);
        while (pad-- > 0) uart_putc(' ');

        if (t->status == DUMP_NO_DRIVER) {
            uart_puts("needs-driver  (");
            uart_puts(t->depends ? t->depends : "unimplemented");
            uart_puts(")\n");
            continue;
        }

        uart_puts(t->status == DUMP_READY ? "ready       " : "unverified  ");
        uart_puts("0x");
        uart_puts(utoa_hex(t->base));
        uart_puts(" len=0x");
        uart_puts(utoa_hex(t->length));
        uart_puts("  ");
        uart_puts(t->desc);
        uart_puts("\n");
    }
}

/* --- engine -------------------------------------------------------------- */

static void print_ascii(uint8_t c) {
    uart_putc((c >= 32 && c <= 126) ? (char)c : '.');
}

/* One 16-byte row. `width` groups the row into elements of 1, 2, 4 or 8
 * bytes so a word-oriented register window reads like words. */
static void dump_row(uint64_t addr, const uint8_t *p, uint32_t width,
                     int ascii) {
    uart_puts("0x");
    uart_puts(utoa_hex(addr));
    uart_puts(":");

    char sep = ' ';
    for (uint32_t off = 0; off < 16; off += width) {
        for (uint32_t b = width; b-- > 0;) {
            uint8_t byte = p[off + b];
            const char *digits = "0123456789abcdef";
            uart_putc(digits[(byte >> 4) & 0xF]);
            uart_putc(digits[byte & 0xF]);
        }
        uart_putc(sep);
    }

    if (ascii) {
        uart_puts(" |");
        for (uint32_t i = 0; i < 16; i++) print_ascii(p[i]);
        uart_puts("|");
    }
    uart_putc('\n');
}

void dump_run(uint64_t addr, uint64_t length, const dump_opts_t *opts) {
    dump_opts_t d;
    d.width  = opts ? opts->width : 4;
    d.ascii  = opts ? opts->ascii : 1;
    d.sparse = opts ? opts->sparse : 1;

    if (d.width != 1 && d.width != 2 && d.width != 4 && d.width != 8) d.width = 4;

    if (length == 0) {
        uart_puts("dump: length is zero\n");
        return;
    }
    if (length > DUMP_MAX_LENGTH) {
        uart_puts("dump: clamping ");
        uart_puts(utoa_hex(length));
        uart_puts(" to 0x");
        uart_puts(utoa_hex(DUMP_MAX_LENGTH));
        uart_puts(" per command; use the target's length or repeat\n");
        length = DUMP_MAX_LENGTH;
    }

    uart_puts("dump 0x");
    uart_puts(utoa_hex(addr));
    uart_puts(" len=0x");
    uart_puts(utoa_hex(length));
    uart_puts(" width=");
    uart_puts(utoa(d.width));
    uart_puts("\n");

    /* A wrap in the end address means the range runs off the top of the
     * address space; there is no partial second pass worth attempting. */
    if (addr + length < addr) {
        uart_puts("dump: range wraps the address space\n");
        return;
    }

    uint8_t prev[16];
    int have_prev = 0;
    int collapsing = 0;
    uint64_t done = 0;

    for (uint64_t off = 0; off < length; off += 16) {
        const uint8_t *p = (const uint8_t *)(uintptr_t)(addr + off);
        uint32_t row = (uint32_t)((length - off) < 16 ? (length - off) : 16);

        if (row < 16) {
            uint8_t tail[16];
            for (uint32_t i = 0; i < 16; i++) tail[i] = (i < row) ? p[i] : 0;
            dump_row(addr + off, tail, d.width, d.ascii);
        } else if (d.sparse && have_prev && memcmp(prev, p, 16) == 0) {
            if (!collapsing) {
                uart_puts("*\n");
                collapsing = 1;
            }
        } else {
            memcpy(prev, p, 16);
            have_prev = 1;
            collapsing = 0;
            dump_row(addr + off, p, d.width, d.ascii);
        }

        done += row;

        /* Progress lines every 4 KiB of input. Without them a 1 MiB dump over
         * 115200 baud looks hung for the better part of two minutes. */
        if ((done % DUMP_CHUNK) + row >= DUMP_CHUNK && done < length) {
            uart_puts("... 0x");
            uart_puts(utoa_hex(done));
            uart_puts("/0x");
            uart_puts(utoa_hex(length));
            uart_puts(" bytes\n");
        }
    }

    uart_puts("dump: 0x");
    uart_puts(utoa_hex(done));
    uart_puts(" bytes from 0x");
    uart_puts(utoa_hex(addr));
    uart_puts("\n");
}

void dump_digest(uint64_t addr, uint64_t length) {
    if (length > DUMP_MAX_LENGTH) length = DUMP_MAX_LENGTH;
    if (length == 0) {
        uart_puts("digest: length is zero\n");
        return;
    }

    goat_sha256_ctx ctx;
    goat_sha256_init(&ctx);

    /* The range is fed straight from physical memory; the streaming digest
     * makes arbitrary lengths a non-event, so no staging buffer is needed. */
    const uint8_t *p = (const uint8_t *)(uintptr_t)addr;
    goat_sha256_update(&ctx, p, (size_t)length);

    uint8_t digest[GOAT_SHA256_DIGEST_SIZE];
    goat_sha256_final(&ctx, digest);

    char hex[GOAT_SHA256_DIGEST_SIZE * 2 + 1];
    goat_hex(digest, sizeof(digest), 0, hex, sizeof(hex));

    uart_puts("sha256(0x");
    uart_puts(utoa_hex(addr));
    uart_puts(" + 0x");
    uart_puts(utoa_hex(length));
    uart_puts(") = ");
    uart_puts(hex);
    uart_puts("\n");
}

int dump_find(uint64_t addr, uint64_t length, const uint8_t *pattern,
              uint32_t pattern_len) {
    if (length > DUMP_MAX_LENGTH) length = DUMP_MAX_LENGTH;
    if (pattern_len == 0 || pattern_len > 64) {
        uart_puts("find: pattern must be 1..64 bytes\n");
        return -1;
    }

    int hits = 0;
    for (uint64_t off = 0; off + pattern_len <= length; off++) {
        const uint8_t *p = (const uint8_t *)(uintptr_t)(addr + off);
        if (memcmp(p, pattern, pattern_len) == 0) {
            uart_puts("found at 0x");
            uart_puts(utoa_hex(addr + off));
            uart_puts("\n");
            if (++hits >= 64) {
                uart_puts("find: 64 hits, stopping\n");
                return hits;
            }
        }
    }
    if (hits == 0) uart_puts("find: no hits\n");
    return hits;
}
