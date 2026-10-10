/* Firmware store: the NAND-resident half of the multi-stage loader.
 *
 * The core bootstrap carries no feature code. A firmware (the full monitor,
 * a dumping build, a diagnostics build) lives in a fixed NAND slot and is
 * copied to its load address the moment the operator picks it. This file owns
 * the slot layout and the copy; the menu in core_main.c owns the choice.
 *
 * It is deliberately the only place that knows how a firmware is laid out on
 * NAND, so the on-NAND format and the goat container format can stay one
 * definition (firmware_header_t) rather than two that drift.
 */

#include "firmware.h"
#include "fw_store.h"
#include "nand.h"
#include "memory_map.h"
#include "string.h"
#include "uart.h"
#include "util.h"
#include "goat/goat.h"
#include "goat/loader.h"

#define FW_SLOT_CACHE   FW_SLOT_COUNT

typedef struct {
    firmware_header_t hdr;
    int present;
} fw_slot_t;

static fw_slot_t slots[FW_SLOT_CACHE];
static uint8_t oob_scratch[NAND_MAX_OOB_BYTES];
/* One page of staging for the writer. A NAND page can be 16 KB, so this lives
 * in .bss rather than on the deliberately small core stack. */
static uint8_t page_scratch[NAND_MAX_PAGE_BYTES];

/* --- CRC32 (IEEE 802.3, reflected) -------------------------------------- */

uint32_t fw_crc32(const void *data, uint32_t len) {
    const uint8_t *p = (const uint8_t *)data;
    uint32_t crc = 0xFFFFFFFFu;

    for (uint32_t i = 0; i < len; i++) {
        crc ^= p[i];
        for (int b = 0; b < 8; b++) {
            crc = (crc >> 1) ^ (0xEDB88320u & (uint32_t)(-(int32_t)(crc & 1u)));
        }
    }
    return ~crc;
}

/* --- slot geometry ------------------------------------------------------ */

static uint32_t pages_per_block(void) {
    const nand_info_t *n = nand_info();
    return n ? n->geometry.pages_per_block : NAND_DEFAULT_PAGES_BLOCK;
}

/* Global page number of slot `slot`'s first page. */
static uint32_t slot_first_page(unsigned slot) {
    uint32_t ppb = pages_per_block();
    return FW_STORE_BLOCK * ppb + slot * FW_SLOT_BLOCKS * ppb;
}

/* Read the first page of a slot into the staging window and hand back the
 * header, if one is there. Read to FW_LOAD_BASE rather than the stack: a NAND
 * page can be 16 KB and the core's stack is deliberately small. */
static int read_slot_header(unsigned slot, firmware_header_t *out) {
    const nand_info_t *n = nand_info();
    uint32_t page_size, ppb, first, block, page;

    if (!n || !n->initialized) return -1;
    page_size = n->geometry.page_size;
    ppb = n->geometry.pages_per_block;
    if (page_size < sizeof(firmware_header_t)) return -1;

    first = slot_first_page(slot);
    block = first / ppb;
    page = first % ppb;

    if (nand_read_page(block, page, (uint8_t *)(uintptr_t)FW_LOAD_BASE,
                       oob_scratch) != 0) {
        return -1;
    }
    memcpy(out, (const void *)(uintptr_t)FW_LOAD_BASE, sizeof *out);
    return 0;
}

static int header_ok(const firmware_header_t *h) {
    if (h->magic != FW_MAGIC) return 0;
    if (h->version != FW_VERSION) return 0;
    if (h->size == 0 || h->size > FW_MAX_SIZE) return 0;
    if (h->load_base < FW_SRAM_BASE || h->load_base > FW_SRAM_END) return 0;
    if (h->load_base + h->size > FW_SRAM_END) return 0;
    if (h->entry_off >= h->size) return 0;
    return 1;
}

void fw_store_scan(void) {
    const nand_info_t *n = nand_info();

    memset(slots, 0, sizeof slots);
    if (!n || !n->initialized) return;

    for (unsigned s = 0; s < FW_SLOT_CACHE; s++) {
        firmware_header_t h;
        if (read_slot_header(s, &h) == 0 && header_ok(&h)) {
            slots[s].hdr = h;
            slots[s].present = 1;
        }
    }
}

int fw_store_count(void) {
    int n = 0;
    for (unsigned s = 0; s < FW_SLOT_CACHE; s++) if (slots[s].present) n++;
    return n;
}

const firmware_header_t *fw_store_slot(unsigned slot) {
    if (slot >= FW_SLOT_CACHE || !slots[slot].present) return 0;
    return &slots[slot].hdr;
}

/* --- loading ------------------------------------------------------------ */

/* The header's name field is 16 bytes and NUL-padded, but a record written by
 * a tool that filled all 16 bytes has no terminator. Printing it with uart_puts
 * would read on into the image; this stops at the field. */
static void print_name(const char *name) {
    for (uint32_t i = 0; i < 16u && name[i]; i++) uart_putc(name[i]);
}

/* Read `size` bytes starting at the slot's first page into `dst`, dropping
 * each page's OOB. `size` is rounded up to a whole page. */
static int read_slot_image(unsigned slot, uint8_t *dst, uint32_t size) {
    const nand_info_t *n = nand_info();
    uint32_t page_size, ppb, gp, pages, done = 0;

    if (!n || !n->initialized) return -1;
    page_size = n->geometry.page_size;
    ppb = n->geometry.pages_per_block;
    gp = slot_first_page(slot);
    pages = (size + page_size - 1) / page_size;

    for (uint32_t i = 0; i < pages; i++) {
        uint32_t block = (gp + i) / ppb;
        uint32_t page = (gp + i) % ppb;
        uint32_t take = size - done;
        if (take > page_size) take = page_size;
        if (nand_read_page(block, page, dst + done, oob_scratch) != 0) return -1;
        done += take;
        if (done >= size) break;
    }
    return 0;
}

void fw_run_slot(unsigned slot) {
    const firmware_header_t *h = fw_store_slot(slot);
    uint8_t *image;
    uint64_t entry;

    if (!h) {
        uart_puts("fw: no firmware in slot\r\n");
        return;
    }

    /* The header sits at the front of the image on NAND; read the whole
     * record into the staging window and keep the image that follows. */
    if (read_slot_image(slot, (uint8_t *)(uintptr_t)FW_LOAD_BASE,
                        (uint32_t)sizeof(firmware_header_t) + h->size) != 0) {
        uart_puts("fw: NAND read failed\r\n");
        return;
    }

    image = (uint8_t *)(uintptr_t)FW_LOAD_BASE + sizeof(firmware_header_t);
    if (fw_crc32(image, h->size) != h->crc32) {
        uart_puts("fw: CRC mismatch, refusing to run\r\n");
        return;
    }

    if (h->load_base != FW_LOAD_BASE) {
        memmove((void *)(uintptr_t)h->load_base, image, h->size);
    } else {
        memmove((void *)(uintptr_t)FW_LOAD_BASE, image, h->size);
    }

    entry = (uint64_t)h->load_base + h->entry_off;
    uart_puts("fw: entering ");
    print_name(h->name);
    uart_puts(" at 0x");
    uart_puts(utoa_hex(entry));
    uart_puts("\r\n");
    goat_enter(entry);
}

/* --- writing ------------------------------------------------------------ */

int fw_store_erase(unsigned slot) {
    const nand_info_t *n = nand_info();
    uint32_t ppb, first, first_block;

    if (!n || !n->initialized || slot >= FW_SLOT_COUNT) return -1;
    ppb = n->geometry.pages_per_block;
    first = slot_first_page(slot);
    first_block = first / ppb;

    for (uint32_t b = 0; b < FW_SLOT_BLOCKS; b++) {
        uint32_t block = first_block + b;
        if (block >= n->geometry.block_count) return -2;
        if (nand_is_bad_block(block) != 0) return -3;
        if (nand_erase_block(block) != 0) return -4;
    }
    return 0;
}

int fw_store_install(unsigned slot, const uint8_t *image, uint32_t size,
                     uint64_t load_base, uint32_t entry_off, const char *name) {
    const nand_info_t *n = nand_info();
    firmware_header_t h;
    uint32_t page_size, ppb, first_page, total, pages, block_span;
    const uint8_t *header = (const uint8_t *)&h;

    if (!n || !n->initialized || !n->verified || slot >= FW_SLOT_COUNT) return -1;
    if (!image || size == 0 || size > FW_MAX_SIZE) return -1;
    if (load_base < FW_SRAM_BASE || load_base + size > FW_SRAM_END) return -1;
    if (entry_off >= size) return -1;

    page_size = n->geometry.page_size;
    ppb = n->geometry.pages_per_block;
    first_page = slot_first_page(slot);
    total = (uint32_t)sizeof h + size;
    if (total > FW_SLOT_BLOCKS * ppb * page_size) return -1;
    pages = (total + page_size - 1u) / page_size;

    memset(&h, 0, sizeof h);
    h.magic = FW_MAGIC;
    h.version = FW_VERSION;
    h.flags = 0;
    h.load_base = load_base;
    h.entry_off = entry_off;
    h.size = size;
    h.crc32 = fw_crc32(image, size);
    if (name) {
        uint32_t i = 0;
        for (; name[i] && i + 1u < sizeof h.name; i++) h.name[i] = name[i];
        h.name[i] = 0;
    }

    /* Erase the blocks the record will touch. Only the blocks actually used:
     * erasing a whole 1 MB slot for a 100 KB firmware throws away flash the
     * operator will want back, and the first-page header is all a scan reads. */
    block_span = (pages + ppb - 1u) / ppb;
    uint32_t first_block = first_page / ppb;
    for (uint32_t b = 0; b < block_span; b++) {
        uint32_t block = first_block + b;
        if (block >= n->geometry.block_count) return -2;
        if (nand_is_bad_block(block) != 0) return -3;
        if (nand_erase_block(block) != 0) return -4;
    }

    for (uint32_t i = 0; i < pages; i++) {
        uint32_t offset = i * page_size;
        uint32_t block = (first_page + i) / ppb;
        uint32_t page = (first_page + i) % ppb;

        /* The tail of the last page is left at 0xFF so it reads as erased, not
         * as a programmed run of zeros with the wrong ECC. */
        memset(page_scratch, 0xff, page_size);
        for (uint32_t j = 0; j < page_size; j++) {
            uint32_t pos = offset + j;
            if (pos >= total) break;
            page_scratch[j] = (pos < sizeof h) ? header[pos] : image[pos - sizeof h];
        }

        if (nand_write_page(block, page, page_scratch, 0) != 0) return -5;
        if (nand_verify_page(block, page, page_scratch, 0) != 0) return -6;
    }

    fw_store_scan();
    return 0;
}

/* Strong definition for the goatloader's INSTALL verb; the loader ships a weak
 * refusal so it stays host-testable without NAND. */
int goatloader_install_hook(unsigned slot, const uint8_t *image, uint32_t size,
                            uint64_t load_base, uint32_t entry_off,
                            const char *name) {
    return fw_store_install(slot, image, size, load_base, entry_off, name);
}
