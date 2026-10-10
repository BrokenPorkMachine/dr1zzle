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
#include "nand.h"
#include "string.h"
#include "uart.h"
#include "util.h"
#include "goat/goat.h"

#define FW_SLOT_CACHE   FW_SLOT_COUNT

typedef struct {
    firmware_header_t hdr;
    int present;
} fw_slot_t;

static fw_slot_t slots[FW_SLOT_CACHE];
static uint8_t oob_scratch[NAND_MAX_OOB_BYTES];

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
    uart_puts(h->name);
    uart_puts(" at 0x");
    uart_puts(utoa_hex(entry));
    uart_puts("\r\n");
    goat_enter(entry);
}
