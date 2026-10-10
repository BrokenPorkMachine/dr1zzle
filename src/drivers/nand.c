/* A11 NAND controller.
 *
 * The command protocol is intentionally kept behind this file.  The address
 * window is not emulated by QEMU, so every public operation validates the
 * controller state and geometry before it touches a page.  The geometry is
 * a conservative 4 KiB/128-byte-OOB profile until the device ID table has
 * been checked against an actual board.
 */

#include "nand.h"

#include "memory_map.h"
#include "mmio.h"
#include "timer.h"

#define NFC_CTRL       0x00u
#define NFC_STATUS     0x04u
#define NFC_CMD        0x08u
#define NFC_ADDR       0x0cu
#define NFC_DATA       0x10u
#define NFC_ECC_CTRL   0x14u
#define NFC_ECC_STATUS 0x18u

#define NFC_CTRL_ENABLE        (1u << 0)
#define NFC_CTRL_RESET         (1u << 1)
#define NFC_CTRL_ECC_ENABLE    (1u << 2)

#define NFC_STATUS_READY       (1u << 0)
#define NFC_STATUS_FAIL        (1u << 1)
#define NFC_ECC_UNCORRECTABLE (1u << 31)
#define NFC_ECC_CORRECTED_MASK 0xffu

#define NAND_CMD_READ0         0x00u
#define NAND_CMD_READSTART     0x30u
#define NAND_CMD_READID        0x90u
#define NAND_CMD_RESET         0xffu

#define NAND_TIMEOUT_US        100000u
#define NAND_ECC_STEP          512u
#define NAND_ECC_BYTES_STEP    13u

static nand_info_t g_nand;
static uint8_t g_page[NAND_MAX_PAGE_BYTES];
static uint8_t g_oob[NAND_MAX_OOB_BYTES];

static inline uintptr_t nfc_reg(uint32_t offset) {
    return (uintptr_t)NAND_BASE + offset;
}

static void nfc_write(uint32_t offset, uint32_t value) {
    mmio_write32(nfc_reg(offset), value);
}

static uint32_t nfc_read(uint32_t offset) {
    return mmio_read32(nfc_reg(offset));
}

static int nfc_wait_ready(void) {
    volatile uint32_t *status = (volatile uint32_t *)nfc_reg(NFC_STATUS);
    return timer_wait_reg(status, NFC_STATUS_READY, NFC_STATUS_READY,
                          NAND_TIMEOUT_US);
}

static void nfc_reset(void) {
    nfc_write(NFC_CTRL, NFC_CTRL_RESET);
    timer_sleep_us(10);
    nfc_write(NFC_CTRL, NFC_CTRL_ENABLE | NFC_CTRL_ECC_ENABLE);
}

static int id_is_plausible(const uint8_t *id, uint32_t len) {
    int all_zero = 1;
    int all_ff = 1;
    if (!id || len == 0) return 0;
    for (uint32_t i = 0; i < len; i++) {
        if (id[i] != 0x00u) all_zero = 0;
        if (id[i] != 0xffu) all_ff = 0;
    }
    /* The first byte is the manufacturer byte.  Zero/0xff is what a
     * floating or absent device window returns on the parts we can test. */
    return !all_zero && !all_ff && id[0] != 0x00u && id[0] != 0xffu;
}

static void nfc_read_words(uint8_t *out, uint32_t length) {
    uint32_t offset = 0;
    while (offset + 4u <= length) {
        uint32_t word = nfc_read(NFC_DATA);
        out[offset + 0] = (uint8_t)word;
        out[offset + 1] = (uint8_t)(word >> 8);
        out[offset + 2] = (uint8_t)(word >> 16);
        out[offset + 3] = (uint8_t)(word >> 24);
        offset += 4u;
    }
    if (offset < length) {
        uint32_t word = nfc_read(NFC_DATA);
        while (offset < length) {
            out[offset++] = (uint8_t)word;
            word >>= 8;
        }
    }
}

int nand_read_id(uint8_t *id, uint32_t capacity, uint32_t *length) {
    if (!id || capacity == 0 || !length || capacity < 5u) return -1;

    nfc_write(NFC_CMD, NAND_CMD_READID);
    nfc_write(NFC_ADDR, 0);
    if (nfc_wait_ready() != 0) return -2;

    uint32_t count = capacity < NAND_MAX_ID_BYTES ? capacity
                                                   : NAND_MAX_ID_BYTES;
    nfc_read_words(id, count);
    *length = count;
    return id_is_plausible(id, count) ? 0 : -3;
}

int nand_init(void) {
    if (g_nand.initialized) return g_nand.verified ? 0 : -1;

    g_nand.geometry.page_size = NAND_DEFAULT_PAGE_SIZE;
    g_nand.geometry.oob_size = NAND_DEFAULT_OOB_SIZE;
    g_nand.geometry.pages_per_block = NAND_DEFAULT_PAGES_BLOCK;
    g_nand.geometry.block_count = NAND_DEFAULT_BLOCKS;
    g_nand.geometry.ecc_step = NAND_ECC_STEP;
    g_nand.geometry.ecc_bytes = NAND_ECC_BYTES_STEP;

    nfc_reset();
    nfc_write(NFC_CMD, NAND_CMD_RESET);
    if (nfc_wait_ready() != 0) return -1;

    uint32_t id_len = 0;
    int rc = nand_read_id(g_nand.id, NAND_MAX_ID_BYTES, &id_len);
    if (rc != 0) return rc;

    g_nand.id_len = id_len;
    g_nand.initialized = 1;
    g_nand.verified = 1;
    return 0;
}

const nand_info_t *nand_info(void) {
    return &g_nand;
}

uint32_t nand_total_blocks(void) {
    return g_nand.geometry.block_count;
}

uint32_t nand_pages_per_block(void) {
    return g_nand.geometry.pages_per_block;
}

static int nand_valid_page(uint32_t block, uint32_t page) {
    return g_nand.initialized && g_nand.verified &&
           block < g_nand.geometry.block_count &&
           page < g_nand.geometry.pages_per_block;
}

int nand_read_page(uint32_t block, uint32_t page, uint8_t *data, uint8_t *oob) {
    if (!data || !nand_valid_page(block, page)) return -1;

    uint64_t row64 = (uint64_t)block * g_nand.geometry.pages_per_block + page;
    if (row64 > 0xffffffffULL) return -2;

    /* The A11 controller exposes the NAND row/column address as a packed
     * word.  Keeping the two writes separate mirrors the command sequence
     * in the controller specification and avoids endian-dependent structs. */
    nfc_write(NFC_CMD, NAND_CMD_READ0);
    nfc_write(NFC_ADDR, 0);                  /* column */
    nfc_write(NFC_ADDR, (uint32_t)row64);    /* row */
    nfc_write(NFC_CMD, NAND_CMD_READSTART);
    if (nfc_wait_ready() != 0) return -3;

    uint32_t total = g_nand.geometry.page_size +
                     (oob ? g_nand.geometry.oob_size : 0u);
    nfc_read_words(data, g_nand.geometry.page_size);
    if (oob) nfc_read_words(oob, g_nand.geometry.oob_size);

    uint32_t ecc_status = nfc_read(NFC_ECC_STATUS);
    uint32_t corrected = ecc_status & NFC_ECC_CORRECTED_MASK;
    g_nand.ecc.corrected += corrected;
    if ((ecc_status & NFC_ECC_UNCORRECTABLE) != 0u ||
        (nfc_read(NFC_STATUS) & NFC_STATUS_FAIL) != 0u) {
        g_nand.ecc.uncorrectable++;
        return -4;
    }
    (void)total;
    return 0;
}

int nand_is_bad_block(uint32_t block) {
    if (!g_nand.initialized || block >= g_nand.geometry.block_count) return -1;
    if (nand_read_page(block, 0, g_page, g_oob) != 0) return -1;
    /* Large-page NAND uses byte 0 of the first-page OOB as its bad-block
     * marker.  Check byte 1 as well because some A11 packages expose the
     * marker at the second byte after controller metadata. */
    return (g_oob[0] != 0xffu || g_oob[1] != 0xffu) ? 1 : 0;
}

int nand_bch8_check(const uint8_t *data, uint32_t data_len,
                    const uint8_t *ecc, uint32_t ecc_len,
                    nand_ecc_stats_t *stats) {
    nand_ecc_stats_t local = {0, 0, 0};
    if (!stats) stats = &local;
    stats->corrected = stats->failed = stats->uncorrectable = 0;

    if (!data || !ecc || data_len == 0 || (data_len % NAND_ECC_STEP) != 0) {
        return -1;
    }
    uint32_t steps = data_len / NAND_ECC_STEP;
    if (ecc_len < steps * NAND_ECC_BYTES_STEP) return -1;

    /* BCH parity is generated by the controller on silicon.  This portable
     * checker handles the important erased-page case and refuses to claim a
     * correction for a non-erased page without a matching controller status.
     * A caller can therefore never mistake an unchecked image for corrected
     * data. */
    for (uint32_t step = 0; step < steps; step++) {
        int erased = 1;
        for (uint32_t i = 0; i < NAND_ECC_STEP; i++) {
            if (data[step * NAND_ECC_STEP + i] != 0xffu) {
                erased = 0;
                break;
            }
        }
        if (erased) {
            for (uint32_t i = 0; i < NAND_ECC_BYTES_STEP; i++) {
                if (ecc[step * NAND_ECC_BYTES_STEP + i] != 0xffu) {
                    stats->failed++;
                    return -2;
                }
            }
        } else {
            stats->uncorrectable++;
            return -3;
        }
    }
    return 0;
}

int nand_dump_range(uint32_t first_block, uint32_t last_block,
                    nand_page_sink_t sink, void *context,
                    uint32_t *bad_blocks, uint32_t *pages_read) {
    if (!g_nand.initialized || !g_nand.verified || !sink ||
        first_block > last_block || last_block >= g_nand.geometry.block_count) {
        return -1;
    }
    uint32_t bad = 0, read = 0;
    for (uint32_t block = first_block; block <= last_block; block++) {
        int bad_block = nand_is_bad_block(block);
        if (bad_block < 0) return -2;
        if (bad_block != 0) {
            bad++;
            continue;
        }
        for (uint32_t page = 0; page < g_nand.geometry.pages_per_block; page++) {
            if (nand_read_page(block, page, g_page, g_oob) != 0) return -3;
            if (sink(block, page, g_page, g_nand.geometry.page_size,
                     g_oob, g_nand.geometry.oob_size, context) != 0) {
                return -4;
            }
            read++;
        }
    }
    if (bad_blocks) *bad_blocks = bad;
    if (pages_read) *pages_read = read;
    return 0;
}
