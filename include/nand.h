#ifndef DR1ZZLE_NAND_H
#define DR1ZZLE_NAND_H

#include <stdint.h>

/* The A11 NAND window is not emulated by QEMU and its exact geometry is
 * board-dependent.  Keep the geometry explicit instead of baking it into
 * page-address arithmetic. */
#define NAND_MAX_ID_BYTES       8u
#define NAND_MAX_PAGE_BYTES     16384u
#define NAND_MAX_OOB_BYTES      1024u
#define NAND_DEFAULT_PAGE_SIZE  4096u
#define NAND_DEFAULT_OOB_SIZE   128u
#define NAND_DEFAULT_PAGES_BLOCK 64u
#define NAND_DEFAULT_BLOCKS     512u

typedef struct {
    uint32_t page_size;
    uint32_t oob_size;
    uint32_t pages_per_block;
    uint32_t block_count;
    uint32_t ecc_step;
    uint32_t ecc_bytes;
} nand_geometry_t;

typedef struct {
    uint32_t corrected;
    uint32_t failed;
    uint32_t uncorrectable;
} nand_ecc_stats_t;

typedef struct {
    nand_geometry_t geometry;
    uint8_t id[NAND_MAX_ID_BYTES];
    uint32_t id_len;
    nand_ecc_stats_t ecc;
    int initialized;
    int verified;
} nand_info_t;

/* Bring the controller to a known state and read its ID.  A guessed or
 * floating register window is rejected before any page operation is issued. */
int nand_init(void);
int nand_read_id(uint8_t *id, uint32_t capacity, uint32_t *length);
const nand_info_t *nand_info(void);

int nand_read_page(uint32_t block, uint32_t page, uint8_t *data,
                   uint8_t *oob);
int nand_is_bad_block(uint32_t block);
uint32_t nand_total_blocks(void);
uint32_t nand_pages_per_block(void);

/* Software ECC entry point for captured pages.  The on-device controller
 * reports corrected/failed status; this function verifies the same 512-byte
 * step framing for callers processing a page image off-device. */
int nand_bch8_check(const uint8_t *data, uint32_t data_len,
                    const uint8_t *ecc, uint32_t ecc_len,
                    nand_ecc_stats_t *stats);

typedef int (*nand_page_sink_t)(uint32_t block, uint32_t page,
                                const uint8_t *data, uint32_t data_len,
                                const uint8_t *oob, uint32_t oob_len,
                                void *context);

int nand_dump_range(uint32_t first_block, uint32_t last_block,
                    nand_page_sink_t sink, void *context,
                    uint32_t *bad_blocks, uint32_t *pages_read);

#endif /* DR1ZZLE_NAND_H */
