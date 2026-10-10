#ifndef DR1ZZLE_NAND_H
#define DR1ZZLE_NAND_H

#include <stdint.h>

/* The A11 NAND window is not emulated by QEMU and its exact geometry is
 * board-dependent.  Keep the geometry explicit instead of baking it into
 * page-address arithmetic. */
#define NAND_MAX_ID_BYTES       8u
#define NAND_MAX_PAGE_BYTES     16384u
#define NAND_MAX_OOB_BYTES      1024u

/* Geometry defaults come from the selected SoC profile, which is why this
 * header pulls the map in itself rather than assuming a caller did. */
#include "soc.h"
/*
 * Default NAND geometry, supplied by the SoC profile. These are conservative
 * values confirmed against the device ID table at init before any real page
 * is touched; a board with different geometry is picked up automatically.
 */
#define NAND_DEFAULT_PAGE_SIZE  SOC_NAND_PAGE_SIZE
#define NAND_DEFAULT_OOB_SIZE   SOC_NAND_OOB_SIZE
#define NAND_DEFAULT_PAGES_BLOCK SOC_NAND_PAGES_PER_BLOCK
#define NAND_DEFAULT_BLOCKS     SOC_NAND_BLOCK_COUNT

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

/* Write-path counters. Kept separate from the ECC counters because a program
 * that the part rejects and a page that reads back differently are different
 * failures, and an operator watching a flash calls for the one they hit. */
typedef struct {
    uint32_t erased;          /* blocks erased cleanly */
    uint32_t programmed;      /* pages programmed cleanly */
    uint32_t write_failed;    /* erase/program ops the part rejected */
    uint32_t verify_failed;   /* pages whose readback did not match */
} nand_write_stats_t;

typedef struct {
    nand_geometry_t geometry;
    uint8_t id[NAND_MAX_ID_BYTES];
    uint32_t id_len;
    nand_ecc_stats_t ecc;
    nand_write_stats_t write;
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

/* Write path. All three refuse on an unprobed controller and on an
 * out-of-range block/page. `oob` semantics are the same for write and verify:
 * a NULL spare means "let the controller's ECC engine place parity" -- the
 * spare area is written as 0xFF and the engine fills the ECC bytes on program.
 * A non-NULL `oob` is written and compared verbatim.
 *
 * nand_verify_page() reads the page back through the normal ECC path, so a
 * page that was programmed with marginal cells reports honestly instead of
 * being called good. It returns 0 on a match, -1 on a mismatch and -2 when the
 * read itself failed. */
int nand_erase_block(uint32_t block);
int nand_write_page(uint32_t block, uint32_t page, const uint8_t *data,
                    const uint8_t *oob);
int nand_verify_page(uint32_t block, uint32_t page, const uint8_t *data,
                     const uint8_t *oob);

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
