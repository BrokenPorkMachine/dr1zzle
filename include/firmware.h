#ifndef DR1ZZLE_FIRMWARE_H
#define DR1ZZLE_FIRMWARE_H

#include <stdint.h>

/* dr1zzle firmware images.
 *
 * ---------------------------------------------------------------------------
 * Why a firmware is a separate image
 * ---------------------------------------------------------------------------
 *
 * The core payload has to be small enough for `goat kload` to place it below
 * the pwndfu command area (0x18001C000). Everything that made the single flat
 * image too big for that window -- the full monitor shell, networking, the
 * dump drivers, the crypto -- therefore cannot live in the core. Instead it
 * is built as a *firmware*: a self-contained image for one kind of work, laid
 * onto the device on demand.
 *
 * The core's menu picks a firmware; the goatloader can also stage one over
 * USB (that is what `goat push --run` already does with a sealed container).
 * Both paths end with the same header below parsed at the load address.
 *
 * Layout, on NAND or in a goat container:
 *
 *     firmware_header_t
 *     uint8_t image[size]        -- linked for load_base
 *
 * The image is entered at load_base + entry_off. crc32 covers only the image
 * bytes: a corrupt header is caught by magic/version/size sanity first, and
 * the CRC then catches a truncated or garbled image.
 */

#define FW_MAGIC        0x31574644u   /* "DFW1" (little-endian) */
#define FW_VERSION      1u

/* Where the core places a firmware before it runs it. This deliberately
 * coincides with the goatloader staging window and the host tool's
 * GOAT_STAGE_BASE (the Rust Goat container implementation), so a pushed container and an on-NAND
 * firmware share one region: the core only ever holds one at a time, and the
 * two delivery paths cannot disagree about where it lands. */
#define FW_LOAD_BASE    0x180100000ull
#define FW_MAX_SIZE     0xE8000u          /* to the end of SRAM */
#define FW_SRAM_BASE    0x180000000ull
#define FW_SRAM_END     0x1801E8000ull

typedef struct __attribute__((packed)) {
    uint32_t magic;        /* FW_MAGIC */
    uint16_t version;      /* FW_VERSION */
    uint16_t flags;        /* reserved, 0 */
    uint64_t load_base;    /* runtime link address of the image */
    uint32_t entry_off;    /* entry = load_base + entry_off */
    uint32_t size;         /* bytes of image following this header */
    uint32_t crc32;        /* CRC32 (IEEE 802.3) over the image bytes */
    char     name[16];     /* NUL-padded label: "dump", "diag", "shell" */
} firmware_header_t;

/* NAND-resident firmware store. Slots are fixed-size so the core can find
 * them without a filesystem: slot n starts at block FW_STORE_BLOCK +
 * n * FW_SLOT_BLOCKS. A slot the core has never been asked to load costs one
 * header read to reject. */
#define FW_STORE_BLOCK   0x2000u
#define FW_SLOT_BLOCKS   4u           /* 4 x 256 KB = 1 MB per slot */
#define FW_SLOT_COUNT    8u

uint32_t fw_crc32(const void *data, uint32_t len);

#endif /* DR1ZZLE_FIRMWARE_H */
