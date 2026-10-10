/* NAND export: read pages through the driver, stream them out with digests.
 *
 * ---------------------------------------------------------------------------
 * What this is for
 * ---------------------------------------------------------------------------
 *
 * The corpus capture story needs raw NAND bytes -- LLB, iBoot and kernelcache
 * live there as files, which is strictly better than a DRAM snapshot because
 * the image is canonical rather than a runtime state. The driver already
 * reads pages; what was missing was a way to move them out with integrity.
 *
 * A serial link at 115200 is not a reliable bulk transport: a dropped byte
 * mid-page silently corrupts a firmware image and you only find out much
 * later, off-device, when a signature fails. So every block is digested as it
 * is read, and the digest travels with the block. A receiver that recomputes
 * it can stop at the first bad block instead of wrote a plausible-looking
 * corrupt corpus to disk.
 *
 * Output is line-oriented hex so it survives a terminal-shaped pipe:
 *
 *   NAND/EXPORT BEGIN <first> <last> <ppb> <page> <oob>
 *   NAND/BLOCK <n> BEGIN <pages> <bad>
 *   NAND/PAGE <block> <page> <oob_hex>
 *   NAND/DATA <block> <page> <len> <hex...>
 *   NAND/BLOCK <n> END <sha256>
 *   NAND/BLOCK <n> SKIP              (bad block, no data follows)
 *   NAND/EXPORT END <blocks> <bytes> <sha256>
 */

#include "nand_export.h"

#include "nand.h"
#include "goat/sha256.h"
#include "uart.h"
#include "util.h"

#define EXPORT_CHUNK 32   /* pages per digest boundary; see EXPORT_CHUNK_SHA */

static void put_hex8(uint8_t b) {
    static const char digits[] = "0123456789abcdef";
    uart_putc(digits[b >> 4]);
    uart_putc(digits[b & 0xF]);
}

static void put_hex(const uint8_t *data, uint32_t len) {
    for (uint32_t i = 0; i < len; i++) put_hex8(data[i]);
}

static void put_sha(const uint8_t digest[GOAT_SHA256_DIGEST_SIZE]) {
    put_hex(digest, GOAT_SHA256_DIGEST_SIZE);
}

/* Feed a length-prefixed record into the running digest so the two sides
 * agree on exactly which bytes were covered, and in what order. */
static void digest_field(goat_sha256_ctx *ctx, const void *data, uint32_t len) {
    uint8_t hdr[4];
    hdr[0] = (uint8_t)(len >> 24);
    hdr[1] = (uint8_t)(len >> 16);
    hdr[2] = (uint8_t)(len >> 8);
    hdr[3] = (uint8_t)len;
    goat_sha256_update(ctx, hdr, sizeof(hdr));
    goat_sha256_update(ctx, data, len);
}

int nand_export_range(uint32_t first_block, uint32_t last_block) {
    if (nand_init() != 0) {
        uart_puts("nand-export: controller/ID unavailable\n");
        return -1;
    }

    const nand_info_t *info = nand_info();
    uint32_t ppb = info->geometry.pages_per_block;
    uint32_t page_size = info->geometry.page_size;
    uint32_t oob_size = info->geometry.oob_size;
    uint32_t total_blocks = info->geometry.block_count;

    if (last_block >= total_blocks) {
        uart_puts("nand-export: last block past the end of the device (");
        uart_puts(utoa(total_blocks));
        uart_puts(")\n");
        return -1;
    }

    uart_puts("NAND/EXPORT BEGIN ");
    uart_puts(utoa(first_block));
    uart_putc(' ');
    uart_puts(utoa(last_block));
    uart_putc(' ');
    uart_puts(utoa(ppb));
    uart_putc(' ');
    uart_puts(utoa(page_size));
    uart_putc(' ');
    uart_puts(utoa(oob_size));
    uart_putc('\n');

    /* Scratches: the driver hands pages back into caller-owned buffers, and
     * this is the only caller that needs page-sized storage of its own. */
    static uint8_t page[NAND_MAX_PAGE_BYTES];
    static uint8_t oob[NAND_MAX_OOB_BYTES];

    goat_sha256_ctx whole;
    goat_sha256_init(&whole);
    uint64_t bytes_sent = 0;
    uint32_t blocks_done = 0;

    for (uint32_t block = first_block; block <= last_block; block++) {
        int bad = nand_is_bad_block(block);
        if (bad < 0) {
            uart_puts("NAND/EXPORT ERROR bad-block-scan failed at ");
            uart_puts(utoa(block));
            uart_putc('\n');
            return -2;
        }

        if (bad) {
            /* A named gap, not silence: the receiver must be able to tell
                 * "this block was bad" from "the transfer stopped here". */
            uart_puts("NAND/BLOCK ");
            uart_puts(utoa(block));
            uart_puts(" SKIP\n");
            digest_field(&whole, "SKIP", 4);
            blocks_done++;
            continue;
        }

        uart_puts("NAND/BLOCK ");
        uart_puts(utoa(block));
        uart_puts(" BEGIN ");
        uart_puts(utoa(ppb));
        uart_puts(" 0\n");

        goat_sha256_ctx block_ctx;
        goat_sha256_init(&block_ctx);
        int failed = 0;

        for (uint32_t p = 0; p < ppb; p++) {
            if (nand_read_page(block, p, page, oob) != 0) {
                uart_puts("NAND/BLOCK ");
                uart_puts(utoa(block));
                uart_puts(" READFAIL page=");
                uart_puts(utoa(p));
                uart_putc('\n');
                failed = 1;
                break;
            }

            uart_puts("NAND/PAGE ");
            uart_puts(utoa(block));
            uart_putc(' ');
            uart_puts(utoa(p));
            uart_puts(" oob=");
            put_hex(oob, oob_size < 32u ? oob_size : 32u);
            uart_putc('\n');

            uart_puts("NAND/DATA ");
            uart_puts(utoa(block));
            uart_putc(' ');
            uart_puts(utoa(p));
            uart_putc(' ');
            uart_puts(utoa(page_size));
            uart_putc(' ');
            put_hex(page, page_size);
            uart_putc('\n');

            /* The digests cover the same bytes in the same order as the
             * output, minus the hex encoding: page data then OOB. */
            digest_field(&block_ctx, page, page_size);
            digest_field(&block_ctx, oob, oob_size);
            digest_field(&whole, page, page_size);
            digest_field(&whole, oob, oob_size);
            bytes_sent += (uint64_t)page_size + oob_size;
        }

        if (failed) {
            return -3;
        }

        uint8_t digest[GOAT_SHA256_DIGEST_SIZE];
        goat_sha256_final(&block_ctx, digest);
        uart_puts("NAND/BLOCK ");
        uart_puts(utoa(block));
        uart_puts(" END sha256=");
        put_sha(digest);
        uart_putc('\n');
        blocks_done++;

        /* Progress, because a full NAND over 115200 is thousands of pages
         * and a silent transfer looks like a hung one. */
        if ((block - first_block) % EXPORT_CHUNK == 0 && block != first_block) {
            uart_puts("NAND/PROGRESS block=");
            uart_puts(utoa(block));
            uart_puts(" bytes=");
            uart_puts(utoa(bytes_sent));
            uart_putc('\n');
        }
    }

    uint8_t digest[GOAT_SHA256_DIGEST_SIZE];
    goat_sha256_final(&whole, digest);
    uart_puts("NAND/EXPORT END blocks=");
    uart_puts(utoa(blocks_done));
    uart_puts(" bytes=");
    uart_puts(utoa(bytes_sent));
    uart_puts(" sha256=");
    put_sha(digest);
    uart_putc('\n');
    return 0;
}
