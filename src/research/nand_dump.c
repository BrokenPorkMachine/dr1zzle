/* NAND/APFS shell adapters. The raw NAND driver owns command sequencing; this
 * file owns operator-facing summaries and the read-only APFS adapter. */

#include "nand_dump.h"

#include "apfs.h"
#include "memory_map.h"
#include "nand.h"
#include "uart.h"
#include "util.h"

static int report_page(uint32_t block, uint32_t page, const uint8_t *data,
                       uint32_t data_len, const uint8_t *oob,
                       uint32_t oob_len, void *context) {
    (void)context;
    uart_puts("nand: block="); uart_puts(utoa(block));
    uart_puts(" page="); uart_puts(utoa(page));
    uart_puts(" bytes="); uart_puts(utoa(data_len));
    if (data_len >= 4u) {
        uart_puts(" head=0x");
        uart_puts(utoa_hex((uint64_t)data[0] | ((uint64_t)data[1] << 8) |
                           ((uint64_t)data[2] << 16) | ((uint64_t)data[3] << 24)));
    }
    uart_puts(" oob="); uart_puts(utoa(oob_len));
    if (oob && oob_len != 0u) {
        uart_puts(" marker=0x"); uart_puts(utoa_hex(oob[0]));
    }
    uart_puts("\n");
    return 0;
}

static void report_nand_info(void) {
    const nand_info_t *info = nand_info();
    uart_puts("nand: ");
    if (!info->initialized || !info->verified) {
        uart_puts("not initialized\n");
        return;
    }
    uart_puts("id=");
    for (uint32_t i = 0; i < info->id_len; i++) {
        uart_puts(i == 0u ? "" : ":");
        uart_puts(utoa_hex(info->id[i]));
    }
    uart_puts(" page="); uart_puts(utoa(info->geometry.page_size));
    uart_puts(" oob="); uart_puts(utoa(info->geometry.oob_size));
    uart_puts(" pages/block="); uart_puts(utoa(info->geometry.pages_per_block));
    uart_puts(" blocks="); uart_puts(utoa(info->geometry.block_count));
    uart_puts(" corrected="); uart_puts(utoa(info->ecc.corrected));
    uart_puts(" uncorrectable="); uart_puts(utoa(info->ecc.uncorrectable));
    uart_puts("\n");
}

static int ensure_nand(void) {
    if (nand_init() != 0) {
        uart_puts("nand: controller/ID not available; no page command issued\n");
        return -1;
    }
    return 0;
}

void dump_nand_all(void) {
    if (ensure_nand() != 0) return;
    report_nand_info();
    uint32_t bad = 0, pages = 0;
    int rc = nand_dump_range(0, nand_total_blocks() - 1u, report_page, 0,
                             &bad, &pages);
    uart_puts("nand: dump "); uart_puts(rc == 0 ? "complete" : "failed");
    uart_puts(" pages="); uart_puts(utoa(pages));
    uart_puts(" bad-blocks="); uart_puts(utoa(bad));
    uart_puts(" (page records are emitted to the active console)\n");
}

void dump_nand_range(uint32_t start_block, uint32_t end_block) {
    if (ensure_nand() != 0) return;
    report_nand_info();
    if (start_block > end_block || end_block >= nand_total_blocks()) {
        uart_puts("nand: invalid block range\n");
        return;
    }
    uint32_t bad = 0, pages = 0;
    int rc = nand_dump_range(start_block, end_block, report_page, 0,
                             &bad, &pages);
    uart_puts("nand: range "); uart_puts(rc == 0 ? "complete" : "failed");
    uart_puts(" pages="); uart_puts(utoa(pages));
    uart_puts(" bad-blocks="); uart_puts(utoa(bad));
    uart_puts("\n");
}

static int apfs_nand_read(void *context, uint64_t block, uint8_t *out,
                          uint32_t length) {
    (void)context;
    const nand_info_t *info = nand_info();
    if (!out || length != info->geometry.page_size ||
        block >= (uint64_t)info->geometry.block_count *
                     info->geometry.pages_per_block) return -1;
    uint32_t nand_block = (uint32_t)(block / info->geometry.pages_per_block);
    uint32_t page = (uint32_t)(block % info->geometry.pages_per_block);
    return nand_read_page(nand_block, page, out, 0);
}

void extract_apfs_files(void) {
    if (ensure_nand() != 0) return;
    const nand_info_t *info = nand_info();
    apfs_io_t io = { apfs_nand_read, 0 };
    apfs_container_info_t container;
    apfs_volume_info_t volume;
    int rc = apfs_open(&io, 4096u, &container, &volume);
    if (rc < 0) {
        uart_puts("apfs: no readable NXSB/volume found in the first 4096 pages\n");
        return;
    }
    uart_puts("apfs: container block="); uart_puts(utoa(container.nx_block));
    uart_puts(" size="); uart_puts(utoa(container.block_size));
    uart_puts(" blocks="); uart_puts(utoa(container.block_count));
    uart_puts(" checksum="); uart_puts(container.checksum_valid == 1 ? "ok" : "not-verified");
    uart_puts("\n");
    if (rc == 0) {
        uart_puts("apfs: volume index="); uart_puts(utoa(volume.fs_index));
        uart_puts(" block="); uart_puts(utoa(volume.block));
        uart_puts(" name="); uart_puts(volume.name);
        uart_puts(" root=0x"); uart_puts(utoa_hex(volume.root_tree_oid));
        uart_puts("\n");
        uart_puts("apfs: file extraction requires OMAP resolution; metadata scan complete\n");
    } else {
        uart_puts("apfs: container found, but no volume superblock was resolved\n");
    }
    (void)info;
}
