#include "sepos.h"
#include "sep.h"
#include "uart.h"
#include "timer.h"
#include "util.h"
#include "memory_map.h"

/* SEP driver instance for research module */
static struct sep_driver sep_drv;
static bool sep_init_attempted;
static int sep_init_result = SEP_ERR_UNSUPPORTED;

static int sepos_ensure_init(void) {
    if (!sep_init_attempted) {
        sep_init_attempted = true;
        sep_init_result = sep_init(&sep_drv, MAILBOX_BASE);
        if (sep_init_result != SEP_OK)
            uart_puts("SEP transport disabled: mailbox base/register map is not verified\n");
    }
    return sep_init_result;
}

/* Initialize SEP driver with mailbox base from SoC profile */
int sepos_init(void) {
    return sepos_ensure_init();
}

/* Dump SEPOS via mailbox protocol */
void dump_sepos(void) {
    if (sepos_ensure_init() != SEP_OK) return;
    uart_puts("Dumping SEPOS via SEP mailbox...\n");

    /* First, ping SEP */
    if (sep_ping(&sep_drv) != SEP_OK) {
        uart_puts("SEP ping failed\n");
        return;
    }
    uart_puts("SEP ping OK\n");

    /* Get random data (tests SEP crypto) */
    uint8_t random[32];
    if (sep_get_random(&sep_drv, random) == SEP_OK) {
        uart_puts("Got random data from SEP: ");
        for (int i = 0; i < 32; i++) {
            uart_puts(utoa_hex(random[i] >> 4));
            uart_puts(utoa_hex(random[i] & 0xF));
        }
        uart_puts("\n");
    } else {
        uart_puts("SEP get_random failed\n");
    }

    /* Try to boot TZ0 (SEPOS) */
    uart_puts("Attempting to boot TZ0...\n");
    if (sep_boot_tz0(&sep_drv, 0) == SEP_OK) {
        uart_puts("TZ0 boot command sent\n");
    } else {
        uart_puts("TZ0 boot failed\n");
    }

    /* Dump SEPOS memory via mailbox */
    uart_puts("SEPOS dump requires SEP-side cooperation\n");
    uart_puts("Use 'sepos memdump <addr> <len>' for memory dump\n");
}

/* SEP memory dump via mailbox */
void sepos_memdump(uint64_t addr, uint32_t len) {
    uart_puts("SEPOS memdump: ");
    uart_puts(utoa_hex(addr));
    uart_puts(" len ");
    uart_puts(utoa(len));
    uart_puts("\n");

    /* This would require SEPOS cooperation to read its memory */
    uart_puts("Requires SEPOS-side memory dump command\n");
}

/* SEP mailbox status */
void sepos_status(void) {
    if (sepos_ensure_init() != SEP_OK) return;
    if (!sep_drv.base) {
        uart_puts("SEP mailbox transport unavailable: T8015 FIFO base/register map is unverified\n");
        return;
    }
    uint32_t status = sep_get_status(&sep_drv);
    uart_puts("SEP Mailbox Status:\n");
    uart_puts("  STATUS: 0x"); uart_puts(utoa_hex(status)); uart_puts("\n");
    uart_puts("  AP->IOP_MSG: 0x"); uart_puts(utoa_hex(sep_drv.base[SEP_AP2IOP_MSG0/4])); uart_puts("\n");
    uart_puts("  AP->IOP_DB:  0x"); uart_puts(utoa_hex(sep_drv.base[SEP_AP2IOP_DB/4])); uart_puts("\n");
    uart_puts("  IOP->AP_MSG: 0x"); uart_puts(utoa_hex(sep_drv.base[SEP_IOP2AP_MSG0/4])); uart_puts("\n");
    uart_puts("  IOP->AP_DB:  0x"); uart_puts(utoa_hex(sep_drv.base[SEP_IOP2AP_DB/4])); uart_puts("\n");

    /* Print statistics */
    const sep_stats_t *stats = sep_get_stats(&sep_drv);
    if (stats) {
        uart_puts("  Commands sent:     "); uart_puts(utoa(stats->commands_sent)); uart_puts("\n");
        uart_puts("  Replies received:  "); uart_puts(utoa(stats->replies_received)); uart_puts("\n");
        uart_puts("  Timeouts:          "); uart_puts(utoa(stats->timeouts)); uart_puts("\n");
        uart_puts("  NAKs:              "); uart_puts(utoa(stats->naks)); uart_puts("\n");
        uart_puts("  Busy retries:      "); uart_puts(utoa(stats->busy_retries)); uart_puts("\n");
        uart_puts("  Errors:            "); uart_puts(utoa(stats->errors)); uart_puts("\n");
    }
}

/* Shell wrapper functions */
int sepos_ping(void) {
    if (sepos_ensure_init() != SEP_OK) return sep_init_result;
    return sep_ping(&sep_drv);
}

int sepos_get_random(void) {
    if (sepos_ensure_init() != SEP_OK) return sep_init_result;
    uint8_t random[32];
    int rc = sep_get_random(&sep_drv, random);
    if (rc == SEP_OK) {
        uart_puts("Got random data from SEP: ");
        for (int i = 0; i < 32; i++) {
            uart_puts(utoa_hex(random[i] >> 4));
            uart_puts(utoa_hex(random[i] & 0xF));
        }
        uart_puts("\n");
    } else {
        uart_puts("SEP get_random failed (");
        uart_puts(utoa(rc));
        uart_puts(")\n");
    }
    return rc;
}

int sepos_boot_tz0(void) {
    if (sepos_ensure_init() != SEP_OK) return sep_init_result;
    int rc = sep_boot_tz0(&sep_drv, 0);
    if (rc != SEP_OK) {
        uart_puts("TZ0 boot failed (");
        uart_puts(utoa(rc));
        uart_puts(")\n");
    }
    return rc;
}

int sepos_send_sepos(uint64_t image_base, uint32_t image_size, uint64_t entry_page) {
    if (sepos_ensure_init() != SEP_OK) return sep_init_result;
    return sep_send_sepos(&sep_drv, image_base, image_size, entry_page);
}

int sepos_send_art(uint64_t art_base, uint32_t art_size) {
    if (sepos_ensure_init() != SEP_OK) return sep_init_result;
    return sep_send_art(&sep_drv, art_base, art_size);
}
