#include "sepos.h"
#include "sep.h"
#include "uart.h"
#include "timer.h"
#include "util.h"
#include "memory_map.h"

/*
 * SEP research shell wrappers.
 *
 * Protocol source: pongoOS src/drivers/sep/sep.c. The A11 uses the 64-bit
 * mailbox at sep_reg + 0x8100, with the message FIFO at +0x8800/+0x8830.
 * This module owns a single driver instance and is the only caller that
 * touches the hardware; the shell commands are thin wrappers.
 *
 * Status of the transport: the mailbox base comes from the SoC profile and
 * has not been verified on silicon. sepos_init reports the outcome and the
 * shell refuses every command that needs a live transport rather than
 * silently doing nothing.
 */

static struct sep_driver sep_drv;
static bool sep_init_attempted;
static int sep_init_result = SEP_ERR_INVALID;

static int sepos_ensure_init(void) {
    if (!sep_init_attempted) {
        sep_init_attempted = true;
        sep_init_result = sep_init(&sep_drv, MAILBOX_BASE);
        if (sep_init_result != SEP_OK) {
            uart_puts("sepos: transport init failed (");
            uart_puts(utoa(sep_init_result));
            uart_puts(")\n");
        }
    }
    return sep_init_result;
}

int sepos_init(void) {
    return sepos_ensure_init();
}

void dump_sepos(void) {
    if (sepos_ensure_init() != SEP_OK) {
        uart_puts("SEP transport unavailable\n");
        return;
    }
    uart_puts("Dumping SEPOS via SEP mailbox...\n");

    if (sep_ping(&sep_drv) != SEP_OK) {
        uart_puts("SEP ping failed\n");
        return;
    }
    uart_puts("SEP ping OK\n");

    uint8_t random[32];
    if (sep_get_random(&sep_drv, random) == SEP_OK) {
        uart_puts("SEP random: ");
        for (int i = 0; i < 32; i++) {
            uart_puts(utoa_hex(random[i] >> 4));
            uart_puts(utoa_hex(random[i] & 0xF));
        }
        uart_puts("\n");
    } else {
        uart_puts("SEP get_random failed\n");
    }

    uart_puts("SEPOS dump requires SEP-side cooperation\n");
    uart_puts("Use 'sepos memdump <addr> <len>' for memory dump\n");
}

void sepos_memdump(uint64_t addr, uint32_t len) {
    uart_puts("SEPOS memdump: ");
    uart_puts(utoa_hex(addr));
    uart_puts(" len ");
    uart_puts(utoa(len));
    uart_puts("\n");
    uart_puts("Requires SEPOS-side cooperation (no opcode for this in pongoOS)\n");
}

void sepos_status(void) {
    if (sepos_ensure_init() != SEP_OK) {
        uart_puts("SEP mailbox transport unavailable\n");
        return;
    }
    uint32_t sts = sep_recv_status(&sep_drv);
    uart_puts("SEP Mailbox (64-bit, A11 layout):\n");
    uart_puts("  base:        0x"); uart_puts(utoa_hex(sep_drv.base_addr)); uart_puts("\n");
    uart_puts("  recv_sts:    0x"); uart_puts(utoa_hex(sts)); uart_puts("\n");
    uart_puts("  queue empty: "); uart_puts(sep_recv_queue_empty(&sep_drv) ? "yes" : "no"); uart_puts("\n");
    uart_puts("  irq enabled: "); uart_puts(sep_drv.irq_mode ? "yes" : "no"); uart_puts("\n");

    const struct sep_stats *s = sep_get_stats(&sep_drv);
    if (s) {
        uart_puts("  sent:        "); uart_puts(utoa(s->commands_sent)); uart_puts("\n");
        uart_puts("  replies:     "); uart_puts(utoa(s->replies_received)); uart_puts("\n");
        uart_puts("  timeouts:    "); uart_puts(utoa(s->timeouts)); uart_puts("\n");
        uart_puts("  naks:        "); uart_puts(utoa(s->naks)); uart_puts("\n");
        uart_puts("  panics:      "); uart_puts(utoa(s->panics)); uart_puts("\n");
        uart_puts("  errors:      "); uart_puts(utoa(s->errors)); uart_puts("\n");
    }
}

/* Shell wrappers ------------------------------------------------------- */

int sepos_ping(void) {
    if (sepos_ensure_init() != SEP_OK) return sep_init_result;
    return sep_ping(&sep_drv);
}

int sepos_get_random(void) {
    if (sepos_ensure_init() != SEP_OK) return sep_init_result;
    uint8_t random[32];
    int rc = sep_get_random(&sep_drv, random);
    if (rc == SEP_OK) {
        uart_puts("SEP random: ");
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
    /* pongoOS seprom_boot_tz0 also configures the integrity tree first. */
    int rc = sep_config_integrity_tree(&sep_drv, 0);
    if (rc != SEP_OK) {
        uart_puts("integrity tree config failed (");
        uart_puts(utoa(rc));
        uart_puts(")\n");
        return rc;
    }
    rc = sep_boot_tz0(&sep_drv);
    if (rc != SEP_OK) {
        uart_puts("TZ0 boot failed (");
        uart_puts(utoa(rc));
        uart_puts(")\n");
    }
    return rc;
}

int sepos_send_sepos(uint64_t image_phys, uint32_t image_size, uint64_t entry_phys) {
    if (sepos_ensure_init() != SEP_OK) return sep_init_result;
    return sep_send_sepos(&sep_drv, image_phys, image_size, entry_phys);
}

int sepos_send_art(uint64_t art_phys, uint32_t art_size) {
    if (sepos_ensure_init() != SEP_OK) return sep_init_result;
    return sep_send_art(&sep_drv, art_phys, art_size);
}

int sepos_enable_irq(void) {
    if (sepos_ensure_init() != SEP_OK) return sep_init_result;
    sep_enable_interrupt(&sep_drv);
    return SEP_OK;
}