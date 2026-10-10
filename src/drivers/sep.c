#include "sep.h"
#include "uart.h"
#include "timer.h"
#include "util.h"
#include <stddef.h>

static inline uint32_t sep_read(volatile uint32_t *base, uint32_t offset) {
    return base[offset / 4];
}

static inline void sep_write(volatile uint32_t *base, uint32_t offset, uint32_t val) {
    base[offset / 4] = val;
}

/* Per-opcode timeout table */
static const struct {
    uint16_t opcode;
    uint32_t timeout_us;
} sep_timeout_table[] = {
    { SEP_OP_PING,         SEP_TIMEOUT_PING },
    { SEP_OP_GET_RANDOM,   SEP_TIMEOUT_RANDOM },
    { SEP_OP_BOOT_TZ0,     SEP_TIMEOUT_BOOT_TZ0 },
    { SEP_OP_SEND_SEPOS,   SEP_TIMEOUT_SEND_SEPOS },
    { SEP_OP_SEND_ART,     SEP_TIMEOUT_SEND_SEPOS },
};

static int sep_timeout_index(uint16_t opcode) {
    for (size_t i = 0; i < sizeof(sep_timeout_table) / sizeof(sep_timeout_table[0]); i++) {
        if (sep_timeout_table[i].opcode == opcode) return (int)i;
    }
    return -1;
}

static uint32_t sep_get_timeout_for_opcode(const struct sep_driver *drv, uint16_t opcode) {
    int index = sep_timeout_index(opcode);
    if (index >= 0 && drv->opcode_timeout_us[index] != 0)
        return drv->opcode_timeout_us[index];
    if (index >= 0) return sep_timeout_table[index].timeout_us;
    return drv->timeout_us;
}

int sep_init(struct sep_driver *drv, uint64_t base_addr) {
    if (!drv) return SEP_ERR_INVALID;
#ifdef SEP_TEST_MMIO
    drv->base = (volatile uint32_t *)base_addr;
#else
    /* The A11 SecureROM literal establishes an aperture, not this driver's
     * FIFO register map. Keep the production path inert until that map and
     * the mailbox sub-window are reconciled against measured evidence. */
    (void)base_addr;
    drv->base = NULL;
#endif
    drv->timeout_us = SEP_TIMEOUT_DEFAULT;
    drv->irq_mode = false;
    for (size_t i = 0; i < sizeof(drv->opcode_timeout_us) / sizeof(drv->opcode_timeout_us[0]); i++)
        drv->opcode_timeout_us[i] = 0;
    sep_reset_stats(drv);
#ifndef SEP_TEST_MMIO
    return SEP_ERR_UNSUPPORTED;
#endif
    return SEP_OK;
}

void sep_deinit(struct sep_driver *drv) {
    if (drv) {
        sep_clear_doorbells(drv);
        drv->base = NULL;
    }
}

void sep_set_timeout(struct sep_driver *drv, uint16_t opcode, uint32_t timeout_us) {
    if (!drv) return;
    int index = sep_timeout_index(opcode);
    if (index >= 0) drv->opcode_timeout_us[index] = timeout_us;
}

void sep_set_default_timeout(struct sep_driver *drv, uint32_t timeout_us) {
    if (drv) drv->timeout_us = timeout_us;
}

const sep_stats_t *sep_get_stats(const struct sep_driver *drv) {
    return drv ? &drv->stats : NULL;
}

void sep_reset_stats(struct sep_driver *drv) {
    if (drv) {
        drv->stats.commands_sent = 0;
        drv->stats.replies_received = 0;
        drv->stats.timeouts = 0;
        drv->stats.naks = 0;
        drv->stats.busy_retries = 0;
        drv->stats.errors = 0;
    }
}

void sep_clear_doorbells(struct sep_driver *drv) {
    if (!drv || !drv->base) return;
    /* Clear any pending AP→IOP doorbell */
    sep_write(drv->base, SEP_AP2IOP_DB, 0);
    /* Ack any pending IOP→AP doorbell by reading then writing 1 */
    (void)sep_read(drv->base, SEP_IOP2AP_DB);
    sep_write(drv->base, SEP_IOP2AP_DB, 1);
}

uint32_t sep_get_status(struct sep_driver *drv) {
    if (!drv || !drv->base) return 0;
    return sep_read(drv->base, SEP_STATUS);
}

int sep_check_hw_error(struct sep_driver *drv) {
    if (!drv || !drv->base) return SEP_ERR_INVALID;
    uint32_t status = sep_get_status(drv);
    /* Check for error bits in status register (implementation-specific) */
    if (status & 0x80000000) return SEP_ERR_HW;
    return SEP_OK;
}

static int sep_wait_for_doorbell_clear(struct sep_driver *drv, uint32_t timeout_us) {
    uint32_t timeout = timeout_us / 10;
    while (timeout--) {
        if (sep_read(drv->base, SEP_AP2IOP_DB) == 0) return SEP_OK;
        drv->stats.busy_retries++;
        timer_sleep_us(10);
    }
    return SEP_ERR_BUSY;
}

static int sep_wait_for_reply(struct sep_driver *drv, uint32_t timeout_us,
                              uint64_t *out_reply) {
    uint32_t timeout = timeout_us;
    while (timeout--) {
        uint64_t reply = (uint64_t)sep_read(drv->base, SEP_IOP2AP_MSG0) |
                         ((uint64_t)sep_read(drv->base, SEP_IOP2AP_MSG1) << 32);
        if (reply != 0) {
            if (out_reply) *out_reply = reply;
            return SEP_OK;
        }
        timer_sleep_us(1);
    }
    return SEP_ERR_TIMEOUT;
}

/* Compose message from opcode and payload */
static uint64_t sep_compose_message(uint16_t opcode, const uint8_t *payload, uint32_t payload_len) {
    uint64_t msg = ((uint64_t)opcode << 32);
    if (payload && payload_len > 0) {
        uint32_t payload32 = 0;
        if (payload_len >= 4) {
            payload32 = payload[0] | (payload[1] << 8) | (payload[2] << 16) | (payload[3] << 24);
        } else {
            for (uint32_t i = 0; i < payload_len; i++) {
                payload32 |= (payload[i] << (i * 8));
            }
        }
        msg |= payload32;
    }
    return msg;
}

/* Parse reply into opcode and payload */
static void sep_parse_reply(uint64_t reply, uint16_t *out_opcode, uint32_t *out_payload) {
    if (out_opcode) *out_opcode = (reply >> 32) & 0xFFFF;
    if (out_payload) *out_payload = reply & 0xFFFFFFFF;
}

int sep_send_command(struct sep_driver *drv,
                     uint16_t opcode,
                     const uint8_t *payload, uint32_t payload_len,
                     uint8_t *reply_data, uint32_t *reply_len) {
    if (!drv || !drv->base) return SEP_ERR_INVALID;
    if (opcode == 0) return SEP_ERR_INVALID;

    uint32_t timeout = sep_get_timeout_for_opcode(drv, opcode);

    /* Check hardware error before sending */
    int hw_err = sep_check_hw_error(drv);
    if (hw_err != SEP_OK) {
        drv->stats.errors++;
        return hw_err;
    }

    /* Wait for doorbell to be clear */
    int rc = sep_wait_for_doorbell_clear(drv, timeout);
    if (rc != SEP_OK) {
        drv->stats.errors++;
        return rc;
    }

    /* Compose and write message */
    uint64_t msg = sep_compose_message(opcode, payload, payload_len);
    sep_write(drv->base, SEP_AP2IOP_MSG0, msg & 0xFFFFFFFF);
    sep_write(drv->base, SEP_AP2IOP_MSG1, (msg >> 32) & 0xFFFFFFFF);

    /* Ring doorbell */
    sep_write(drv->base, SEP_AP2IOP_DB, 1);
    drv->stats.commands_sent++;

    /* Wait for reply */
    uint64_t reply;
    rc = sep_wait_for_reply(drv, timeout, &reply);
    if (rc != SEP_OK) {
        drv->stats.timeouts++;
        return rc;
    }

    /* Ack reply doorbell */
    sep_write(drv->base, SEP_IOP2AP_DB, 1);
    drv->stats.replies_received++;

    /* Parse reply */
    uint16_t reply_opcode;
    uint32_t reply_payload;
    sep_parse_reply(reply, &reply_opcode, &reply_payload);

    if (reply_opcode == 0xFFFF) {
        drv->stats.naks++;
        return SEP_ERR_NAK;
    }

    if (reply_data && reply_len) {
        *reply_len = 4;
        reply_data[0] = reply_payload & 0xFF;
        reply_data[1] = (reply_payload >> 8) & 0xFF;
        reply_data[2] = (reply_payload >> 16) & 0xFF;
        reply_data[3] = (reply_payload >> 24) & 0xFF;
    }

    return SEP_OK;
}

/* Extended send using descriptor protocol for payloads > 4 bytes */
int sep_send_extended(struct sep_driver *drv,
                      uint16_t opcode,
                      const void *payload, uint32_t payload_len) {
    if (!drv || !payload || payload_len == 0) return SEP_ERR_INVALID;
    if (payload_len > 4096) return SEP_ERR_OVERFLOW;
    (void)opcode;
    /* No descriptor layout or multi-message transfer protocol has been
     * established. Never disguise repeated single-word messages as a bulk
     * image transfer. */
    return SEP_ERR_UNSUPPORTED;
}

int sep_poll(struct sep_driver *drv,
             uint16_t *out_opcode,
             uint8_t *out_data, uint32_t *out_len) {
    if (!drv || !drv->base) return SEP_ERR_INVALID;

    uint64_t reply = (uint64_t)sep_read(drv->base, SEP_IOP2AP_MSG0) |
                     ((uint64_t)sep_read(drv->base, SEP_IOP2AP_MSG1) << 32);
    if (reply == 0) return SEP_ERR_TIMEOUT;

    uint16_t opcode;
    uint32_t payload;
    sep_parse_reply(reply, &opcode, &payload);

    if (out_opcode) *out_opcode = opcode;
    if (out_data && out_len) {
        *out_len = 4;
        out_data[0] = payload & 0xFF;
        out_data[1] = (payload >> 8) & 0xFF;
        out_data[2] = (payload >> 16) & 0xFF;
        out_data[3] = (payload >> 24) & 0xFF;
    }

    /* Note: does NOT ack the doorbell — caller must call sep_ack_reply() */
    return SEP_OK;
}

void sep_ack_reply(struct sep_driver *drv) {
    if (drv && drv->base) {
        sep_write(drv->base, SEP_IOP2AP_DB, 1);
    }
}

/* Convenience helpers */

int sep_ping(struct sep_driver *drv) {
    return sep_send_command(drv, SEP_OP_PING, NULL, 0, NULL, NULL);
}

int sep_get_random(struct sep_driver *drv, uint8_t out[32]) {
    if (!drv || !out) return SEP_ERR_INVALID;

    for (int i = 0; i < 8; i++) {
        uint8_t reply[4];
        uint32_t len;
        int rc = sep_send_command(drv, SEP_OP_GET_RANDOM, NULL, 0, reply, &len);
        if (rc != SEP_OK) return rc;
        if (len != 4) return SEP_ERR_MALFORMED;
        out[i*4 + 0] = reply[0];
        out[i*4 + 1] = reply[1];
        out[i*4 + 2] = reply[2];
        out[i*4 + 3] = reply[3];
    }
    return SEP_OK;
}

int sep_boot_tz0(struct sep_driver *drv, uint64_t load_addr_page) {
    if (!drv) return SEP_ERR_INVALID;
    uint8_t payload[4];
    payload[0] = load_addr_page & 0xFF;
    payload[1] = (load_addr_page >> 8) & 0xFF;
    payload[2] = (load_addr_page >> 16) & 0xFF;
    payload[3] = (load_addr_page >> 24) & 0xFF;
    return sep_send_command(drv, SEP_OP_BOOT_TZ0, payload, 4, NULL, NULL);
}

int sep_send_sepos(struct sep_driver *drv, uint64_t image_base, uint32_t image_size, uint64_t entry_page) {
    if (!drv) return SEP_ERR_INVALID;
    if (image_base & 0xF) return SEP_ERR_UNALIGNED;  /* Must be 16-byte aligned */

    /* SEPOS metadata structure per pongoOS:
     * word 0: image_base >> 12 (page number)
     * word 1: image_size
     * word 2: entry_page
     * word 3: flags (0)
     */
    uint32_t metadata[4];
    metadata[0] = (uint32_t)(image_base >> 12);
    metadata[1] = image_size;
    metadata[2] = (uint32_t)entry_page;
    metadata[3] = 0;

    return sep_send_extended(drv, SEP_OP_SEND_SEPOS, metadata, sizeof(metadata));
}

int sep_send_art(struct sep_driver *drv, uint64_t art_base, uint32_t art_size) {
    if (!drv) return SEP_ERR_INVALID;
    if (art_base & 0xF) return SEP_ERR_UNALIGNED;

    uint32_t metadata[4];
    metadata[0] = (uint32_t)(art_base >> 12);
    metadata[1] = art_size;
    metadata[2] = 0;
    metadata[3] = 0;

    return sep_send_extended(drv, SEP_OP_SEND_ART, metadata, sizeof(metadata));
}
