#include "sep.h"
#include "uart.h"
#include "timer.h"
#include "util.h"
#include <stddef.h>

static inline uint32_t sep_read32(volatile uint32_t *base, uint32_t offset) {
    return base[offset / 4];
}

static inline void sep_write32(volatile uint32_t *base, uint32_t offset, uint32_t val) {
    base[offset / 4] = val;
}

static inline uint64_t sep_read64(volatile uint32_t *base, uint32_t offset) {
    return (uint64_t)sep_read32(base, offset) |
           ((uint64_t)sep_read32(base, offset + 4) << 32);
}

static inline void sep_write64(volatile uint32_t *base, uint32_t offset, uint64_t val) {
    sep_write32(base, offset, (uint32_t)(val & 0xFFFFFFFFu));
    sep_write32(base, offset + 4, (uint32_t)(val >> 32));
}

int sep_init(struct sep_driver *drv, uint64_t base_addr) {
    if (!drv) return SEP_ERR_INVALID;
    drv->base = (volatile uint32_t *)base_addr;
    drv->base_addr = base_addr;
    drv->timeout_us = 1000000;  /* 1 s default */
    drv->irq_mode = false;
    sep_reset_stats(drv);
    sep_clear_doorbells(drv);
    return SEP_OK;
}

void sep_deinit(struct sep_driver *drv) {
    if (drv) {
        sep_disable_interrupt(drv);
        drv->base = NULL;
        drv->base_addr = 0;
    }
}

void sep_enable_interrupt(struct sep_driver *drv) {
    if (!drv || !drv->base) return;
    sep_write32(drv->base, SEP_MBOX_EN_INT, SEP_MBOX_INT_ENABLE);
    drv->irq_mode = true;
}

void sep_disable_interrupt(struct sep_driver *drv) {
    if (!drv || !drv->base) return;
    sep_write32(drv->base, SEP_MBOX_DIS_INT, SEP_MBOX_INT_ENABLE);
    drv->irq_mode = false;
}

uint32_t sep_recv_status(struct sep_driver *drv) {
    if (!drv || !drv->base) return 0;
    return sep_read32(drv->base, SEP_MBOX_RECV_STS);
}

bool sep_recv_queue_empty(struct sep_driver *drv) {
    return (sep_recv_status(drv) & SEP_MBOX_QUEUE_EMPTY) != 0;
}

void sep_clear_doorbells(struct sep_driver *drv) {
    if (!drv || !drv->base) return;
    /* Disable the inbox interrupt and drain any pending send status bit. */
    sep_write32(drv->base, SEP_MBOX_DIS_INT, SEP_MBOX_INT_ENABLE);
    /* The 64-bit send word is cleared; pongoOS does not ack it explicitly. */
    sep_write64(drv->base, SEP_MBOX_SND0, 0);
}

uint64_t sep_msg_encode(struct sep_msg *m) {
    uint64_t v = 0;
    v |= (uint64_t)m->ep;
    v |= (uint64_t)m->tag << 8;
    v |= (uint64_t)m->opcode << 16;
    v |= (uint64_t)m->param << 24;
    v |= (uint64_t)m->data << 32;
    return v;
}

void sep_msg_decode(uint64_t raw, struct sep_msg *m) {
    if (!m) return;
    m->ep     = (uint8_t)(raw & 0xFF);
    m->tag    = (uint8_t)((raw >> 8) & 0xFF);
    m->opcode = (uint8_t)((raw >> 16) & 0xFF);
    m->param  = (uint8_t)((raw >> 24) & 0xFF);
    m->data   = (uint32_t)(raw >> 32);
}

static uint32_t sep_timeout_for(struct sep_driver *drv, uint8_t opcode) {
    switch (opcode) {
    case SEP_OP_PING:           return 10000;
    case SEP_OP_GET_RANDOM:     return 100000;
    case SEP_OP_BOOT_TZ0:       return 5000000;
    case SEP_OP_SEND_SEPOS:     return 10000000;
    case SEP_OP_INTEGRITY_TREE: return 10000000;
    default:                    return drv->timeout_us;
    }
}

static int sep_wait_send_ready(struct sep_driver *drv, uint32_t timeout_us) {
    uint32_t spins = timeout_us / 10;
    while (spins--) {
        uint32_t sts = sep_read32(drv->base, SEP_MBOX_SND_STS);
        /* pongoOS does not document snd_sts bits beyond enabling; treat any
         * non-busy state as ready once the previous send is drained. */
        (void)sts;
        return SEP_OK;
    }
    return SEP_ERR_BUSY;
}

static int sep_wait_reply(struct sep_driver *drv, uint32_t timeout_us, uint64_t *out) {
    uint32_t spins = timeout_us;
    while (spins--) {
        if (!sep_recv_queue_empty(drv)) {
            *out = sep_read64(drv->base, SEP_MBOX_RECV0);
            return SEP_OK;
        }
        timer_sleep_us(1);
    }
    return SEP_ERR_TIMEOUT;
}

int sep_send_raw(struct sep_driver *drv,
                 uint8_t ep, uint8_t tag, uint8_t opcode, uint8_t param, uint32_t data,
                 uint64_t *out_reply) {
    if (!drv || !drv->base) return SEP_ERR_INVALID;
    if (opcode == 0) return SEP_ERR_INVALID;

    uint32_t timeout = sep_timeout_for(drv, opcode);

    int rc = sep_wait_send_ready(drv, timeout);
    if (rc != SEP_OK) { drv->stats.errors++; return rc; }

    struct sep_msg m = { .ep = ep, .tag = tag, .opcode = opcode, .param = param, .data = data };
    uint64_t wire = sep_msg_encode(&m);

    /* pongoOS writes snd0 = value, snd1 = 0 on the 64-bit mailbox. */
    sep_write64(drv->base, SEP_MBOX_SND0, wire);
    sep_write64(drv->base, SEP_MBOX_SND1, 0);
    drv->stats.commands_sent++;

    uint64_t reply = 0;
    rc = sep_wait_reply(drv, timeout, &reply);
    if (rc != SEP_OK) { drv->stats.timeouts++; return rc; }

    drv->stats.replies_received++;

    struct sep_msg r;
    sep_msg_decode(reply, &r);

    if (r.ep == SEP_EP_SEPROM && r.opcode == SEP_OP_SEPROM_PANIC) {
        drv->stats.panics++;
        return SEP_ERR_PANIC;
    }

    if (out_reply) *out_reply = reply;
    return SEP_OK;
}

int sep_poll(struct sep_driver *drv, uint64_t *out_reply) {
    if (!drv || !drv->base) return SEP_ERR_INVALID;
    if (sep_recv_queue_empty(drv)) return SEP_ERR_QUEUE_EMPTY;
    if (out_reply) *out_reply = sep_read64(drv->base, SEP_MBOX_RECV0);
    return SEP_OK;
}

/* No sep_ack_reply(). Neither pongoOS mailbox layout has a reply doorbell,
 * so there is nothing to ack: reading recv0 in sep_poll() is the whole
 * consumption path, exactly as sep_check_mailbox() reads recv0 and returns.
 * An earlier revision of this file provided one that re-read recv0, which
 * looked like an ack and was not -- a register read that pops a FIFO entry
 * is a consume, and calling it a second time would advance the queue. */

const struct sep_stats *sep_get_stats(const struct sep_driver *drv) {
    return drv ? &drv->stats : NULL;
}

void sep_reset_stats(struct sep_driver *drv) {
    if (!drv) return;
    drv->stats.commands_sent = 0;
    drv->stats.replies_received = 0;
    drv->stats.timeouts = 0;
    drv->stats.naks = 0;
    drv->stats.busy_retries = 0;
    drv->stats.errors = 0;
    drv->stats.panics = 0;
}

/* ----------------------------------------------------------------------- */
/* Typed helpers                                                            */
/* ----------------------------------------------------------------------- */

int sep_ping(struct sep_driver *drv) {
    return sep_send_raw(drv, SEP_EP_SEPROM, 0, SEP_OP_PING, 0, 0, NULL);
}

int sep_get_random(struct sep_driver *drv, uint8_t out[32]) {
    if (!drv || !out) return SEP_ERR_INVALID;
    /* pongoOS sends opcode 16 and reads one 32-bit word per reply; it calls
     * seprom_rand() once and takes rnd_val. Collect 8 words for 32 bytes. */
    for (int i = 0; i < 8; i++) {
        uint64_t reply = 0;
        int rc = sep_send_raw(drv, SEP_EP_SEPROM, 0, SEP_OP_GET_RANDOM, 0, 0, &reply);
        if (rc != SEP_OK) return rc;
        struct sep_msg r;
        sep_msg_decode(reply, &r);
        if (r.opcode != (uint8_t)(SEP_OP_GET_RANDOM + SEP_REPLY_OFFSET))
            return SEP_ERR_MALFORMED;
        uint32_t v = r.data;
        out[i*4 + 0] = (uint8_t)(v & 0xFF);
        out[i*4 + 1] = (uint8_t)((v >> 8) & 0xFF);
        out[i*4 + 2] = (uint8_t)((v >> 16) & 0xFF);
        out[i*4 + 3] = (uint8_t)((v >> 24) & 0xFF);
    }
    return SEP_OK;
}

int sep_boot_tz0(struct sep_driver *drv) {
    if (!drv || !drv->base) return SEP_ERR_INVALID;
    return sep_send_raw(drv, SEP_EP_SEPROM, 0, SEP_OP_BOOT_TZ0, 0, 0, NULL);
}

int sep_send_sepos(struct sep_driver *drv, uint64_t image_phys, uint32_t image_size, uint64_t entry_phys) {
    if (!drv) return SEP_ERR_INVALID;
    if (image_phys & 0xFFF) return SEP_ERR_INVALID;  /* page-aligned */
    /* pongoOS: seprom_execute_opcode(6, mode, vatophys(firmware) >> 12).
     * The SEP reads the image header from the page in data; size and entry
     * are not carried in the message. The parameters are accepted and
     * checked, then deliberately not sent — pongoOS does not send them. */
    (void)image_size;
    (void)entry_phys;
    uint32_t page = (uint32_t)(image_phys >> 12);
    uint8_t param = 0;  /* mode 0 */
    return sep_send_raw(drv, SEP_EP_SEPROM, 0, SEP_OP_SEND_SEPOS, param, page, NULL);
}

int sep_send_art(struct sep_driver *drv, uint64_t art_phys, uint32_t art_size) {
    if (!drv) return SEP_ERR_INVALID;
    if (art_phys & 0xFFF) return SEP_ERR_INVALID;
    (void)art_size;  /* not carried in the message */
    uint32_t page = (uint32_t)(art_phys >> 12);
    return sep_send_raw(drv, SEP_EP_SEPROM, 0, SEP_OP_SEND_ART, 0, page, NULL);
}

int sep_config_integrity_tree(struct sep_driver *drv, uint32_t pages) {
    if (!drv) return SEP_ERR_INVALID;
    /* pongoOS: seprom_execute_opcode(17, 0, tree_size >> 12 in 0x400 units). */
    uint32_t units = pages / 0x400;
    return sep_send_raw(drv, SEP_EP_SEPROM, 0, SEP_OP_INTEGRITY_TREE, 0, units, NULL);
}