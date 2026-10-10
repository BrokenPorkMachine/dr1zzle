/*
 * SEP driver unit tests — host-side, fake MMIO.
 *
 * Audit source: pongoOS src/drivers/sep/sep.c. These tests pin the register
 * offsets, the message framing and the reply convention against the values
 * that file establishes, so a future edit that drifts from the reference
 * fails here rather than on hardware.
 *
 * Run via: make host-test (python3 -m unittest tests.test_sep)
 */

#include "sep.h"
#include "uart.h"
#include "string.h"
#include "util.h"
#include <stdint.h>
#include <stdlib.h>

#define FAKE_MMIO_SIZE 0x9000
static uint8_t fake_mmio[FAKE_MMIO_SIZE];

static void fake_write32(uint32_t offset, uint32_t val) {
    if (offset + 3 < FAKE_MMIO_SIZE) *(uint32_t *)(fake_mmio + offset) = val;
}
static uint32_t fake_read32(uint32_t offset) {
    if (offset + 3 < FAKE_MMIO_SIZE) return *(uint32_t *)(fake_mmio + offset);
    return 0;
}
static void fake_write64(uint32_t offset, uint64_t val) {
    fake_write32(offset, (uint32_t)(val & 0xFFFFFFFFu));
    fake_write32(offset + 4, (uint32_t)(val >> 32));
}
static uint64_t fake_read64(uint32_t offset) {
    return (uint64_t)fake_read32(offset) | ((uint64_t)fake_read32(offset + 4) << 32);
}

static void reset_fake(void) { memset(fake_mmio, 0, FAKE_MMIO_SIZE); }

static struct sep_driver *make_drv(void) {
    struct sep_driver *d = malloc(sizeof(*d));
    sep_init(d, (uint64_t)fake_mmio);
    d->timeout_us = 1000;
    return d;
}
static void drop_drv(struct sep_driver *d) { free(d); }

/* Queue one reply into recv0 and clear the queue-empty bit in recv_sts. */
static void queue_reply(uint8_t ep, uint8_t tag, uint8_t opcode, uint8_t param, uint32_t data) {
    struct sep_msg m = { .ep = ep, .tag = tag, .opcode = opcode, .param = param, .data = data };
    fake_write64(SEP_MBOX_RECV0, sep_msg_encode(&m));
    fake_write32(SEP_MBOX_RECV_STS, fake_read32(SEP_MBOX_RECV_STS) & ~SEP_MBOX_QUEUE_EMPTY);
}

/* --- register offsets ------------------------------------------------- */

static int test_register_offsets_match_pongoos(void) {
    /* pongoOS struct mailbox_registers64, 64-bit layout. */
    if (SEP_MBOX_DIS_INT != 0x8100) return 1;
    if (SEP_MBOX_EN_INT  != 0x8104) return 2;
    if (SEP_MBOX_SND_STS != 0x8108) return 3;
    if (SEP_MBOX_RECV_STS != 0x810C) return 4;
    if (SEP_MBOX_SND0    != 0x8800) return 5;
    if (SEP_MBOX_RECV0   != 0x8830) return 6;
    if (SEP_MBOX_QUEUE_EMPTY != 0x20000u) return 7;
    if (SEP_MBOX_INT_ENABLE != 0x1000u) return 8;
    return 0;
}

/* --- message framing -------------------------------------------------- */

static int test_msg_encode_decode_roundtrip(void) {
    struct sep_msg m = { .ep = 255, .tag = 0x42, .opcode = 16, .param = 7, .data = 0xDEADBEEF };
    uint64_t w = sep_msg_encode(&m);
    /* byte order: ep | tag<<8 | opcode<<16 | param<<24 | data<<32 */
    uint64_t expect = 0xDEADBEEF00000000ULL | 0x00000000071042FFULL;
    if (w != expect) return 1;
    struct sep_msg out;
    sep_msg_decode(w, &out);
    if (out.ep != 255 || out.tag != 0x42 || out.opcode != 16 || out.param != 7 || out.data != 0xDEADBEEF) return 2;
    return 0;
}

static int test_msg_decode_null_safe(void) {
    sep_msg_decode(0, NULL);   /* must not crash */
    return 0;
}

/* --- framing pinned against real captured traces -----------------------
 *
 * These words are from AsahiLinux HW:SEP, captured on an Apple Silicon SEP
 * with the SEPTracer. They are hardware trace data, not a description of
 * the protocol, which makes them the strongest evidence available for the
 * framing -- stronger than pongoOS's struct and much stronger than prose.
 *
 * The wiki's prose says "bits 16-24 - message type" and "bits 25-31 - message
 * parameters", which would put the type/param boundary one bit lower than
 * pongoOS's packed struct. The wiki's own worked examples decode bytewise,
 * and these do too, so the prose is the inaccuracy. Both of these tests
 * would fail under the prose reading. */
static int test_framing_matches_captured_sep_traces(void) {
    struct sep_msg m;

    /* [stac] ping: EP=0x18, TAG=0xfc, TYPE=0xf, PARAM=0x0, DATA=0x0 */
    sep_msg_decode(0x00000000000ffc18ULL, &m);
    if (m.ep != 0x18 || m.tag != 0xfc || m.opcode != 0x0f || m.param != 0 || m.data != 0)
        return 1;

    /* [xarm] locker request: EP=0x13, TAG=0x2, TYPE=0x0, PARAM=0x0, DATA=0x100 */
    sep_msg_decode(0x0000010000000213ULL, &m);
    if (m.ep != 0x13 || m.tag != 0x02 || m.opcode != 0x00 || m.param != 0 || m.data != 0x100)
        return 2;

    /* [xart] fetch: EP=0x13, TAG=0x1, TYPE=0x0, PARAM=0x0, DATA=0x0 */
    sep_msg_decode(0x0000000000000113ULL, &m);
    if (m.ep != 0x13 || m.tag != 0x01 || m.opcode != 0x00 || m.param != 0 || m.data != 0)
        return 3;

    return 0;
}

/* --- ping -------------------------------------------------------------- */

static int test_ping_writes_seprom_opcode_one(void) {
    reset_fake();
    struct sep_driver *d = make_drv();
    /* pongoOS seprom_ping: seprom_execute_opcode(1, 0, 0) => ep 255, opcode 1. */
    queue_reply(SEP_EP_SEPROM, 0, (uint8_t)(SEP_OP_PING + SEP_REPLY_OFFSET), 0, 0);

    int rc = sep_ping(d);
    if (rc != SEP_OK) { drop_drv(d); return 1; }

    uint64_t sent = fake_read64(SEP_MBOX_SND0);
    struct sep_msg m; sep_msg_decode(sent, &m);
    if (m.ep != SEP_EP_SEPROM) { drop_drv(d); return 2; }
    if (m.opcode != SEP_OP_PING) { drop_drv(d); return 3; }
    if (m.tag != 0 || m.param != 0 || m.data != 0) { drop_drv(d); return 4; }
    /* snd1 must be written zero, as pongoOS does. */
    if (fake_read64(SEP_MBOX_SND1) != 0) { drop_drv(d); return 5; }

    drop_drv(d);
    return 0;
}

static int test_ping_timeout_when_queue_empty(void) {
    reset_fake();
    struct sep_driver *d = make_drv();
    fake_write32(SEP_MBOX_RECV_STS, SEP_MBOX_QUEUE_EMPTY);  /* empty by default */

    int rc = sep_ping(d);
    if (rc != SEP_ERR_TIMEOUT) { drop_drv(d); return 1; }
    if (sep_get_stats(d)->timeouts != 1) { drop_drv(d); return 2; }

    drop_drv(d);
    return 0;
}

/* --- get_random -------------------------------------------------------- */

static int test_get_random_uses_opcode_16_and_reply_offset(void) {
    reset_fake();
    struct sep_driver *d = make_drv();

    /* pongoOS seprom_rand: opcode 16; the reply arrives with opcode 116. */
    queue_reply(SEP_EP_SEPROM, 0, (uint8_t)(SEP_OP_GET_RANDOM + SEP_REPLY_OFFSET), 0, 0x11223344);
    /* Top up the queue for the remaining seven words. */
    for (int i = 1; i < 8; i++) {
        struct sep_msg m = { .ep = SEP_EP_SEPROM, .tag = 0,
                             .opcode = (uint8_t)(SEP_OP_GET_RANDOM + SEP_REPLY_OFFSET),
                             .param = 0, .data = (uint32_t)(0x1000 * i) };
        fake_write64(SEP_MBOX_RECV0 + i * 8, sep_msg_encode(&m));
        fake_write32(SEP_MBOX_RECV_STS, fake_read32(SEP_MBOX_RECV_STS) & ~SEP_MBOX_QUEUE_EMPTY);
    }

    uint8_t out[32];
    int rc = sep_get_random(d, out);
    if (rc != SEP_OK) { drop_drv(d); return 1; }
    if (out[0] != 0x44 || out[1] != 0x33 || out[2] != 0x22 || out[3] != 0x11) { drop_drv(d); return 2; }

    drop_drv(d);
    return 0;
}

/* --- send_sepos -------------------------------------------------------- */

static int test_send_sepos_sends_page_number(void) {
    reset_fake();
    struct sep_driver *d = make_drv();
    /* pongoOS: seprom_execute_opcode(6, mode, vatophys(fw) >> 12). */
    queue_reply(SEP_EP_SEPROM, 0, (uint8_t)(SEP_OP_SEND_SEPOS + SEP_REPLY_OFFSET), 0, 0);

    uint64_t image_phys = 0x19C000000ULL;
    int rc = sep_send_sepos(d, image_phys, 0x10000, 0);
    if (rc != SEP_OK) { drop_drv(d); return 1; }

    uint64_t sent = fake_read64(SEP_MBOX_SND0);
    struct sep_msg m; sep_msg_decode(sent, &m);
    if (m.ep != SEP_EP_SEPROM) { drop_drv(d); return 2; }
    if (m.opcode != SEP_OP_SEND_SEPOS) { drop_drv(d); return 3; }
    if (m.data != (uint32_t)(image_phys >> 12)) { drop_drv(d); return 4; }

    drop_drv(d);
    return 0;
}

static int test_send_sepos_rejects_unaligned(void) {
    reset_fake();
    struct sep_driver *d = make_drv();
    if (sep_send_sepos(d, 0x19C000001ULL, 0x10000, 0) != SEP_ERR_INVALID) { drop_drv(d); return 1; }
    drop_drv(d);
    return 0;
}

/* --- integrity tree ---------------------------------------------------- */

static int test_integrity_tree_opcode_17(void) {
    reset_fake();
    struct sep_driver *d = make_drv();
    queue_reply(SEP_EP_SEPROM, 0, (uint8_t)(SEP_OP_INTEGRITY_TREE + SEP_REPLY_OFFSET), 0, 0);

    int rc = sep_config_integrity_tree(d, 0x4000);
    if (rc != SEP_OK) { drop_drv(d); return 1; }

    uint64_t sent = fake_read64(SEP_MBOX_SND0);
    struct sep_msg m; sep_msg_decode(sent, &m);
    if (m.opcode != SEP_OP_INTEGRITY_TREE) { drop_drv(d); return 2; }
    if (m.data != 0x4000 / 0x400) { drop_drv(d); return 3; }

    drop_drv(d);
    return 0;
}

/* --- panic -------------------------------------------------------------- */

static int test_seprom_panic_detected(void) {
    reset_fake();
    struct sep_driver *d = make_drv();
    /* SEPROM panic: endpoint 255, opcode 255 (pongoOS sep_handle_msg_from_seprom). */
    queue_reply(SEP_EP_SEPROM, 0, SEP_OP_SEPROM_PANIC, 0, 0);

    int rc = sep_ping(d);
    if (rc != SEP_ERR_PANIC) { drop_drv(d); return 1; }
    if (sep_get_stats(d)->panics != 1) { drop_drv(d); return 2; }

    drop_drv(d);
    return 0;
}

/* --- interrupt control -------------------------------------------------- */

static int test_interrupt_enable_disable(void) {
    reset_fake();
    struct sep_driver *d = make_drv();
    sep_enable_interrupt(d);
    if (fake_read32(SEP_MBOX_EN_INT) != SEP_MBOX_INT_ENABLE) { drop_drv(d); return 1; }
    if (!d->irq_mode) { drop_drv(d); return 2; }
    sep_disable_interrupt(d);
    if (fake_read32(SEP_MBOX_DIS_INT) != SEP_MBOX_INT_ENABLE) { drop_drv(d); return 3; }
    if (d->irq_mode) { drop_drv(d); return 4; }
    drop_drv(d);
    return 0;
}

/* --- queue status ------------------------------------------------------- */

static int test_queue_empty_bit(void) {
    reset_fake();
    struct sep_driver *d = make_drv();
    fake_write32(SEP_MBOX_RECV_STS, SEP_MBOX_QUEUE_EMPTY);
    if (!sep_recv_queue_empty(d)) { drop_drv(d); return 1; }
    fake_write32(SEP_MBOX_RECV_STS, 0);
    if (sep_recv_queue_empty(d)) { drop_drv(d); return 2; }
    drop_drv(d);
    return 0;
}

static int test_register_set_is_exactly_pongoos(void) {
    /* The complete pongoOS struct mailbox_registers64 field set. If a future
     * edit adds a register to this driver's map that is not here, an ack
     * doorbell or completion flag has been invented again -- which is exactly
     * what sep_ack_reply() was. Pin the set, not just the values. */
    if (SEP_MBOX_DIS_INT  != 0x8100) return 1;
    if (SEP_MBOX_EN_INT   != 0x8104) return 2;
    if (SEP_MBOX_SND_STS  != 0x8108) return 3;
    if (SEP_MBOX_RECV_STS != 0x810C) return 4;
    if (SEP_MBOX_SND0     != 0x8800) return 5;
    if (SEP_MBOX_SND1     != 0x8808) return 6;
    if (SEP_MBOX_RECV0    != 0x8830) return 7;
    if (SEP_MBOX_RECV1    != 0x8838) return 8;

    /* Every offset in the map must be one of those eight. Counting them is
     * the cheapest way to fail if a ninth is added. */
    int count = 0;
    if (SEP_MBOX_DIS_INT)  count++;
    if (SEP_MBOX_EN_INT)   count++;
    if (SEP_MBOX_SND_STS)  count++;
    if (SEP_MBOX_RECV_STS) count++;
    if (SEP_MBOX_SND0)     count++;
    if (SEP_MBOX_SND1)     count++;
    if (SEP_MBOX_RECV0)    count++;
    if (SEP_MBOX_RECV1)    count++;
    if (count != 8) return 9;

    return 0;
}

/* --- poll --------------------------------------------------------------- */

static int test_poll_returns_queued_message(void) {
    reset_fake();
    struct sep_driver *d = make_drv();
    /* Queue-empty must be asserted, not assumed: reset leaves recv_sts 0,
     * which reads as "queue not empty". */
    fake_write32(SEP_MBOX_RECV_STS, SEP_MBOX_QUEUE_EMPTY);
    if (sep_poll(d, NULL) != SEP_ERR_QUEUE_EMPTY) { drop_drv(d); return 1; }
    queue_reply(SEP_EP_SEPOS, 0, 0x0d, 0, 0);
    uint64_t reply = 0;
    if (sep_poll(d, &reply) != SEP_OK) { drop_drv(d); return 2; }
    struct sep_msg m; sep_msg_decode(reply, &m);
    if (m.ep != SEP_EP_SEPOS || m.opcode != 0x0d) { drop_drv(d); return 3; }
    drop_drv(d);
    return 0;
}

/* --- invalid args ------------------------------------------------------- */

static int test_invalid_args(void) {
    reset_fake();
    struct sep_driver *d = make_drv();
    if (sep_send_raw(NULL, 255, 0, 1, 0, 0, NULL) != SEP_ERR_INVALID) { drop_drv(d); return 1; }
    if (sep_send_raw(d, 255, 0, 0, 0, 0, NULL) != SEP_ERR_INVALID) { drop_drv(d); return 2; }
    if (sep_get_random(NULL, NULL) != SEP_ERR_INVALID) { drop_drv(d); return 3; }
    if (sep_boot_tz0(NULL) != SEP_ERR_INVALID) { drop_drv(d); return 4; }
    drop_drv(d);
    return 0;
}

/* --- stats -------------------------------------------------------------- */

static int test_stats_accumulate(void) {
    reset_fake();
    struct sep_driver *d = make_drv();
    if (sep_get_stats(d)->commands_sent != 0) { drop_drv(d); return 1; }
    fake_write32(SEP_MBOX_RECV_STS, SEP_MBOX_QUEUE_EMPTY);
    sep_ping(d);   /* will time out */
    sep_ping(d);
    const struct sep_stats *s = sep_get_stats(d);
    if (s->commands_sent != 2) { drop_drv(d); return 2; }
    if (s->timeouts != 2) { drop_drv(d); return 3; }
    sep_reset_stats(d);
    if (sep_get_stats(d)->commands_sent != 0) { drop_drv(d); return 4; }
    drop_drv(d);
    return 0;
}

/* --- runner ------------------------------------------------------------- */

typedef int (*test_fn)(void);
struct test_case { const char *name; test_fn fn; };

static const struct test_case tests[] = {
    {"register_offsets_match_pongoos", test_register_offsets_match_pongoos},
    {"msg_encode_decode_roundtrip",    test_msg_encode_decode_roundtrip},
    {"framing_matches_captured_sep_traces", test_framing_matches_captured_sep_traces},
    {"msg_decode_null_safe",           test_msg_decode_null_safe},
    {"framing_matches_captured_traces", test_framing_matches_captured_sep_traces},
    {"ping_writes_seprom_opcode_one",  test_ping_writes_seprom_opcode_one},
    {"ping_timeout_when_queue_empty",  test_ping_timeout_when_queue_empty},
    {"get_random_uses_opcode_16",      test_get_random_uses_opcode_16_and_reply_offset},
    {"send_sepos_sends_page_number",   test_send_sepos_sends_page_number},
    {"send_sepos_rejects_unaligned",   test_send_sepos_rejects_unaligned},
    {"integrity_tree_opcode_17",       test_integrity_tree_opcode_17},
    {"seprom_panic_detected",          test_seprom_panic_detected},
    {"interrupt_enable_disable",       test_interrupt_enable_disable},
    {"queue_empty_bit",                test_queue_empty_bit},
    {"register_set_is_exactly_pongoos", test_register_set_is_exactly_pongoos},
    {"poll_returns_queued_message",    test_poll_returns_queued_message},
    {"invalid_args",                   test_invalid_args},
    {"stats_accumulate",               test_stats_accumulate},
};

int main(void) {
    int failed = 0;
    size_t total = sizeof(tests) / sizeof(tests[0]);

    for (size_t i = 0; i < total; i++) {
        uart_puts(tests[i].name);
        uart_puts("... ");
        int rc = tests[i].fn();
        if (rc != 0) {
            uart_puts("FAIL (");
            uart_puts(utoa(rc));
            uart_puts(")\n");
            failed++;
        } else {
            uart_puts("ok\n");
        }
    }

    uart_puts(failed ? "FAILED: " : "All passed: ");
    uart_puts(utoa(total - failed));
    uart_puts("/");
    uart_puts(utoa(total));
    uart_puts("\n");

    return failed == 0 ? 0 : 1;
}
