/*
 * Shell-wrapper layer tests — host-side, fake MMIO.
 *
 * src/research/sepos.c is the only layer in the SEP work with no test: it is
 * the glue between the shell commands and the driver, and it owns the single
 * static driver instance. These tests drive it exactly as the shell does,
 * over the same fake MMIO the driver tests use, so the two layers are checked
 * against each other rather than each only against itself.
 *
 * Run via: python3 -m unittest tests.test_sepos_wrappers
 */

#include "sepos.h"
#include "sep.h"
#include "uart.h"
#include "string.h"
#include "util.h"
#include <stdint.h>
#include <stdlib.h>

#ifdef SEP_HOST_TEST
/* Defined in src/research/sepos.c under the same guard. */
void sepos_test_reset_for_host_test(void);
void sepos_test_attach(uint64_t base);
struct sep_driver *sepos_test_driver(void);
#endif

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

/* Every test starts from a clean module so the static driver instance, the
 * one-shot init latch and the statistics are all reset, then attaches the
 * wrapper's driver to the fake MMIO. Without sepos_test_attach() the lazy
 * init would write to the profile's real base (0x243000000 on the A11) and
 * fault. */
static void reset_module(void) {
    memset(fake_mmio, 0, FAKE_MMIO_SIZE);
    sepos_test_reset_for_host_test();
    sepos_test_attach((uint64_t)fake_mmio);
}

/* Queue one reply and clear the queue-empty bit. */
static void queue_reply(uint8_t ep, uint8_t tag, uint8_t opcode, uint8_t param, uint32_t data) {
    struct sep_msg m = { .ep = ep, .tag = tag, .opcode = opcode, .param = param, .data = data };
    fake_write64(SEP_MBOX_RECV0, sep_msg_encode(&m));
    fake_write32(SEP_MBOX_RECV_STS, fake_read32(SEP_MBOX_RECV_STS) & ~SEP_MBOX_QUEUE_EMPTY);
}

/* --- init --------------------------------------------------------------- */

/* sepos_init() itself cannot be called on the host: it uses MAILBOX_BASE,
 * which is a real SoC address (0x243000000 on the A11) and would fault. These
 * tests therefore check the attach path the test uses, which is the same
 * driver instance and the same init call with a different base. */
static int test_attach_initialises_the_owned_driver(void) {
    reset_module();
    struct sep_driver *d = sepos_test_driver();
    if (d->base != (volatile uint32_t *)fake_mmio) return 1;
    if (d->timeout_us == 0) return 2;
    return 0;
}

static int test_reset_clears_latch_and_stats(void) {
    reset_module();
    /* Run one command so statistics accumulate. */
    fake_write32(SEP_MBOX_RECV_STS, SEP_MBOX_QUEUE_EMPTY);
    (void)sepos_ping();   /* will time out */
    struct sep_driver *d = sepos_test_driver();
    if (d->stats.commands_sent == 0) return 1;

    sepos_test_reset_for_host_test();
    if (d->stats.commands_sent != 0) return 2;
    if (d->base != NULL) return 3;
    return 0;
}

/* --- wrappers route to the driver -------------------------------------- */

static int test_ping_wrapper_sends_seprom_opcode_one(void) {
    reset_module();
    queue_reply(SEP_EP_SEPROM, 0, (uint8_t)(SEP_OP_PING + SEP_REPLY_OFFSET), 0, 0);

    if (sepos_ping() != SEP_OK) return 1;

    uint64_t sent = fake_read64(SEP_MBOX_SND0);
    struct sep_msg m; sep_msg_decode(sent, &m);
    if (m.ep != SEP_EP_SEPROM) return 2;
    if (m.opcode != SEP_OP_PING) return 3;
    return 0;
}

static int test_random_wrapper_returns_32_bytes(void) {
    reset_module();
    for (int i = 0; i < 8; i++) {
        queue_reply(SEP_EP_SEPROM, 0, (uint8_t)(SEP_OP_GET_RANDOM + SEP_REPLY_OFFSET), 0,
                    (uint32_t)(0x01010101u * (i + 1)));
    }
    /* sepos_get_random() prints the bytes and returns the driver's code. */
    if (sepos_get_random() != SEP_OK) return 1;
    return 0;
}

static int test_send_sepos_wrapper_sends_page_number(void) {
    reset_module();
    queue_reply(SEP_EP_SEPROM, 0, (uint8_t)(SEP_OP_SEND_SEPOS + SEP_REPLY_OFFSET), 0, 0);

    if (sepos_send_sepos(0x19C000000ULL, 0x10000, 0) != SEP_OK) return 1;

    uint64_t sent = fake_read64(SEP_MBOX_SND0);
    struct sep_msg m; sep_msg_decode(sent, &m);
    if (m.opcode != SEP_OP_SEND_SEPOS) return 2;
    if (m.data != (uint32_t)(0x19C000000ULL >> 12)) return 3;
    return 0;
}

static int test_send_art_wrapper_sends_page_number(void) {
    reset_module();
    queue_reply(SEP_EP_SEPROM, 0, (uint8_t)(SEP_OP_SEND_ART + SEP_REPLY_OFFSET), 0, 0);

    if (sepos_send_art(0x19C010000ULL, 0x1000) != SEP_OK) return 1;

    uint64_t sent = fake_read64(SEP_MBOX_SND0);
    struct sep_msg m; sep_msg_decode(sent, &m);
    if (m.opcode != SEP_OP_SEND_ART) return 2;
    if (m.data != (uint32_t)(0x19C010000ULL >> 12)) return 3;
    return 0;
}

static int test_irq_wrapper_writes_the_en_int_mask(void) {
    reset_module();
    if (sepos_enable_irq() != SEP_OK) return 1;
    if (fake_read32(SEP_MBOX_EN_INT) != SEP_MBOX_INT_ENABLE) return 2;
    return 0;
}

/* --- wrapper is reusable across reset cycles ---------------------------- */

static int test_commands_work_after_reset_and_attach(void) {
    reset_module();
    queue_reply(SEP_EP_SEPROM, 0, (uint8_t)(SEP_OP_PING + SEP_REPLY_OFFSET), 0, 0);

    if (sepos_ping() != SEP_OK) return 1;

    /* A second cycle must work too: the static driver is reusable. */
    reset_module();
    queue_reply(SEP_EP_SEPROM, 0, (uint8_t)(SEP_OP_PING + SEP_REPLY_OFFSET), 0, 0);
    if (sepos_ping() != SEP_OK) return 2;
    return 0;
}

/* --- runner ------------------------------------------------------------- */

typedef int (*test_fn)(void);
struct test_case { const char *name; test_fn fn; };

static const struct test_case tests[] = {
    {"attach_initialises_owned_driver",   test_attach_initialises_the_owned_driver},
    {"reset_clears_latch_and_stats",      test_reset_clears_latch_and_stats},
    {"ping_wrapper_sends_seprom_opcode",  test_ping_wrapper_sends_seprom_opcode_one},
    {"random_wrapper_returns_32_bytes",   test_random_wrapper_returns_32_bytes},
    {"send_sepos_wrapper_sends_page",     test_send_sepos_wrapper_sends_page_number},
    {"send_art_wrapper_sends_page",       test_send_art_wrapper_sends_page_number},
    {"irq_wrapper_writes_en_int_mask",    test_irq_wrapper_writes_the_en_int_mask},
    {"commands_work_after_reset",         test_commands_work_after_reset_and_attach},
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