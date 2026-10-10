/*
 * SEP driver unit tests — host-side, fake MMIO
 * Run via: make host-test
 */

#include "sep.h"
#include "uart.h"
#include "string.h"
#include "util.h"
#include <stdint.h>
#include <stdlib.h>

extern void test_timer_reset(void);
extern uint32_t test_timer_calls(void);

/* Fake MMIO region for testing */
#define FAKE_MMIO_SIZE 0x1000
static uint8_t fake_mmio[FAKE_MMIO_SIZE];

static void fake_mmio_write(uint32_t offset, uint32_t val) {
    if (offset + 3 < FAKE_MMIO_SIZE) {
        *(uint32_t *)(fake_mmio + offset) = val;
    }
}

static uint32_t fake_mmio_read(uint32_t offset) {
    if (offset + 3 < FAKE_MMIO_SIZE) {
        return *(uint32_t *)(fake_mmio + offset);
    }
    return 0;
}

/* Test helpers */
static void reset_fake_mmio(void) {
    memset(fake_mmio, 0, FAKE_MMIO_SIZE);
}

static struct sep_driver *make_test_driver(void) {
    struct sep_driver *drv = malloc(sizeof(struct sep_driver));
    sep_init(drv, (uint64_t)fake_mmio);
    drv->timeout_us = 10;  // Very short timeout for fast tests
    return drv;
}

static void free_test_driver(struct sep_driver *drv) {
    free(drv);
}

/* Test cases */
static int test_sep_ping_ok(void) {
    reset_fake_mmio();
    struct sep_driver *drv = make_test_driver();

    /* Pre-load a PONG reply in IOP2AP_MSG */
    fake_mmio_write(SEP_IOP2AP_MSG0, 0x00000001);
    fake_mmio_write(SEP_IOP2AP_MSG1, 0x00000000);

    int rc = sep_ping(drv);
    if (rc != SEP_OK) { free_test_driver(drv); return 1; }

    /* Verify doorbell was rung */
    if (fake_mmio_read(SEP_AP2IOP_DB) != 1) { free_test_driver(drv); return 2; }

    /* Verify reply doorbell was acked */
    if (fake_mmio_read(SEP_IOP2AP_DB) != 1) { free_test_driver(drv); return 3; }

    /* Verify stats */
    const sep_stats_t *stats = sep_get_stats(drv);
    if (stats->commands_sent != 1) { free_test_driver(drv); return 4; }
    if (stats->replies_received != 1) { free_test_driver(drv); return 5; }

    free_test_driver(drv);
    return 0;
}

static int test_sep_ping_timeout(void) {
    reset_fake_mmio();
    struct sep_driver *drv = make_test_driver();

    int rc = sep_ping(drv);
    if (rc != SEP_ERR_TIMEOUT) { free_test_driver(drv); return 1; }

    const sep_stats_t *stats = sep_get_stats(drv);
    if (stats->timeouts != 1) { free_test_driver(drv); return 2; }
    if (stats->commands_sent != 1) { free_test_driver(drv); return 3; }

    free_test_driver(drv);
    return 0;
}

static int test_sep_framing(void) {
    reset_fake_mmio();
    struct sep_driver *drv = make_test_driver();

    uint8_t payload[4] = {0x12, 0x34, 0x56, 0x78};
    fake_mmio_write(SEP_IOP2AP_MSG0, 0x00000001);
    fake_mmio_write(SEP_IOP2AP_MSG1, 0x00000000);

    int rc = sep_send_command(drv, SEP_OP_BOOT_TZ0, payload, 4, NULL, NULL);
    if (rc != SEP_OK) { free_test_driver(drv); return 1; }

    /* Verify message written: low 32 = payload, high 32 = opcode<<16 */
    uint32_t msg0 = fake_mmio_read(SEP_AP2IOP_MSG0);
    uint32_t msg1 = fake_mmio_read(SEP_AP2IOP_MSG1);

    if (msg0 != 0x78563412) { free_test_driver(drv); return 2; }
    if ((msg1 & 0xFFFF) != SEP_OP_BOOT_TZ0) { free_test_driver(drv); return 3; }

    free_test_driver(drv);
    return 0;
}

static int test_sep_clear_doorbells(void) {
    reset_fake_mmio();
    struct sep_driver *drv = make_test_driver();

    /* Set both doorbells */
    fake_mmio_write(SEP_AP2IOP_DB, 1);
    fake_mmio_write(SEP_IOP2AP_DB, 1);

    sep_clear_doorbells(drv);

    if (fake_mmio_read(SEP_AP2IOP_DB) != 0) { free_test_driver(drv); return 1; }
    if (fake_mmio_read(SEP_IOP2AP_DB) != 1) { free_test_driver(drv); return 2; }

    free_test_driver(drv);
    return 0;
}

static int test_sep_poll_and_ack(void) {
    reset_fake_mmio();
    struct sep_driver *drv = make_test_driver();

    /* Pre-load a reply */
    fake_mmio_write(SEP_IOP2AP_MSG0, 0x12345678);
    fake_mmio_write(SEP_IOP2AP_MSG1, 0x00000010);  // opcode 0x10

    uint16_t opcode;
    uint8_t data[4];
    uint32_t len;

    int rc = sep_poll(drv, &opcode, data, &len);
    if (rc != SEP_OK) { free_test_driver(drv); return 1; }
    if (opcode != 0x10) { free_test_driver(drv); return 2; }
    if (len != 4) { free_test_driver(drv); return 3; }
    if (data[0] != 0x78 || data[1] != 0x56 || data[2] != 0x34 || data[3] != 0x12) { free_test_driver(drv); return 4; }

    /* Now ack it */
    sep_ack_reply(drv);
    if (fake_mmio_read(SEP_IOP2AP_DB) != 1) { free_test_driver(drv); return 5; }

    free_test_driver(drv);
    return 0;
}

static int test_sep_get_random(void) {
    reset_fake_mmio();
    struct sep_driver *drv = make_test_driver();

    /* Mock one reply for get_random */
    fake_mmio_write(SEP_IOP2AP_MSG0, 0x12345678);
    fake_mmio_write(SEP_IOP2AP_MSG1, 0x00000010);

    /* Test single get_random framing via sep_send_command */
    uint8_t out[4];
    uint32_t len;
    int rc = sep_send_command(drv, SEP_OP_GET_RANDOM, NULL, 0, out, &len);
    if (rc != SEP_OK) { free_test_driver(drv); return 1; }

    if (len != 4) { free_test_driver(drv); return 2; }
    if (out[0] != 0x78 || out[1] != 0x56 || out[2] != 0x34 || out[3] != 0x12) { free_test_driver(drv); return 3; }

    const sep_stats_t *stats = sep_get_stats(drv);
    if (stats->commands_sent != 1) { free_test_driver(drv); return 4; }
    if (stats->replies_received != 1) { free_test_driver(drv); return 5; }

    free_test_driver(drv);
    return 0;
}

static int test_sep_boot_tz0(void) {
    reset_fake_mmio();
    struct sep_driver *drv = make_test_driver();

    fake_mmio_write(SEP_IOP2AP_MSG0, 0x00000001);
    fake_mmio_write(SEP_IOP2AP_MSG1, 0x00000000);

    /* load_addr_page = 0x12345678 -> payload bytes = 0x78, 0x56, 0x34, 0x12 -> msg = 0x12345678 */
    int rc = sep_boot_tz0(drv, 0x12345678);
    if (rc != SEP_OK) { free_test_driver(drv); return 1; }

    uint32_t msg0 = fake_mmio_read(SEP_AP2IOP_MSG0);
    uint32_t msg1 = fake_mmio_read(SEP_AP2IOP_MSG1);

    if (msg0 != 0x12345678) { free_test_driver(drv); return 2; }
    if ((msg1 & 0xFFFF) != SEP_OP_BOOT_TZ0) { free_test_driver(drv); return 3; }

    free_test_driver(drv);
    return 0;
}

static int test_sep_stats(void) {
    reset_fake_mmio();
    struct sep_driver *drv = make_test_driver();

    const sep_stats_t *stats = sep_get_stats(drv);
    if (stats->commands_sent != 0) { free_test_driver(drv); return 1; }

    fake_mmio_write(SEP_IOP2AP_MSG0, 1);
    fake_mmio_write(SEP_IOP2AP_MSG1, 0);
    sep_ping(drv);

    stats = sep_get_stats(drv);
    if (stats->commands_sent != 1) { free_test_driver(drv); return 2; }
    if (stats->replies_received != 1) { free_test_driver(drv); return 3; }

    sep_reset_stats(drv);
    stats = sep_get_stats(drv);
    if (stats->commands_sent != 0) { free_test_driver(drv); return 4; }

    free_test_driver(drv);
    return 0;
}

static int test_sep_hw_error(void) {
    reset_fake_mmio();
    struct sep_driver *drv = make_test_driver();

    /* Set hardware error bit in status */
    fake_mmio_write(SEP_STATUS, 0x80000000);

    int rc = sep_ping(drv);
    if (rc != SEP_ERR_HW) { free_test_driver(drv); return 1; }

    const sep_stats_t *stats = sep_get_stats(drv);
    if (stats->errors != 1) { free_test_driver(drv); return 2; }

    free_test_driver(drv);
    return 0;
}

static int test_sep_send_sepos(void) {
    reset_fake_mmio();
    struct sep_driver *drv = make_test_driver();

    /* Mock one reply for the first chunk */
    fake_mmio_write(SEP_IOP2AP_MSG0, 0x00000001);
    fake_mmio_write(SEP_IOP2AP_MSG1, 0x00000000);

    /* Test first chunk framing via sep_send_command with SEP_OP_SEND_SEPOS */
    /* metadata[0] = image_base >> 12 = 0x19C000000 >> 12 = 0x19C000 */
    uint32_t metadata0 = 0x19C000;
    int rc = sep_send_command(drv, SEP_OP_SEND_SEPOS, (uint8_t *)&metadata0, 4, NULL, NULL);
    if (rc != SEP_OK) { free_test_driver(drv); return 1; }

    /* Verify first chunk sent correctly */
    uint32_t msg0 = fake_mmio_read(SEP_AP2IOP_MSG0);
    if (msg0 != 0x0019C000) { free_test_driver(drv); return 2; }
    uint32_t msg1 = fake_mmio_read(SEP_AP2IOP_MSG1);
    if ((msg1 & 0xFFFF) != SEP_OP_SEND_SEPOS) { free_test_driver(drv); return 3; }

    free_test_driver(drv);
    return 0;
}

static int test_sep_timeout_override(void) {
    reset_fake_mmio();
    struct sep_driver *drv = make_test_driver();
    test_timer_reset();

    sep_set_timeout(drv, SEP_OP_PING, 20);
    int rc = sep_ping(drv);
    if (rc != SEP_ERR_TIMEOUT) { free_test_driver(drv); return 1; }
    if (test_timer_calls() != 20) { free_test_driver(drv); return 2; }

    free_test_driver(drv);
    return 0;
}

static int test_sep_extended_is_fail_closed(void) {
    reset_fake_mmio();
    struct sep_driver *drv = make_test_driver();
    uint32_t payload[4] = {1, 2, 3, 4};

    int rc = sep_send_extended(drv, SEP_OP_SEND_SEPOS, payload, sizeof(payload));
    if (rc != SEP_ERR_UNSUPPORTED) { free_test_driver(drv); return 1; }
    for (uint32_t i = 0; i < FAKE_MMIO_SIZE; i++) {
        if (fake_mmio[i] != 0) { free_test_driver(drv); return 2; }
    }

    free_test_driver(drv);
    return 0;
}

static int test_sep_invalid_args(void) {
    reset_fake_mmio();
    struct sep_driver *drv = make_test_driver();

    if (sep_send_command(NULL, 0xFF, NULL, 0, NULL, NULL) != SEP_ERR_INVALID) { free_test_driver(drv); return 1; }
    if (sep_send_command(drv, 0, NULL, 0, NULL, NULL) != SEP_ERR_INVALID) { free_test_driver(drv); return 2; }
    if (sep_get_random(NULL, NULL) != SEP_ERR_INVALID) { free_test_driver(drv); return 3; }
    if (sep_boot_tz0(NULL, 0) != SEP_ERR_INVALID) { free_test_driver(drv); return 4; }
    if (sep_send_sepos(NULL, 0, 0, 0) != SEP_ERR_INVALID) { free_test_driver(drv); return 5; }

    free_test_driver(drv);
    return 0;
}

/* Test runner */
typedef int (*test_fn)(void);

struct test_case {
    const char *name;
    test_fn fn;
};

static const struct test_case tests[] = {
    {"test_sep_ping_ok", test_sep_ping_ok},
    {"test_sep_ping_timeout", test_sep_ping_timeout},
    {"test_sep_framing", test_sep_framing},
    {"test_sep_clear_doorbells", test_sep_clear_doorbells},
    {"test_sep_poll_and_ack", test_sep_poll_and_ack},
    {"test_sep_get_random", test_sep_get_random},
    {"test_sep_boot_tz0", test_sep_boot_tz0},
    {"test_sep_stats", test_sep_stats},
    {"test_sep_hw_error", test_sep_hw_error},
    {"test_sep_send_sepos", test_sep_send_sepos},
    {"test_sep_timeout_override", test_sep_timeout_override},
    {"test_sep_extended_is_fail_closed", test_sep_extended_is_fail_closed},
    {"test_sep_invalid_args", test_sep_invalid_args},
};

int main(void) {
    int failed = 0;

    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        uart_puts("Running ");
        uart_puts(tests[i].name);
        uart_puts("... ");
        int rc = tests[i].fn();
        if (rc != 0) {
            uart_puts("FAILED (rc=");
            uart_puts(utoa(rc));
            uart_puts(")\n");
            failed++;
        } else {
            uart_puts("OK\n");
        }
    }

    if (failed) {
        uart_puts("FAILED: ");
        uart_puts(utoa(failed));
        uart_puts(" test(s)\n");
    } else {
        uart_puts("All ");
        uart_puts(utoa(sizeof(tests) / sizeof(tests[0])));
        uart_puts(" tests passed\n");
    }

    return failed == 0 ? 0 : 1;
}
