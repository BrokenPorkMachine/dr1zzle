#ifndef SEP_H
#define SEP_H

#include <stdint.h>
#include <stdbool.h>

/*
 * Apple ASC (Apple Secure Channel) Mailbox Register Map
 *
 * The offsets and command protocol below are research hypotheses, not a
 * verified T8015 register map. Production sep_init() therefore fails closed;
 * SEP_TEST_MMIO enables only the host fake-MMIO test transport.
 *
 * 0x243000000 is an AP-visible aperture literal, not a verified FIFO base.
 * The measured mailbox access window is recorded separately at 0x243008000.
 * Do not use this map for hardware access until those addresses and offsets
 * are reconciled.
 */

/* AP → IOP (SEP) */
#define SEP_AP2IOP_MSG0        0x800  // Message low 32 bits
#define SEP_AP2IOP_MSG1        0x804  // Message high 32 bits
#define SEP_AP2IOP_DB          0x808  // Doorbell: write 1 to ring

/* IOP (SEP) → AP */
#define SEP_IOP2AP_MSG0        0x80C  // Reply low 32 bits
#define SEP_IOP2AP_MSG1        0x810  // Reply high 32 bits
#define SEP_IOP2AP_DB          0x814  // Doorbell: read, then write 1 to ack

/* Status / Control (offsets from pongoOS; verify on silicon) */
#define SEP_STATUS             0x400  // Mailbox status register
#define SEP_IRQ_ENABLE         0x404  // IRQ enable
#define SEP_IRQ_STATUS         0x408  // IRQ status
#define SEP_IRQ_CLEAR          0x40C  // IRQ clear (write 1 to clear)

/* Extended mailbox region for descriptor-based transfers */
#define SEP_DESC_BASE          0x900  // Descriptor ring base (256 bytes)
#define SEP_DESC_SIZE          0x100  // 16 descriptors × 16 bytes

/* Legacy fake-MMIO test identifiers, not a verified command API. PongoOS's
 * A11 SEPROM path uses 0x01 for ping, 0x10 for random, 0x05 for TZ0, 0x06
 * for SEPOS load, and 0x11 for integrity-tree configuration; 0xff is a
 * SEPROM panic message, not ping. */
#define SEP_OP_PING            0xFF
#define SEP_OP_GET_RANDOM      0x10
#define SEP_OP_BOOT_TZ0        0x05
#define SEP_OP_SEND_SEPOS      0x06
#define SEP_OP_SEND_ART        0x11

/* Legacy fake-MMIO framing only. PongoOS's A11 message is endpoint/tag/
 * opcode/param/data, not this layout. */

/* Descriptor format for extended transfers (SEP_OP_SEND_SEPOS) */
typedef struct sep_descriptor {
    uint64_t addr;      // Physical address of payload (must be 16-byte aligned)
    uint32_t size;      // Payload size in bytes
    uint32_t flags;     // Flags: bit 0 = last, bit 1 = interrupt on completion
} sep_descriptor_t;

/* Error codes */
#define SEP_OK                 0
#define SEP_ERR_TIMEOUT        -1
#define SEP_ERR_NAK            -2     // SEP replied with NAK
#define SEP_ERR_BUSY           -3     // Doorbell not clear
#define SEP_ERR_INVALID        -4     // Bad opcode/payload
#define SEP_ERR_MALFORMED      -5     // Reply malformed
#define SEP_ERR_UNALIGNED      -6     // Address not aligned
#define SEP_ERR_OVERFLOW       -7     // Payload too large
#define SEP_ERR_HW             -8     // Hardware error (status register)
#define SEP_ERR_UNSUPPORTED    -9     // Transport/register map not verified

/* Default timeouts per opcode (microseconds) */
#define SEP_TIMEOUT_PING       10000      // 10 ms
#define SEP_TIMEOUT_RANDOM     100000     // 100 ms per 4 bytes
#define SEP_TIMEOUT_BOOT_TZ0   5000000    // 5 seconds
#define SEP_TIMEOUT_SEND_SEPOS 10000000   // 10 seconds
#define SEP_TIMEOUT_DEFAULT    1000000    // 1 second

/* Statistics for debugging */
typedef struct sep_stats {
    uint32_t commands_sent;
    uint32_t replies_received;
    uint32_t timeouts;
    uint32_t naks;
    uint32_t busy_retries;
    uint32_t errors;
} sep_stats_t;

/* Driver API */
struct sep_driver {
    volatile uint32_t *base;
    uint32_t timeout_us;          // Default timeout
    uint32_t opcode_timeout_us[5]; // Per-opcode overrides; zero selects default
    sep_stats_t stats;            // Statistics counters
    bool irq_mode;                // If true, use IRQ instead of polling (future)
};

int sep_init(struct sep_driver *drv, uint64_t base_addr);
void sep_deinit(struct sep_driver *drv);

/* Configure per-opcode timeouts */
void sep_set_timeout(struct sep_driver *drv, uint16_t opcode, uint32_t timeout_us);
void sep_set_default_timeout(struct sep_driver *drv, uint32_t timeout_us);

/* Get statistics */
const sep_stats_t *sep_get_stats(const struct sep_driver *drv);
void sep_reset_stats(struct sep_driver *drv);

/* Blocking send with reply. Returns SEP_OK on success, negative error code on failure.
 * If reply_len > 0, reply_data must point to a buffer of at least reply_len bytes.
 * On success, *reply_len is set to actual reply size. */
int sep_send_command(struct sep_driver *drv,
                     uint16_t opcode,
                     const uint8_t *payload, uint32_t payload_len,
                     uint8_t *reply_data, uint32_t *reply_len);

/* Reserved for a verified multi-word transfer protocol. Currently returns
 * SEP_ERR_UNSUPPORTED for valid requests and performs no MMIO. */
int sep_send_extended(struct sep_driver *drv,
                      uint16_t opcode,
                      const void *payload, uint32_t payload_len);

/* Non-blocking poll for incoming message. Returns SEP_OK if message ready,
 * SEP_ERR_TIMEOUT if none. Does not ack the doorbell. */
int sep_poll(struct sep_driver *drv,
             uint16_t *out_opcode,
             uint8_t *out_data, uint32_t *out_len);

/* Acknowledge a polled message (must be called after sep_poll returns SEP_OK) */
void sep_ack_reply(struct sep_driver *drv);

/* Read mailbox status register */
uint32_t sep_get_status(struct sep_driver *drv);

/* Clear pending doorbells */
void sep_clear_doorbells(struct sep_driver *drv);

/* Check if hardware reports error condition */
int sep_check_hw_error(struct sep_driver *drv);

/* Convenience helpers for common opcodes */
int sep_ping(struct sep_driver *drv);
int sep_get_random(struct sep_driver *drv, uint8_t out[32]);
int sep_boot_tz0(struct sep_driver *drv, uint64_t load_addr_page);
int sep_send_sepos(struct sep_driver *drv, uint64_t image_base, uint32_t image_size, uint64_t entry_page);
int sep_send_art(struct sep_driver *drv, uint64_t art_base, uint32_t art_size);

#endif /* SEP_H */
