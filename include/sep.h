#ifndef SEP_H
#define SEP_H

#include <stdint.h>
#include <stdbool.h>

/*
 * Apple SEP ASC Mailbox Register Map and Protocol
 *
 * Audit source: pongoOS src/drivers/sep/sep.c (checkra1n/pongoOS master)
 * Cross-reference: AsahiLinux docs/hw/soc/asc, docs/hw/soc/sep
 *
 * A11 (T8015) and later use the 64-bit mailbox layout. Older parts (A10/A10X)
 * use a 32-bit layout. This driver implements the 64-bit layout only; a
 * 32-bit variant is not written and no offset in here applies to it.
 *
 * The COMPLETE 64-bit register set, from pongoOS struct mailbox_registers64:
 *
 *   0x8100  dis_int    write 0x1000 to disable the inbox interrupt
 *   0x8104  en_int     write 0x1000 to enable it; write 0 to disable
 *   0x8108  snd_sts    AP->IOP send status (bits not documented in pongoOS)
 *   0x810C  recv_sts   IOP->AP status; bit 17 (0x20000) = queue EMPTY
 *   0x8110..0x87FC     not present in the struct (pad[0x6f0/4])
 *   0x8800  snd0       AP->IOP message, 64-bit at this offset
 *   0x8808  snd1       written 0 alongside snd0 by pongoOS
 *   0x8810  _unk0      named _unk in pongoOS; purpose not established
 *   0x8818  _unk1      "
 *   0x8820  _unk2      "
 *   0x8828  _unk3      "
 *   0x8830  recv0      IOP->AP reply, 64-bit at this offset
 *   0x8838  recv1      read and discarded by pongoOS ("is that OK?" XXX)
 *
 * That is the whole file. In particular there is NO reply doorbell, NO ack
 * register and no per-message completion flag in either layout, so nothing in
 * this driver writes one. Reading recv0 is the entire consumption path —
 * pongoOS's sep_check_mailbox() reads recv0, dispatches the message, and
 * returns; there is nothing after it.
 *
 * The interrupt the mask controls is per-part and comes from the device
 * tree, not from a constant here: pongoOS reads /device-tree/arm-io/sep's
 * "interrupts" property and task_bind_to_irq()s each one, skipping
 * IRQ_T8015_SEP_INBOX_NOT_EMPTY (0x79) on the A11 because "it keeps firing
 * and I don't know why". The DT-derived number is why this driver takes no
 * IRQ at all: wiring one needs the tree, and the numbers differ per part
 * (the A11's own sep node in the reference ioreg dump carries 0x62/0x61/
 * 0x64/0x63, which is a different set again).
 *
 * Message format (packed 64-bit at snd0):
 *   byte 0  ep      endpoint: 255=SEPROM, 0=SEPOS control, 254=Boot254
 *   byte 1  tag     opaque tag echoed in the reply; 0 for one-shot commands
 *   byte 2  opcode  operation code (see SEP_OP_*)
 *   byte 3  param   operation parameter (mode, flags)
 *   bytes 4-7 data  payload (physical page number, length, etc.)
 *
 * opcode convention (pongoOS seprom_execute_opcode):
 *   AP->SEP commands are sent as (endpoint 255, opcode, param, data).
 *   Replies come back with opcode = opcode + 100.
 *   SEPROM panic is (endpoint 255, opcode 255).
 *
 * Endpoint routing on the way back: pongoOS dispatches on ep == 0xff to the
 * SEPROM handler, ep == 0 to the SEPOS control handler, and anything else
 * falls through to the generic (unimplemented, "[tbd]") path.
 *
 * Reply conventions are ENDPOINT-SPECIFIC, and this is the one place where a
 * correct implementation of one endpoint must not be generalised:
 *
 *   ep 255 (SEPROM / Boot255)  reply opcode = request opcode + 100
 *                              (pongoOS: 16+100=116, 5+100=105, 6+100=106)
 *   ep 0   (Control/CNTL)      replies with type 0x1 on success
 *                              (AsahiLinux HW:SEP, macOS notes)
 *   ep 0x12/0x13 (SKS/xART)    type 0x5 = success, 0x7 = error
 *
 * This driver implements the ep-255 convention and nothing else. Applying
 * opcode+100 to endpoint 0 would be wrong, and the driver does not.
 *
 * Note also that ep 0xff has two names in the two sources and they are not
 * obviously the same thing: pongoOS calls 0xff "SEPROM" (the AP talking to
 * the boot ROM, via seprom_execute_opcode), while AsahiLinux calls 0xff
 * "Boot255" (SEP signalling that its protected region is ready). They may be
 * one endpoint viewed from two directions, or two uses of the same number.
 * NOT RESOLVED, and this driver uses the pongoOS reading because that is the
 * one whose request side it implements.
 */

/* ----------------------------------------------------------------------- */
/* 64-bit mailbox register offsets (A11+)                                  */
/* ----------------------------------------------------------------------- */

#define SEP_MBOX_DIS_INT      0x8100
#define SEP_MBOX_EN_INT       0x8104
#define SEP_MBOX_SND_STS      0x8108
#define SEP_MBOX_RECV_STS     0x810C
#define SEP_MBOX_SND0         0x8800   /* 64-bit AP->IOP message */
#define SEP_MBOX_SND1         0x8808
#define SEP_MBOX_RECV0        0x8830   /* 64-bit IOP->AP reply */
#define SEP_MBOX_RECV1        0x8838

/* recv_sts bit 17: set means the IOP->AP queue is empty */
#define SEP_MBOX_QUEUE_EMPTY  0x20000u

/* en_int value to enable the inbox-not-empty interrupt (A11) */
#define SEP_MBOX_INT_ENABLE   0x1000u

/* The A11 inbox-not-empty IRQ line, bound in pongoOS sep_setup */
#define SEP_IRQ_INBOX_NOT_EMPTY_T8015  0x79

/* ----------------------------------------------------------------------- */
/* Message format                                                           */
/* ----------------------------------------------------------------------- */

struct sep_msg {
    uint8_t  ep;
    uint8_t  tag;
    uint8_t  opcode;
    uint8_t  param;
    uint32_t data;
};

/* Endpoint identifiers */
#define SEP_EP_SEPROM     255   /* SEP boot ROM */
#define SEP_EP_SEPOS      0     /* SEPOS control messages */
#define SEP_EP_BOOT254    254   /* Boot254: boot into SEPOS */
#define SEP_EP_BOOT255    255   /* Boot255: protected region ready */

/* Opcodes sent to the SEPROM endpoint (255) */
#define SEP_OP_PING            1    /* ping; reply opcode 101 */
#define SEP_OP_GET_RANDOM      16   /* TRNG; reply opcode 116 */
#define SEP_OP_BOOT_TZ0        5    /* boot TZ0/SEPOS; reply opcode 105 */
#define SEP_OP_SEND_SEPOS      6    /* send SEPOS image (page in data) */
#define SEP_OP_SEND_ART        11   /* send ART; reply opcode 111 (verify) */
#define SEP_OP_RESUME          8    /* resume; reply opcode 108 */
#define SEP_OP_PANIC           10   /* request SEPROM panic dump */
#define SEP_OP_INTEGRITY_TREE  17   /* config integrity tree; reply 117 */

/* Reply offset: SEP echoes opcode + 100 */
#define SEP_REPLY_OFFSET       100

/* SEPROM panic: endpoint 255, opcode 255 */
#define SEP_OP_SEPROM_PANIC    255

/* A12 boot_done event (AsahiLinux SEP wiki): response type 0x5 = success */
#define SEP_RESP_SUCCESS       0x5
#define SEP_RESP_ERROR         0x7

/* ----------------------------------------------------------------------- */
/* Errors                                                                   */
/* ----------------------------------------------------------------------- */

#define SEP_OK                 0
#define SEP_ERR_TIMEOUT        -1
#define SEP_ERR_NAK            -2     /* SEP replied with an error response */
#define SEP_ERR_BUSY           -3     /* send queue full */
#define SEP_ERR_INVALID        -4     /* bad opcode/payload */
#define SEP_ERR_MALFORMED      -5     /* reply malformed */
#define SEP_ERR_QUEUE_EMPTY    -6     /* recv_sts says the queue is empty */
#define SEP_ERR_HW             -7     /* hardware fault */
#define SEP_ERR_PANIC          -8     /* SEPROM panicked */
#define SEP_ERR_NO_SEPOS       -9     /* tag/opcode unknown */

/* ----------------------------------------------------------------------- */
/* Driver                                                                   */
/* ----------------------------------------------------------------------- */

struct sep_stats {
    uint32_t commands_sent;
    uint32_t replies_received;
    uint32_t timeouts;
    uint32_t naks;
    uint32_t busy_retries;
    uint32_t errors;
    uint32_t panics;
};

struct sep_driver {
    volatile uint32_t *base;       /* mailbox base + SEP_MBOX_* offsets */
    uint64_t           base_addr;  /* for diagnostics */
    uint32_t           timeout_us;
    bool               irq_mode;   /* true when en_int is set (future) */
    struct sep_stats   stats;
};

int  sep_init(struct sep_driver *drv, uint64_t base_addr);
void sep_deinit(struct sep_driver *drv);

/* Interrupt control (A11 en_int = 0x1000) */
void sep_enable_interrupt(struct sep_driver *drv);
void sep_disable_interrupt(struct sep_driver *drv);

/* Status */
uint32_t sep_recv_status(struct sep_driver *drv);
bool     sep_recv_queue_empty(struct sep_driver *drv);

/* Clear stale state */
void sep_clear_doorbells(struct sep_driver *drv);

/* Core send. Composes a full sep_msg and returns the raw 64-bit reply.
 * Returns SEP_OK or a negative error code. Reply is raw; use
 * sep_msg_decode to interpret it. */
int sep_send_raw(struct sep_driver *drv,
                 uint8_t ep, uint8_t tag, uint8_t opcode, uint8_t param, uint32_t data,
                 uint64_t *out_reply);

/* Compose/decode helpers */
uint64_t sep_msg_encode(struct sep_msg *m);
void     sep_msg_decode(uint64_t raw, struct sep_msg *m);

/* Typed convenience helpers (SEPROM endpoint, tag 0) */
int sep_ping(struct sep_driver *drv);
int sep_get_random(struct sep_driver *drv, uint8_t out[32]);
int sep_boot_tz0(struct sep_driver *drv);
int sep_send_sepos(struct sep_driver *drv, uint64_t image_phys, uint32_t image_size, uint64_t entry_phys);
int sep_send_art(struct sep_driver *drv, uint64_t art_phys, uint32_t art_size);
int sep_config_integrity_tree(struct sep_driver *drv, uint32_t pages);

/* Non-blocking poll of the reply queue.
 *
 * There is NO separate ack step and this driver provides none, because
 * neither pongoOS mailbox layout has a reply doorbell to clear. Reading
 * recv0 is the whole consumption path: sep_check_mailbox() reads recv0,
 * dispatches the message, and that is all it does. So sep_poll() consuming
 * the word IS the ack, and calling it twice on one message reads the next
 * queue entry rather than re-reading the same one. */
int sep_poll(struct sep_driver *drv, uint64_t *out_reply);

/* Stats */
const struct sep_stats *sep_get_stats(const struct sep_driver *drv);
void sep_reset_stats(struct sep_driver *drv);

#endif /* SEP_H */