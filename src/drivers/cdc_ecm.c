#include "usb.h"
#include "net.h"

/* CDC-ECM glue.
 *
 * The descriptors in usb_descriptors.c declare an ECM interface, but nothing
 * implemented the two halves the core needs from the protocol layer, so the
 * old usb.c called usb_cdc_rx() and usb_cdc_tx_pending() that did not exist.
 * These are the minimal correct implementations: a frame queue for RX that
 * hands Ethernet frames up to the network stack, and a TX queue drained from
 * the bulk-IN completion path.
 *
 * RX has to be careful about one thing, which is where the frames actually
 * come from. The DWC2 reports a bulk OUT transfer in RXFLVL events of up to
 * one packet (MPS) at a time, so a 1500-byte Ethernet frame arrives here as
 * three 512-byte calls. A frame boundary is not signalled by the endpoint --
 * it is the short packet at the end of the host's transfer (or a zero-length
 * packet when the frame is an exact multiple of 512). So this file assembles
 * the byte stream into frames and only then hands a whole frame on, and it
 * hands it on from the main loop (usb_cdc_service, called by net_poll), not
 * from the interrupt. That keeps the network stack single-threaded: its
 * segment buffers are statics, and the alternative is a USB interrupt landing
 * in the middle of a retransmission.
 */

#include "uart.h"
#include "util.h"

/* One frame is at most a full Ethernet payload; the stack drops anything
 * longer, so holding four is a queue, not a backlog claim. */
#define RX_FRAME_MAX 1514u
#define RX_QUEUE_DEPTH 4u
#define TX_RING_SIZE 8192u

typedef struct {
    uint8_t  data[RX_FRAME_MAX];
    uint16_t len;
} frame_t;

static frame_t rx_frames[RX_QUEUE_DEPTH];
static volatile uint32_t rx_head;   /* next slot to fill   */
static volatile uint32_t rx_tail;   /* next slot to drain  */
static volatile uint32_t rx_dropped;

/* The frame being assembled across one or more RXFLVL calls. */
static uint8_t rx_partial[RX_FRAME_MAX];
static uint16_t rx_partial_len;
static int rx_partial_active;

static uint8_t tx_ring[TX_RING_SIZE];
static volatile uint32_t tx_head;
static volatile uint32_t tx_tail;

/* Retained so the shell can inspect traffic with `usb` even before the
 * stack is asked anything. A copy, not a pointer: the queue slot is reused. */
static uint8_t last_frame[RX_FRAME_MAX];
static uint16_t last_frame_len;

static void rx_push(void) {
    uint32_t next = (rx_head + 1u) % RX_QUEUE_DEPTH;
    if (next == rx_tail) {
        /* Queue full. Drop the whole frame: a partial one is worse than a
         * missing one, because a truncated Ethernet frame is a frame the
         * stack will parse as garbage. */
        rx_dropped++;
        rx_partial_len = 0;
        rx_partial_active = 0;
        return;
    }
    for (uint16_t i = 0; i < rx_partial_len; i++) rx_frames[rx_head].data[i] = rx_partial[i];
    rx_frames[rx_head].len = rx_partial_len;
    rx_head = next;
    rx_partial_len = 0;
    rx_partial_active = 0;
}

void usb_cdc_rx(const uint8_t *data, uint16_t len) {
    if (!len && !rx_partial_active) return;

    if (len) {
        if (rx_partial_len + len > RX_FRAME_MAX) {
            /* A frame that cannot fit is not a frame we can use, and the
             * stream is now unsynchronised until the boundary arrives. */
            rx_dropped++;
            rx_partial_len = 0;
            rx_partial_active = 0;
            return;
        }
        for (uint16_t i = 0; i < len; i++) rx_partial[rx_partial_len + i] = data[i];
        rx_partial_len = (uint16_t)(rx_partial_len + len);
        rx_partial_active = 1;
    }

    /* A short packet (or a zero-length packet) terminates the host's
     * transfer, which is how a CDC-ECM receiver knows where one Ethernet
     * frame ends and the next begins. A full MPS-sized packet means more of
     * this frame is still coming. */
    if (len && len == USB_MAX_PACKET) return;
    if (!rx_partial_len) return;

    for (uint16_t i = 0; i < rx_partial_len && i < RX_FRAME_MAX; i++) {
        last_frame[i] = rx_partial[i];
    }
    last_frame_len = rx_partial_len;
    rx_push();
}

uint16_t usb_cdc_last_frame(uint8_t *out, uint16_t max) {
    uint16_t n = last_frame_len < max ? last_frame_len : max;
    for (uint16_t i = 0; i < n; i++) out[i] = last_frame[i];
    return n;
}

uint32_t usb_cdc_rx_dropped(void) {
    return rx_dropped;
}

/* Main-loop half of the receive path: hand whole frames to the stack. Called
 * from net_poll(), never from the interrupt. */
void usb_cdc_service(void) {
    while (rx_tail != rx_head) {
        net_recv_frame(rx_frames[rx_tail].data, rx_frames[rx_tail].len);
        rx_tail = (rx_tail + 1u) % RX_QUEUE_DEPTH;
    }
}

void usb_cdc_tx_queue(const uint8_t *data, uint16_t len) {
    if (len == 0 || len > TX_RING_SIZE) return;
    uint32_t h = tx_head;
    uint32_t next = (h + len) % TX_RING_SIZE;
    if (next == tx_tail) {
        /* No room: drop rather than block. The caller is either the stack
         * (which will retransmit) or the main loop, and neither of them has
         * a reason to wait behind a full endpoint. */
        return;
    }
    for (uint16_t i = 0; i < len; i++) tx_ring[(h + i) % TX_RING_SIZE] = data[i];
    tx_head = next;
    usb_cdc_tx_pending();
}

void usb_cdc_tx_pending(void) {
    static uint8_t frame[USB_MAX_PACKET];

    if (!usb_configured()) return;
    if (tx_head == tx_tail) return;

    uint32_t t = tx_tail;
    uint32_t h = tx_head;
    uint32_t n = h > t ? (h - t) : (TX_RING_SIZE - t + h);
    if (n > USB_MAX_PACKET) n = USB_MAX_PACKET;
    for (uint32_t i = 0; i < n; i++) frame[i] = tx_ring[(t + i) % TX_RING_SIZE];
    /* Advance the tail before sending, not after. usb_send() waits on the
     * bulk-IN completion, and if an interrupt fires during that wait and
     * runs this same function, advancing first means it sees an empty queue
     * instead of re-sending the bytes already in flight. */
    tx_tail = (t + n) % TX_RING_SIZE;

    usb_send(frame, (uint16_t)n);
}
