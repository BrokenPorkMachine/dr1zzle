#include "memory_map.h"
#include "mmio.h"
#include "uart.h"

/* S5L UART offsets. Keep offsets explicit so the accessor API is the only
 * code that performs a register transaction. */
#define UART_ULCON      0x00u
#define UART_UCON       0x04u
#define UART_UFCON      0x08u
#define UART_UMCON      0x0Cu
#define UART_UTRSTAT    0x18u
#define UART_UTXH       0x20u
#define UART_URXH       0x24u
#define UART_UBRDIV     0x28u
#define UART_UDIVSLOT   0x2Cu

static inline uintptr_t uart_reg(uint32_t offset) {
    return (uintptr_t)UART_BASE + offset;
}

/* --- output capture -------------------------------------------------------
 * Small on purpose: capture is a reply buffer for one command, not a log.
 * It is flushed when it fills rather than grown, so a command that prints
 * more than this is truncated at the boundary rather than overflowing the
 * sink's own buffer. */
#define CAPTURE_BUFFER 64u

static uart_capture_fn capture_sink;
static uint8_t capture_buffer[CAPTURE_BUFFER];
static size_t capture_length;

static void capture_flush(void) {
    if (capture_length && capture_sink) {
        capture_sink(capture_buffer, capture_length);
        capture_length = 0;
    }
}

static void capture_feed(uint8_t byte) {
    if (!capture_sink) return;
    if (capture_length == CAPTURE_BUFFER) capture_flush();
    capture_buffer[capture_length++] = byte;
}

void uart_capture_begin(uart_capture_fn sink) {
    capture_flush();
    capture_length = 0;
    capture_sink = sink;
}

void uart_capture_end(void) {
    capture_flush();
    capture_sink = 0;
    capture_length = 0;
}

/* ULCON */
#define ULCON_8N1        0x3
/* UCON */
#define UCON_RX_EN       (1 << 0)
#define UCON_TX_EN       (1 << 1)
#define UCON_RX_ERR_INT  (1 << 2)
#define UCON_TX_INT      (1 << 3)
/* UTRSTAT */
#define UTRSTAT_RX_READY (1 << 0)
#define UTRSTAT_TX_EMPTY (1 << 1)

#define PCLK_HZ          24000000u
#define BAUD             115200u

/* Previous bug: ucon was set to 0x5, which is RX_EN|RX_ERR_INT. TX_EN was
 * never set, so uart_putc waited forever on UTRSTAT_TX_EMPTY that the
 * hardware could not assert because the transmitter was disabled. */
void uart_early_init(void) {
    mmio_write32(uart_reg(UART_ULCON), ULCON_8N1);
    mmio_write32(uart_reg(UART_UCON), UCON_RX_EN | UCON_TX_EN);
    mmio_write32(uart_reg(UART_UFCON), 0x3);  /* FIFO enable, 16-byte trigger */
    mmio_write32(uart_reg(UART_UMCON), 0x0);  /* no modem control */

    /* UBRDIV = PCLK / (16 * baud) - 1, fractional part in UDIVSLOT.
     * At 24MHz/115200 that is exactly 13, so UDIVSLOT stays 0. The
     * original computed (24000000 / 1843200) - 1 = 12, one step slow
     * (~115kHz, roughly 3.4% error) because it divided before subtracting. */
    mmio_write32(uart_reg(UART_UBRDIV), (PCLK_HZ / (16 * BAUD)) - 1);
    mmio_write32(uart_reg(UART_UDIVSLOT), 0);
}

/* Command-output mirror. The firmware's on-screen menu (src/ui/menu.c) gives
 * this a strong definition that renders each byte into the output pane under
 * the menu while a command is executing; the core bootstrap keeps this weak
 * no-op so it never needs a framebuffer. Prompts and input echo are emitted
 * outside a command, so they never reach the pane through here. */
extern void uart_mirror_hook(char c);

__attribute__((weak)) void uart_mirror_hook(char c) { (void)c; }

void uart_putc(char c) {
    if (c == '\n') uart_putc('\r');
    while ((mmio_read32(uart_reg(UART_UTRSTAT)) & UTRSTAT_TX_EMPTY) == 0) { }
    mmio_write32(uart_reg(UART_UTXH), (uint32_t)(uint8_t)c);
    /* Mirrored after the register write so a capture sink sees the byte in
     * the same order -- including the '\r' that '\n' expands to -- that the
     * serial console sees it in. */
    capture_feed((uint8_t)c);
    uart_mirror_hook(c);
}

void uart_puts(const char *s) {
    while (*s) uart_putc(*s++);
}

int uart_getc(void) {
    if (mmio_read32(uart_reg(UART_UTRSTAT)) & UTRSTAT_RX_READY) {
        return (int)(mmio_read32(uart_reg(UART_URXH)) & 0xFF);
    }
    return -1;
}

/* Non-blocking drain, for IRQ-driven logging and for the shell so it does
 * not spin on a read that will never complete. */
int uart_getc_timeout(uint32_t spins) {
    while (spins--) {
        int c = uart_getc();
        if (c >= 0) return c;
    }
    return -1;
}
