/*
 * Minimal UART driver for Stage 1 only
 * Only provides uart_early_init and uart_puts
 */

#include "uart.h"
#include "mmio.h"

#define UART_BASE       0x20A0C0000ULL
#define UART_UTRSTAT    0x18
#define UART_UTXH       0x20

#define UCON_RX_EN      (1 << 0)
#define UCON_TX_EN      (1 << 1)

void uart_early_init(void) {
    /* Disable UART */
    mmio_write32(UART_BASE + 0x04, 0);
    
    /* Set baud rate: 115200 @ 24 MHz */
    mmio_write32(UART_BASE + 0x28, 12);   /* UBRDIV = 12 */
    mmio_write32(UART_BASE + 0x2C, 0);    /* UDIVSLOT = 0 */
    
    /* Enable FIFO, reset */
    mmio_write32(UART_BASE + 0x08, 0x0F);
    
    /* Enable RX and TX */
    mmio_write32(UART_BASE + 0x04, UCON_RX_EN | UCON_TX_EN);
}

void uart_putc(char c) {
    /* Wait for TX buffer empty */
    while (!(mmio_read32(UART_BASE + UART_UTRSTAT) & (1 << 1))) {
        /* busy wait */
    }
    mmio_write32(UART_BASE + UART_UTXH, c);
}

void uart_puts(const char *s) {
    while (*s) {
        uart_putc(*s++);
    }
}