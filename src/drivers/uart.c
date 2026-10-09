#include "memory_map.h"
#include "uart.h"

typedef struct {
    volatile uint32_t ulcon;      /* 0x00 */
    volatile uint32_t ucon;       /* 0x04 */
    volatile uint32_t ufcon;      /* 0x08 */
    volatile uint32_t umcon;      /* 0x0C */
    volatile uint32_t _pad[4];
    volatile uint32_t utrstat;    /* 0x18 */
    volatile uint32_t _pad2;
    volatile uint32_t utxh;       /* 0x20 */
    volatile uint32_t urxh;       /* 0x24 */
    volatile uint32_t ubrdiv;     /* 0x28 */
    volatile uint32_t udivslot;   /* 0x2C */
} uart_regs_t;

static volatile uart_regs_t *uart = (volatile uart_regs_t *)UART_BASE;

void uart_early_init(void) {
    /* ULCON: 8N1 */
    uart->ulcon = 0x3;
    
    /* UCON: Rx/Tx enable, PCLK */
    uart->ucon = 0x5;
    
    /* UFCON: FIFO enable, trigger level */
    uart->ufcon = 0x3;
    
    /* UMCON: disable modem control */
    uart->umcon = 0x0;
    
    /* Baud rate: PCLK / (16 * (UBRDIV + 1)) = baud */
    /* PCLK = 24 MHz typical on A11 */
    const uint32_t pclk = 24000000;
    const uint32_t baud = 115200;
    uart->ubrdiv = (pclk / (16 * baud)) - 1;
    uart->udivslot = 0;
}

void uart_putc(char c) {
    while ((uart->utrstat & 0x2) == 0) { /* Wait TX ready */ }
    uart->utxh = c;
}

void uart_puts(const char *s) {
    while (*s) {
        uart_putc(*s++);
    }
}

int uart_getc(void) {
    if (uart->utrstat & 0x1) { /* RX data ready */
        return uart->urxh & 0xFF;
    }
    return -1;
}
