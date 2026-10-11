/* Host-side stubs for UART in tests. */

#include <stdint.h>
#include <stdio.h>

void uart_putc(char c) {
    putchar(c);
}

void uart_puts(const char *s) {
    while (*s) {
        uart_putc(*s++);
    }
}

int uart_getc(void) {
    return -1;  // No input in tests
}