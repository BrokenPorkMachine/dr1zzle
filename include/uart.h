#ifndef UART_H
#define UART_H

#include <stddef.h>
#include <stdint.h>

void uart_early_init(void);
void uart_putc(char c);
void uart_puts(const char *s);
int uart_getc(void);

/* Bounded poll so a shell loop does not spin forever on absent input. */
int uart_getc_timeout(uint32_t spins);

/* --- output capture -------------------------------------------------------
 *
 * While a capture is active, every byte the payload writes to the UART is
 * also delivered to the sink. That is what lets the goatloader answer a
 * command it ran on behalf of a remote session with exactly what the serial
 * console would have shown: the shell, the dump engine and the goat report
 * all print through uart_putc(), so there is one capture point instead of
 * one per printing call site.
 *
 * Captures do not nest. A sink must not itself print.
 */
typedef void (*uart_capture_fn)(const uint8_t *data, size_t len);

void uart_capture_begin(uart_capture_fn sink);
void uart_capture_end(void);

#endif /* UART_H */