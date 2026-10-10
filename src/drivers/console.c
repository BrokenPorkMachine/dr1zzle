/* Console: fan-out of text output to the attached sinks.
 *
 * Serial is the primary sink and is bound first; the display mirror and the
 * TCP session sink are optional and can come and go at runtime. Ordering is
 * serial, then display, then net: the UART log is the fastest, and a slow
 * raster or network write never delays the byte stream that is actually
 * logging the failure.
 *
 * A sink is safely detachable at any time because nothing here holds a
 * reference to one across a call.
 */

#include "console.h"
#include "uart.h"
#include "util.h"

static console_sink_t sink_serial;
static console_sink_t sink_display;
static console_sink_t sink_net;

void console_init(void) {
    sink_serial = uart_putc;
    sink_display = 0;
    sink_net = 0;
}

void console_bind_serial(console_sink_t sink) {
    sink_serial = sink ? sink : uart_putc;
}

void console_bind_display(console_sink_t sink) {
    sink_display = sink;
}

void console_bind_net(console_sink_t sink) {
    sink_net = sink;
}

unsigned console_sinks(void) {
    unsigned mask = 0;
    if (sink_serial) mask |= CONSOLE_SINK_SERIAL;
    if (sink_display) mask |= CONSOLE_SINK_DISPLAY;
    if (sink_net) mask |= CONSOLE_SINK_NET;
    return mask;
}

void console_putc(char c) {
    if (sink_serial) sink_serial(c);
    if (sink_display) sink_display(c);
    if (sink_net) sink_net(c);
}

void console_puts(const char *s) {
    while (*s) console_putc(*s++);
}

void console_put_uint(uint64_t value) {
    console_puts(utoa(value));
}

void console_put_hex(uint64_t value) {
    console_puts(utoa_hex(value));
}
