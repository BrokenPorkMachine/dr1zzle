#ifndef CONSOLE_H
#define CONSOLE_H

#include <stdint.h>

/* One output path, many sinks.
 *
 * Every byte the payload emits for a human goes through here: the shell, the
 * bring-up log, the dump engine, the goat report. Sinks are bound rather than
 * hard-wired so the same code writes to the UART, the framebuffer console and
 * an open TCP session without any of them knowing about the others.
 *
 * That is what makes the TCP shell identical to the UART shell: it is not two
 * implementations that agree, it is the same code with an extra sink bound.
 */

typedef void (*console_sink_t)(char c);

void console_init(void);

/* Bind or detach a sink. A null pointer detaches that sink. Sinks must be
 * callable with any byte, including control characters, and must not call
 * back into the console. */
void console_bind_serial(console_sink_t sink);
void console_bind_display(console_sink_t sink);
void console_bind_net(console_sink_t sink);

/* Bitmask of attached sink kinds, for status output. */
#define CONSOLE_SINK_SERIAL  0x1
#define CONSOLE_SINK_DISPLAY 0x2
#define CONSOLE_SINK_NET     0x4
unsigned console_sinks(void);

void console_putc(char c);
void console_puts(const char *s);

/* Convenience for drivers that want "one printf-ish line" without pulling in
 * a formatter. Same utoa/utoa_hex helpers the rest of the payload uses. */
void console_put_uint(uint64_t value);
void console_put_hex(uint64_t value);

#endif /* CONSOLE_H */
