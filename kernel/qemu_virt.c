#include <stdint.h>
#include <drizzle/console.h>
#include <drizzle/time.h>
enum { PL011_BASE = 0x09000000, PL011_FR = 0x18, PL011_FR_RXFE = 1u << 4, PL011_FR_TXFF = 1u << 5 };
static volatile uint32_t *const uart = (volatile uint32_t *)(uintptr_t)PL011_BASE;
void qemu_console_put(char character) { while (uart[PL011_FR / 4] & PL011_FR_TXFF) {} uart[0] = (uint32_t)character; }
int qemu_console_get(void) { while (uart[PL011_FR / 4] & PL011_FR_RXFE) {} return (int)(uart[0] & 0xffu); }
static uint64_t qemu_time_ms(void) { uint64_t ticks; __asm__ volatile("mrs %0, cntpct_el0" : "=r"(ticks)); return ticks / 24000u; }
void qemu_console_init(void) { drizzle_console_bind(qemu_console_put, qemu_console_get); drizzle_time_init(qemu_time_ms); }
