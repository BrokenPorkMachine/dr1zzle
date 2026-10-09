#include "uart.h"
#include "util.h"
#include "memory_map.h"

void sync_handler(uint64_t esr, uint64_t far) {
    uint64_t ec = (esr >> 26) & 0x3F;
    uint64_t iss = esr & 0xFFFFFF;
    uart_puts("\nSYNC: EC=");
    uart_puts(utoa_hex(ec));
    uart_puts(" ISS=");
    uart_puts(utoa_hex(iss));
    uart_puts(" FAR=");
    uart_puts(utoa_hex(far));
    uart_puts("\n");
    while (1) { __asm__ volatile("wfe"); }
}

void irq_handler(void) {
    volatile uint32_t *timer = (volatile uint32_t *)TIMER_BASE;
    *timer = 0;
}

void fiq_handler(void) {
    uart_puts("FIQ\n");
}

void serror_handler(void) {
    uart_puts("SERROR\n");
    while (1) { __asm__ volatile("wfe"); }
}

void exception_init(void) {
    /* Exception vectors already installed in start.S */
}
