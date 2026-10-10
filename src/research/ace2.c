#include "ace2.h"
#include "uart.h"
#include "timer.h"
#include "util.h"
#include "memory_map.h"

static volatile uint32_t *ace2 = (volatile uint32_t *)ACE2_BASE;

static int ace2_valid_port(int port) {
    if (port >= 0 && port < ACE2_MAX_PORTS) {
        return 1;
    }
    uart_puts("ACE2: invalid port (expected 0-7)\n");
    return 0;
}

static inline uint32_t ace2_read(uint32_t offset) {
    return ace2[offset / 4];
}

static inline void ace2_write(uint32_t offset, uint32_t val) {
    ace2[offset / 4] = val;
}

void ace2_init(void) {
    uart_puts("Initializing ACE2/ACE3 USB Host Controller...\n");
    
    /* Read capability registers */
    uint32_t caplength = ace2_read(0x00);
    uint32_t hcsparams = ace2_read(0x04);
    uint32_t hccparams = ace2_read(0x08);
    
    uart_puts("CAPLENGTH: 0x"); uart_puts(utoa_hex(caplength)); uart_puts("\n");
    uart_puts("HCSPARAMS: 0x"); uart_puts(utoa_hex(hcsparams)); uart_puts("\n");
    uart_puts("HCCPARAMS: 0x"); uart_puts(utoa_hex(hccparams)); uart_puts("\n");
    
    /* Reset controller */
    ace2_write(0x10, 1); /* USBCMD: Run/Stop = 0, HCReset = 1 */
    if (timer_wait_reg(&ace2[0x10 / 4], 1, 0, 10000) != 0) {
        uart_puts("ACE2: controller reset timed out; refusing to configure it\n");
        return;
    }
    
    /* Set frame list base address */
    ace2_write(0x24, (uint32_t)0x180010000UL); /* PeriodicListBase */
    ace2_write(0x28, (uint32_t)0x180011000UL); /* AsyncListAddr */
    
    /* Configure USB command */
    ace2_write(0x10, 0x80000001); /* Run/Stop=1, AsyncScheduleEnable=1, PeriodicScheduleEnable=1 */
    
    uart_puts("ACE2 initialized\n");
}

void ace2_dump(void) {
    uart_puts("=== ACE2/ACE3 Register Dump ===\n");
    
    for (uint32_t offset = 0; offset <= 0x200; offset += 4) {
        if (offset % 64 == 0) {
            uart_puts("\n0x"); uart_puts(utoa_hex(ACE2_BASE + offset)); uart_puts(": ");
        }
        uart_puts(utoa_hex(ace2_read(offset)));
        uart_puts(" ");
        if ((offset + 4) % 64 == 0) uart_puts("\n");
    }
    uart_puts("\n");
    
    /* Port status */
    for (int port = 0; port < 8; port++) {
        uint32_t portsc = ace2_read(0x44 + port * 4);
        uart_puts("PORTSC["); uart_puts(utoa(port)); uart_puts("] = 0x");
        uart_puts(utoa_hex(portsc)); uart_puts("\n");
    }
}

void ace2_port_reset(int port) {
    if (!ace2_valid_port(port)) return;
    uint32_t portsc = ace2_read(0x44 + port * 4);
    ace2_write(0x44 + port * 4, portsc | (1 << 8)); /* Port Reset */
    timer_sleep_ms(50);
    ace2_write(0x44 + port * 4, portsc & ~(1 << 8));
    timer_sleep_ms(10);
}

void ace2_port_enable(int port) {
    if (!ace2_valid_port(port)) return;
    uint32_t portsc = ace2_read(0x44 + port * 4);
    ace2_write(0x44 + port * 4, portsc | (1 << 2)); /* Port Enable */
}

void ace2_dump_port_status(int port) {
    if (!ace2_valid_port(port)) return;
    uint32_t portsc = ace2_read(0x44 + port * 4);
    uart_puts("PORTSC["); uart_puts(utoa(port)); uart_puts("] = 0x");
    uart_puts(utoa_hex(portsc)); uart_puts("\n");
    
    uart_puts("  Current Connect Status: "); uart_puts((portsc & 1) ? "Connected" : "Disconnected"); uart_puts("\n");
    uart_puts("  Port Enabled: "); uart_puts((portsc & 4) ? "Yes" : "No"); uart_puts("\n");
    uart_puts("  Port Reset: "); uart_puts((portsc & 256) ? "In Progress" : "No"); uart_puts("\n");
    uart_puts("  Port Power: "); uart_puts((portsc & 2048) ? "On" : "Off"); uart_puts("\n");
    uart_puts("  Line Status: "); uart_puts(utoa((portsc >> 10) & 3)); uart_puts("\n");
    uart_puts("  Port Speed: "); 
    uint32_t speed = (portsc >> 26) & 3;
    if (speed == 0) uart_puts("Full Speed");
    else if (speed == 1) uart_puts("Low Speed");
    else if (speed == 2) uart_puts("High Speed");
    else uart_puts("SuperSpeed");
    uart_puts("\n");
}
