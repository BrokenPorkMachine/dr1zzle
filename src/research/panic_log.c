#include "panic_log.h"
#include "uart.h"
#include "util.h"
#include "memory_map.h"

void parse_panic_log(void) {
    uart_puts("Parsing panic log...\n");
    
    /* Panic log typically in SRAM at known location */
    /* Look for "panic" string in memory */
    
    uint64_t search_start = SRAM_BASE;
    uint64_t search_end = SRAM_BASE + SRAM_SIZE;
    uint32_t found = 0;
    
    for (uint64_t addr = search_start; addr < search_end; addr += 4) {
        uint32_t word = *(volatile uint32_t *)addr;
        if (word == 0x6E696361) { /* "anic" - part of "panic" */
            uart_puts("Found 'panic' at 0x"); uart_puts(utoa_hex(addr)); uart_puts("\n");
            dump_memory_range(addr, addr + 512);
            found = 1;
            break;
        }
    }
    
    if (!found) {
        uart_puts("Panic log not found in SRAM\n");
    }
}

void dump_panic_info(uint64_t panic_addr) {
    uart_puts("Panic info at 0x"); uart_puts(utoa_hex(panic_addr)); uart_puts(":\n");
    dump_memory_range(panic_addr, panic_addr + 1024);
}
