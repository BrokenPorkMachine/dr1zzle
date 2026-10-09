#include "iboot_dump.h"
#include "uart.h"
#include "util.h"
#include "memory_map.h"

void dump_iboot(void) {
    uart_puts("Dumping iBoot...\n");
    uart_puts("iBoot typically at 0x800000000 (A11) or in recovery at 0x180000000\n");
    
    /* iBoot is loaded by iBEC in recovery mode */
    /* In DFU mode, we can try to boot recovery ramdisk which contains iBoot */
    
    uart_puts("To dump iBoot:\n");
    uart_puts("1. Boot recovery ramdisk (iBSS -> iBEC -> iBoot)\n");
    uart_puts("2. iBoot will load at its load address\n");
    uart_puts("3. Use memdump to dump iBoot region\n");
    
    /* Known iBoot load addresses */
    uart_puts("Known iBoot load addresses:\n");
    uart_puts("  A11 (T8015): 0x800000000\n");
    uart_puts("  A10 (T8010): 0x800000000\n");
    uart_puts("  A12 (T8020): 0x800000000\n");
}

void dump_iboot_recovery(void) {
    uart_puts("Dumping iBoot from recovery mode...\n");
    
    /* iBoot in recovery mode is at known address */
    /* This requires booting recovery mode first */
    uart_puts("Boot recovery mode first, then dump iBoot at its load address\n");
}
