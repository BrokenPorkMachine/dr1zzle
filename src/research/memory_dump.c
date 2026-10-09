#include "memory_dump.h"
#include "uart.h"
#include "util.h"
#include "memory_map.h"

void dump_memory_range(uint64_t start, uint64_t end) {
    uart_puts("Dumping memory from 0x"); uart_puts(utoa_hex(start));
    uart_puts(" to 0x"); uart_puts(utoa_hex(end)); uart_puts("\n");
    
    for (uint64_t addr = start; addr < end; addr += 256) {
        uint32_t chunk = (end - addr < 256) ? (end - addr) : 256;
        
        // Output as hex dump
        for (uint32_t i = 0; i < chunk; i += 16) {
            uart_puts(utoa_hex(start + addr + i));
            uart_puts(": ");
            
            for (int j = 0; j < 16 && i + j < chunk; j++) {
                if (j > 0) uart_puts(" ");
                uint8_t byte = *(volatile uint8_t *)(start + addr + i + j);
                uart_puts(utoa_hex(byte));
            }
            uart_puts("\n");
        }
    }
    
    uart_puts("Memory dump complete.\n");
}

void dump_dram(void) {
    uart_puts("Dumping DRAM...\n");
    uart_puts("DRAM base: 0x"); uart_puts(utoa_hex(NAND_BASE)); uart_puts("\n");
    dump_memory_range(NAND_BASE, NAND_BASE + 0x8000000); // 128MB
}

void dump_sram(void) {
    uart_puts("Dumping SRAM...\n");
    uart_puts("SRAM base: 0x"); uart_puts(utoa_hex(SRAM_BASE)); uart_puts("\n");
    dump_memory_range(SRAM_BASE, SRAM_BASE + SRAM_SIZE);
}

void dump_baseband(void) {
    uart_puts("Dumping Baseband memory...\n");
    uart_puts("Baseband typically at 0x20A000000 region\n");
    dump_memory_range(0x20A000000, 0x20A000000 + 0x100000);
}

void dump_iboot(void) {
    uart_puts("Dumping iBoot...\n");
    uart_puts("iBoot typically at 0x800000000 or in recovery at 0x180000000\n");
    dump_memory_range(0x800000000, 0x800000000 + 0x100000);
}

void dump_gid(void) {
    uart_puts("Dumping GID key...\n");
    uart_puts("GID key is hardware-bound, only accessible via AES engine\n");
    uart_puts("Use 'aes test' to verify GID key access\n");
}

void dump_uid(void) {
    uart_puts("Dumping UID key...\n");
    uart_puts("UID key is hardware-bound, only accessible via AES engine\n");
    uart_puts("Use 'aes test' to verify UID key access\n");
}
