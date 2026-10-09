#include "secure_rom.h"
#include "uart.h"
#include "util.h"
#include "memory_map.h"

void dump_secure_rom(void) {
    uart_puts("Dumping SecureROM (0x100000000 - 0x10100000)...\n");
    
    const uint64_t start = SECURE_ROM_BASE;
    const uint64_t end = SECURE_ROM_BASE + SECURE_ROM_SIZE;
    const uint32_t chunk_size = 4096;
    
    for (uint64_t addr = start; addr < end; addr += chunk_size) {
        uint32_t remaining = end - addr;
        uint32_t chunk = (remaining < chunk_size) ? remaining : chunk_size;
        
        // Map the SecureROM region if not already mapped
        // The SecureROM is at 0x100000000 and should be accessible
        uint8_t *buf = (uint8_t *)0x180010000; // Use heap area as temp buffer
        
        // Copy from SecureROM to buffer
        for (uint32_t i = 0; i < chunk_size; i += 4) {
            uint32_t val = *(volatile uint32_t *)(start + addr + i);
            *(uint32_t *)(buf + i) = val;
        }
        
        // Output as hex dump
        for (uint32_t i = 0; i < chunk_size; i += 16) {
            uart_puts(utoa_hex(start + addr + i));
            uart_puts(": ");
            
            for (int j = 0; j < 16; j++) {
                if (j > 0) uart_puts(" ");
                uint8_t byte = *(volatile uint8_t *)(start + addr + i + j);
                uart_puts(utoa_hex(*(volatile uint8_t *)(start + addr + i + j)));
            }
            uart_puts("\n");
        }
        
        // Send over TCP if connected
        // tcp_send_frame(buf, chunk_size);
    }
    
    uart_puts("SecureROM dump complete.\n");
}

void dump_secure_rom_tcp(void) {
    // Stream SecureROM over TCP in 16KB chunks
    uart_puts("Streaming SecureROM over TCP...\n");
    
    // Implementation would send frames via TCP stack
    // tcp_send_frame(buf, len);
}
