#include "kernel_patch.h"
#include "uart.h"
#include "util.h"
#include "memory_map.h"

void patch_kernel_ram(uint64_t kernel_base, const uint8_t *patches, uint32_t num_patches) {
    uart_puts("Patching kernel at 0x"); uart_puts(utoa_hex(kernel_base)); uart_puts("\n");
    
    for (uint32_t i = 0; i < num_patches; i++) {
        uint64_t addr = kernel_base + patches[i * 16];
        uint8_t original = patches[i * 16 + 8];
        uint8_t replacement = patches[i * 16 + 9];
        
        uint8_t current = *(volatile uint8_t *)addr;
        if (current != original) {
            uart_puts("Warning: Patch at 0x"); uart_puts(utoa_hex(addr));
            uart_puts(" expected 0x"); uart_puts(utoa_hex(original));
            uart_puts(" but found 0x"); uart_puts(utoa_hex(current)); uart_puts("\n");
            continue;
        }
        
        *(volatile uint8_t *)addr = replacement;
        
        /* Flush I-cache for this line */
        uint64_t va = addr;
        __asm__ volatile("dc cvac, %0" :: "r"(va));
        __asm__ volatile("ic ivau, %0" :: "r"(va));
        __asm__ volatile("dsb sy; isb" ::: "memory");
        
        uart_puts("Patched 0x"); uart_puts(utoa_hex(addr));
        uart_puts(" 0x"); uart_puts(utoa_hex(original));
        uart_puts(" -> 0x"); uart_puts(utoa_hex(replacement)); uart_puts("\n");
    }
}

void kernel_patch_amfi(void) {
    uart_puts("Applying AMFI bypass patches...\n");
    /* AMFI patches for iOS kernel - offsets vary by version */
    uart_puts("AMFI patches are version-specific\n");
}

void kernel_patch_code_sign(void) {
    uart_puts("Applying code signing bypass patches...\n");
    uart_puts("Code signing patches are version-specific\n");
}
