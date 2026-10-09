#include "nand_dump.h"
#include "uart.h"
#include "util.h"
#include "memory_map.h"

void dump_nand_all(void) {
    uart_puts("Dumping full NAND...\n");
    
    /* Initialize NAND controller */
    nand_init();
    
    /* Read all blocks */
    for (uint32_t block = 0; block < nand_total_blocks(); block++) {
        if (nand_is_bad_block(block)) {
            uart_puts("Block "); uart_puts(utoa(block)); uart_puts(" BAD\n");
            continue;
        }
        
        for (uint32_t page = 0; page < nand_pages_per_block(); page++) {
            uint8_t buf[4096 + 128];
            nand_read_page(block, page, buf);
            
            /* Output or stream via TCP */
            uart_puts("Block "); uart_puts(utoa(block));
            uart_puts(" Page "); uart_puts(utoa(page));
            uart_puts(" OK\n");
        }
    }
}

void dump_nand_range(uint32_t start_block, uint32_t end_block) {
    uart_puts("Dumping NAND blocks "); uart_puts(utoa(start_block));
    uart_puts(" to "); uart_puts(utoa(end_block)); uart_puts("\n");
    
    nand_init();
    
    for (uint32_t block = start_block; block <= end_block; block++) {
        if (nand_is_bad_block(block)) {
            uart_puts("Block "); uart_puts(utoa(block)); uart_puts(" BAD\n");
            continue;
        }
        
        for (uint32_t page = 0; page < nand_pages_per_block(); page++) {
            uint8_t buf[4096 + 128];
            nand_read_page(block, page, buf);
            
            /* Output page data */
            uart_puts("Block "); uart_puts(utoa(block));
            uart_puts(" Page "); uart_puts(utoa(page));
            uart_puts(" OK\n");
        }
    }
}

void extract_apfs_files(void) {
    uart_puts("Extracting APFS files...\n");
    
    nand_init();
    
    /* Locate APFS container */
    /* Parse checkpoint -> superblock -> volume */
    /* B-tree traversal -> file read */
    
    const char *paths[] = {
        "/System/Library/Caches/com.apple.kernelcaches/kernelcache",
        "/usr/standalone/firmware/iBoot",
        "/usr/standalone/firmware/sep-firmware",
    };
    
    for (int i = 0; i < 3; i++) {
        uart_puts("Extracting: "); uart_puts(paths[i]); uart_puts("\n");
        /* Extract and stream via TCP */
    }
}
