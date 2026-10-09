#include "keybag.h"
#include "uart.h"
#include "util.h"
#include "memory_map.h"
#include "aes.h"

void decrypt_keybag(const uint8_t *img4_data, uint32_t len) {
    uart_puts("Decrypting KBAG from IMG4...\n");
    
    /* Parse IMG4 container */
    /* IMG4 structure: Magic(4) + Size(4) + Type(4) + Subtype(4) + [Data...] */
    if (len < 16) {
        uart_puts("IMG4 too small\n");
        return;
    }
    
    /* Check magic */
    if (img4_data[0] != 'I' || img4_data[1] != 'M' || img4_data[2] != 'G' || img4_data[3] != '4') {
        uart_puts("Invalid IMG4 magic\n");
        return;
    }
    
    /* Parse IMG4 elements */
    uint32_t offset = 16;
    while (offset < len) {
        if (offset + 12 > len) break;
        
        uint32_t type = *(uint32_t *)(img4_data + offset);
        uint32_t size = *(uint32_t *)(img4_data + offset + 4);
        uint32_t offset_val = *(uint32_t *)(img4_data + offset + 8);
        
        if (type == 0x4B424147) { /* 'KBAG' */
            uart_puts("Found KBAG at offset "); uart_puts(utoa_hex(offset)); uart_puts("\n");
            
            /* Parse KBAG structure */
            /* KBAG: SEQUENCE { SEQUENCE { wrap_type(4), key_class(4), key_size(4), iv(16), wrapped_key(var) } } */
            parse_kbag(img4_data + offset + 12, size - 12);
            return;
        }
        
        offset += 12 + size;
    }
    
    uart_puts("No KBAG found in IMG4\n");
}

void parse_kbag(const uint8_t *kbag, uint32_t len) {
    if (len < 4) return;
    
    /* Simple KBAG parser */
    uint32_t offset = 0;
    while (offset + 4 <= len) {
        uint32_t tag = *(uint32_t *)(kbag + offset);
        offset += 4;
        
        if (offset + 4 > len) break;
        uint32_t size = *(uint32_t *)(kbag + offset);
        offset += 4;
        
        if (offset + size > len) break;
        
        if (tag == 0x30) { /* SEQUENCE */
            parse_kbag(kbag + offset, size);
        } else if (tag == 0x02) { /* INTEGER - wrap_type */
            uint32_t wrap_type = 0;
            for (int i = 0; i < size && i < 4; i++) {
                wrap_type = (wrap_type << 8) | kbag[offset + i];
            }
            uart_puts("  Wrap type: "); uart_puts(utoa(wrap_type)); uart_puts("\n");
        } else if (tag == 0x04) { /* OCTET STRING - IV or wrapped key */
            uart_puts("  OCTET STRING (len="); uart_puts(utoa(size)); uart_puts("): ");
            for (int i = 0; i < size && i < 32; i++) {
                uart_puts(utoa_hex(kbag[offset + i])); uart_puts(" ");
            }
            uart_puts("\n");
            
            /* If this looks like a wrapped key (size 32-48), try to decrypt with GID */
            if (size >= 32 && size <= 48) {
                uint8_t decrypted[48];
                uint8_t iv[16] = {0};
                aes_decrypt_gid(kbag + offset, decrypted, iv);
                uart_puts("  Decrypted with GID: ");
                for (int i = 0; i < size && i < 32; i++) {
                    uart_puts(utoa_hex(decrypted[i])); uart_puts(" ");
                }
                uart_puts("\n");
            }
        }
        
        offset += size;
    }
}

void decrypt_keybag_from_file(const char *path) {
    uart_puts("KBAG decryption from file not implemented in bare metal\n");
    uart_puts("Use host tool to extract KBAG from IMG4, then decrypt with AES engine\n");
}
