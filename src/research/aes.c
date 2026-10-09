#include "aes.h"
#include "uart.h"
#include "util.h"
#include "memory_map.h"

#define AES_BASE 0x235008000

#define AES_CTRL      0x00
#define AES_STATUS    0x04
#define AES_KEY_SEL   0x08
#define AES_IV        0x10
#define AES_FIFO_IN   0x30
#define AES_FIFO_OUT  0x34

#define AES_CTRL_START     (1 << 0)
#define AES_CTRL_DECRYPT   (1 << 1)
#define AES_CTRL_AES256    (1 << 2)
#define AES_CTRL_KEY_GID   (0 << 4)
#define AES_CTRL_KEY_UID   (1 << 4)
#define AES_CTRL_KEY_GID_UID (2 << 4)

static volatile uint32_t *aes = (volatile uint32_t *)AES_BASE;

static inline void aes_write(uint32_t offset, uint32_t val) {
    aes[offset / 4] = val;
}

static inline uint32_t aes_read(uint32_t offset) {
    return aes[offset / 4];
}

void aes_init(void) {
    /* Reset AES engine */
    aes_write(AES_CTRL, 0);
    timer_sleep_us(10);
}

void aes_test(void) {
    uart_puts("Testing AES engine...\n");
    
    /* Test with GID key */
    aes_write(AES_KEY_SEL, AES_CTRL_KEY_GID);
    aes_write(AES_CTRL, AES_CTRL_AES256 | AES_CTRL_KEY_GID);
    
    /* Set IV to zeros for test */
    for (int i = 0; i < 4; i++) {
        aes_write(AES_IV + i * 4, 0);
    }
    
    /* Encrypt test block */
    uint8_t plaintext[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                             0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    
    /* Write plaintext to FIFO_IN */
    for (int i = 0; i < 4; i++) {
        uint32_t word = 0;
        for (int j = 0; j < 4; j++) {
            word |= ((uint32_t)plaintext[i*4 + j]) << (j * 8);
        }
        ((volatile uint32_t *)AES_BASE)[AES_FIFO_IN / 4] = word;
    }
    
    /* Start encryption */
    aes_write(AES_CTRL, AES_CTRL_START | AES_CTRL_AES256 | AES_CTRL_KEY_GID);
    
    /* Wait for completion */
    while (aes_read(AES_STATUS) & (1 << 0)) {}
    
    /* Read ciphertext */
    uint8_t ciphertext[16];
    for (int i = 0; i < 4; i++) {
        uint32_t word = ((volatile uint32_t *)AES_BASE)[AES_FIFO_OUT / 4];
        for (int j = 0; j < 4; j++) {
            ciphertext[i*4 + j] = (word >> (j * 8)) & 0xFF;
        }
    }
    
    uart_puts("Plaintext:  ");
    for (int i = 0; i < 16; i++) {
        uart_puts(utoa_hex(plaintext[i])); uart_puts(" ");
    }
    uart_puts("\nCiphertext: ");
    for (int i = 0; i < 16; i++) {
        uart_puts(utoa_hex(((uint8_t *)0x180010000)[i])); uart_puts(" ");
    }
    uart_puts("\nAES test complete\n");
}

void aes_decrypt_gid(const uint8_t *ciphertext, uint8_t *plaintext, const uint8_t *iv) {
    aes_write(AES_KEY_SEL, AES_CTRL_KEY_GID);
    
    /* Load IV */
    for (int i = 0; i < 4; i++) {
        uint32_t word = 0;
        for (int j = 0; j < 4; j++) {
            word |= ((uint32_t)iv[i*4 + j]) << (j * 8);
        }
        ((volatile uint32_t *)AES_BASE)[AES_IV / 4 + i] = word;
    }
    
    aes_write(AES_CTRL, AES_CTRL_DECRYPT | AES_CTRL_AES256 | AES_CTRL_KEY_GID);
    
    for (int i = 0; i < 16; i += 16) {
        for (int j = 0; j < 4; j++) {
            uint32_t word = 0;
            for (int k = 0; k < 4; k++) {
                word |= ((uint32_t)ciphertext[i + j*4 + k]) << (k * 8);
            }
            ((volatile uint32_t *)AES_BASE)[AES_FIFO_IN / 4] = word;
        }
        
        aes_write(AES_CTRL, AES_CTRL_START | AES_CTRL_DECRYPT | AES_CTRL_AES256 | AES_CTRL_KEY_GID);
        while (((volatile uint32_t *)AES_BASE)[AES_STATUS / 4] & 1) {}
        
        for (int j = 0; j < 4; j++) {
            uint32_t word = ((volatile uint32_t *)AES_BASE)[AES_FIFO_OUT / 4 + j];
            for (int k = 0; k < 4; k++) {
                plaintext[j*4 + k] = (word >> (k * 8)) & 0xFF;
            }
        }
    }
}

void aes_encrypt_gid(const uint8_t *plaintext, uint8_t *ciphertext, const uint8_t *iv) {
    aes_write(AES_KEY_SEL, AES_CTRL_KEY_GID);
    
    for (int i = 0; i < 4; i++) {
        uint32_t word = 0;
        for (int j = 0; j < 4; j++) {
            word |= ((uint32_t)iv[i*4 + j]) << (j * 8);
        }
        ((volatile uint32_t *)AES_BASE)[AES_IV / 4 + i] = word;
    }
    
    aes_write(AES_CTRL, AES_CTRL_AES256 | AES_CTRL_KEY_GID);
    
    for (int i = 0; i < 16; i += 16) {
        for (int j = 0; j < 4; j++) {
            uint32_t word = 0;
            for (int k = 0; k < 4; k++) {
                word |= ((uint32_t)plaintext[i + j*4 + k]) << (k * 8);
            }
            ((volatile uint32_t *)AES_BASE)[AES_FIFO_IN / 4] = word;
        }
        
        ((volatile uint32_t *)AES_BASE)[AES_CTRL] = (1 << 0) | (1 << 2) | (0 << 4);
        while ((((volatile uint32_t *)AES_BASE)[AES_STATUS / 4]) & 1) {}
        
        for (int j = 0; j < 4; j++) {
            uint32_t word = ((volatile uint32_t *)AES_BASE)[AES_FIFO_OUT / 4 + j];
            for (int k = 0; k < 4; k++) {
                ciphertext[j*4 + k] = (word >> (k * 8)) & 0xFF;
            }
        }
    }
}
