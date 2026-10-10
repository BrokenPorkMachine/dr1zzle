/* AES engine access plus the small software path used for known vectors.
 *
 * GID/UID keys never leave the hardware slot.  The software helper exists
 * only for deterministic tests and for parsing a captured keybag after a
 * caller has supplied an ordinary 256-bit key.
 */

#include "aes.h"
#include "aes_a9.h"

#include "goat/aes.h"
#include "memory_map.h"
#include "mmio.h"
#include "timer.h"
#include "uart.h"

void aes_init(void) {
    aes_a9_init();
}

int aes_ready(void) {
    return 1;
}

int aes_crypt_block(enum aes_key_slot slot, int decrypt,
                    const uint8_t input[16], uint8_t output[16],
                    const uint8_t iv[16]) {
    return aes_a9_crypt_block(slot, decrypt, input, output, iv);
}

void aes_decrypt_gid(const uint8_t *ciphertext, uint8_t *plaintext,
                     const uint8_t *iv) {
    if (aes_crypt_block(AES_KEY_GID, 1, ciphertext, plaintext, iv) != 0 &&
        plaintext) {
        for (unsigned i = 0; i < 16; i++) plaintext[i] = 0;
    }
}

void aes_encrypt_gid(const uint8_t *plaintext, uint8_t *ciphertext,
                     const uint8_t *iv) {
    if (aes_crypt_block(AES_KEY_GID, 0, plaintext, ciphertext, iv) != 0 &&
        ciphertext) {
        for (unsigned i = 0; i < 16; i++) ciphertext[i] = 0;
    }
}

void aes_test(void) {
    aes_a9_test();
}

/* Software AES-CBC decrypt using goat AES implementation */
int aes_software_decrypt_cbc(const uint8_t key[32], const uint8_t iv[16],
                             const uint8_t *ciphertext, uint32_t length,
                             uint8_t *output) {
    if (!key || !iv || !ciphertext || !output || length == 0 ||
        (length % GOAT_AES_BLOCK_SIZE) != 0) return -1;
    
    goat_aes_key_t schedule;
    if (goat_aes_decrypt_init(&schedule, key) != 0) return -2;
    
    /* Copy ciphertext to output for in-place decryption */
    for (uint32_t i = 0; i < length; i++) output[i] = ciphertext[i];
    
    uint8_t iv_copy[GOAT_AES_IV_SIZE];
    for (int i = 0; i < GOAT_AES_IV_SIZE; i++) iv_copy[i] = iv[i];
    
    goat_aes_cbc_decrypt(&schedule, output, length / GOAT_AES_BLOCK_SIZE, iv_copy);
    return 0;
}
