#ifndef GOAT_AES_H
#define GOAT_AES_H

#include <stdint.h>
#include <stddef.h>

/* AES-256 in CBC mode, decrypt direction only.
 *
 * The container format seals the payload with AES-256-CBC: the host encrypts,
 * the device decrypts with the key the user supplies. Only the inverse cipher
 * is implemented because that is the only direction this payload runs.
 */

#define GOAT_AES_KEY_SIZE   32   /* 256-bit key  */
#define GOAT_AES_BLOCK_SIZE 16   /* AES block    */
#define GOAT_AES_IV_SIZE    16   /* CBC IV       */
#define GOAT_AES_ROUND_KEYS 60 /* 4 words * (14 rounds + initial key) */

typedef struct {
    uint32_t round_keys[GOAT_AES_ROUND_KEYS];
} goat_aes_key_t;

int goat_aes_decrypt_init(goat_aes_key_t *key, const uint8_t key_bytes[GOAT_AES_KEY_SIZE]);

/* Decrypts one block in place. */
void goat_aes_decrypt_block(const goat_aes_key_t *key, uint8_t block[GOAT_AES_BLOCK_SIZE]);

/* CBC decrypt of `blocks` blocks. iv is updated to the final ciphertext block
 * so chained regions can be decrypted without re-reading memory. */
void goat_aes_cbc_decrypt(const goat_aes_key_t *key, uint8_t *data, size_t blocks,
                          uint8_t iv[GOAT_AES_IV_SIZE]);

/* Strip CBC padding after decrypting: PKCS#7. Returns the unpadded length,
 * or (uint64_t)-1 if the padding is not a valid PKCS#7 block for this size. */
uint64_t goat_aes_unpad(const uint8_t *data, size_t blocks_bytes);

#endif /* GOAT_AES_H */
