#ifndef AES_H
#define AES_H

#include <stdint.h>
#include <stddef.h>

typedef enum aes_key_slot {
    AES_KEY_USER = 0,
    AES_KEY_UID  = 1,
    AES_KEY_GID  = 2,
    AES_KEY_GID_UID = 3,
} aes_key_slot_t;

void aes_init(void);
int aes_ready(void);
int aes_crypt_block(enum aes_key_slot slot, int decrypt,
                    const uint8_t input[16], uint8_t output[16],
                    const uint8_t iv[16]);
void aes_decrypt_gid(const uint8_t *ciphertext, uint8_t *plaintext,
                     const uint8_t *iv);
void aes_encrypt_gid(const uint8_t *plaintext, uint8_t *ciphertext,
                     const uint8_t *iv);
void aes_test(void);

int aes_software_decrypt_cbc(const uint8_t key[32], const uint8_t iv[16],
                             const uint8_t *ciphertext, uint32_t length,
                             uint8_t *output);

#endif /* AES_H */