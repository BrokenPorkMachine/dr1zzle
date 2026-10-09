#ifndef AES_H
#define AES_H

void aes_init(void);
void aes_test(void);
void aes_decrypt_gid(const uint8_t *ciphertext, uint8_t *plaintext, const uint8_t *iv);
void aes_encrypt_gid(const uint8_t *plaintext, uint8_t *ciphertext, const uint8_t *iv);

#endif
