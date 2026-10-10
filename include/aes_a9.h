#ifndef AES_A9_H
#define AES_A9_H

#include <stdint.h>
#include <stddef.h>

#include "aes.h"

void aes_a9_init(void);
int aes_a9_crypt_block(enum aes_key_slot slot, int decrypt,
            const uint8_t input[16], uint8_t output[16],
            const uint8_t iv[16]);
void aes_a9_test(void);
void aes_cmd(const char *cmd, char *args);

#endif /* AES_A9_H */
