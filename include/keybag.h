#ifndef KEYBAG_H
#define KEYBAG_H

#include <stdint.h>

#define KEYBAG_MAX_ENTRIES 16u
#define KEYBAG_MAX_KEY_BYTES 64u

typedef struct {
    uint32_t wrap_type;
    uint32_t key_class;
    uint32_t key_size;
    uint8_t iv[16];
    uint8_t wrapped[KEYBAG_MAX_KEY_BYTES];
    uint32_t wrapped_len;
    int decrypted_valid;
} keybag_entry_t;

/* Parse DER KBAG entries (and the legacy fixed-width form used by early
 * captures) without retaining pointers into an untrusted upload. */
int keybag_parse(const uint8_t *data, uint32_t len,
                 keybag_entry_t *entries, uint32_t capacity,
                 uint32_t *count);
int keybag_decrypt_entries(keybag_entry_t *entries, uint32_t count);

void decrypt_keybag(const uint8_t *img4_data, uint32_t len);
void parse_kbag(const uint8_t *kbag, uint32_t len);
void decrypt_keybag_from_file(const char *path);

#endif
