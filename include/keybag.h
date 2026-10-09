#ifndef KEYBAG_H
#define KEYBAG_H

void decrypt_keybag(const uint8_t *img4_data, uint32_t len);
void parse_kbag(const uint8_t *kbag, uint32_t len);
void decrypt_keybag_from_file(const char *path);

#endif
