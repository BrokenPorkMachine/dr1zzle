#include <stdint.h>

#include "apfs.h"
#include "aes.h"
#include "keybag.h"
#include "goat/aes.h"

static uint8_t image[5u * 4096u];
static int callback_count;
static uint64_t callback_value;

static uint32_t rd32(uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void wr16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
}

static void wr32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

static void wr64(uint8_t *p, uint64_t v) {
    for (unsigned i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8u * i));
}

static int read_block(void *context, uint64_t block, uint8_t *out,
                      uint32_t length) {
    (void)context;
    if (block >= 5u || length != 4096u) return -1;
    for (uint32_t i = 0; i < length; i++) out[i] = image[block * 4096u + i];
    return 0;
}

static int visit(const apfs_btree_entry_t *entry, void *context) {
    (void)context;
    callback_count++;
    if (entry->value_len == 24u) callback_value = rd32((uint8_t *)entry->value);
    return 0;
}

static int sink(uint64_t offset, const uint8_t *data, uint32_t length,
                void *context) {
    (void)context;
    return offset == 0u && length == 5u && data[0] == 'h' ? 0 : -1;
}

/* Hardware-bound calls are not exercised by the host fixture. */
int aes_crypt_block(enum aes_key_slot slot, int decrypt,
                    const uint8_t input[16], uint8_t output[16],
                    const uint8_t iv[16]) {
    (void)slot; (void)decrypt; (void)input; (void)output; (void)iv;
    return -1;
}
void uart_puts(const char *s) { (void)s; }
const char *utoa(uint64_t value) { (void)value; return ""; }
const char *utoa_hex(uint64_t value) { (void)value; return ""; }

static int test_apfs(void) {
    apfs_container_info_t container;
    apfs_volume_info_t volume;
    apfs_extent_t extent;
    apfs_io_t io = { read_block, 0 };
    for (unsigned i = 0; i < sizeof(image); i++) image[i] = 0;

    wr32(image + 32u, 0x4e585342u);
    wr32(image + 36u, 4096u);
    wr64(image + 40u, 5u);
    wr32(image + 180u, 1u);
    wr64(image + 184u, 2u);

    wr32(image + 4096u + 32u, 0x41505342u);
    wr32(image + 4096u + 36u, 0u);
    wr64(image + 4096u + 128u, 0x22u);
    wr64(image + 4096u + 136u, 2u);
    image[4096u + 704u] = 'T';
    image[4096u + 705u] = 'e';
    image[4096u + 706u] = 's';
    image[4096u + 707u] = 't';

    /* A one-entry variable-key/value leaf node at block 3. */
    wr16(image + 2u * 4096u + 32u, 0u);
    wr16(image + 2u * 4096u + 34u, 0u);
    wr32(image + 2u * 4096u + 36u, 1u);
    wr16(image + 2u * 4096u + 40u, 32u);
    wr16(image + 2u * 4096u + 42u, 8u);
    image[2u * 4096u + 56u] = 0x11;
    wr32(image + 2u * 4096u + 60u, 5u);
    wr16(image + 2u * 4096u + 88u, 0u);
    wr16(image + 2u * 4096u + 90u, 1u);
    wr16(image + 2u * 4096u + 92u, 4u);
    wr16(image + 2u * 4096u + 94u, 24u);

    image[4u * 4096u + 0u] = 'h';
    image[4u * 4096u + 1u] = 'e';
    image[4u * 4096u + 2u] = 'l';
    image[4u * 4096u + 3u] = 'l';
    image[4u * 4096u + 4u] = 'o';

    if (apfs_open(&io, 5u, &container, &volume) != 0) return 1;
    if (container.block_size != 4096u || volume.fs_index != 0u ||
        volume.root_tree_oid != 2u) return 2;
    callback_count = 0;
    callback_value = 0;
    if (apfs_btree_walk(&io, 2u, 4096u, visit, 0) != 0 ||
        callback_count != 1 || callback_value != 5u) return 3;
    uint8_t extent_value[24] = {0};
    wr64(extent_value, 5u);
    wr64(extent_value + 8u, 4u);
    wr64(extent_value + 16u, 1u);
    if (apfs_decode_extent(7u, extent_value, sizeof(extent_value), &extent) != 0 ||
        apfs_read_extent(&io, &extent, 4096u, sink, 0) != 0) return 4;
    return 0;
}

static int test_aes(void) {
    static const uint8_t key[32] = {
        0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
        0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
    };
    static const uint8_t cipher[16] = {
        0xf3,0xee,0xd1,0xbd,0xb5,0xd2,0xa0,0x3c,0x06,0x4b,0x5a,0x7e,0x3d,0xb1,0x81,0xf8
    };
    static const uint8_t expected[16] = {
        0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a
    };
    goat_aes_key_t schedule;
    uint8_t block[16];
    for (unsigned i = 0; i < 16; i++) block[i] = cipher[i];
    if (goat_aes_decrypt_init(&schedule, key) != 0) return 1;
    goat_aes_decrypt_block(&schedule, block);
    for (unsigned i = 0; i < 16; i++) if (block[i] != expected[i]) return 2;
    return 0;
}

static int test_keybag(void) {
    uint8_t raw[44] = {0};
    keybag_entry_t entry[1];
    uint32_t count = 0;
    wr32(raw + 8u, 16u);
    for (unsigned i = 0; i < 16; i++) raw[28u + i] = (uint8_t)i;
    if (keybag_parse(raw, sizeof(raw), entry, 1u, &count) != 0 ||
        count != 1u || entry[0].key_size != 16u ||
        entry[0].wrapped[15] != 15u) return 1;
    return 0;
}

int main(void) {
    int rc = test_apfs();
    if (rc != 0) return 10 + rc;
    rc = test_aes();
    if (rc != 0) return 20 + rc;
    rc = test_keybag();
    if (rc != 0) return 30 + rc;
    return 0;
}
