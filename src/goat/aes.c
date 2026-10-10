/* AES-256-CBC decryption (FIPS 197).
 *
 * Straight from the specification: byte-oriented S-box lookup, the standard
 * key schedule for Nk=8/Nr=14, and the inverse cipher with InvShiftRows,
 * InvSubBytes and InvMixColumns. There is no T-table or AES-NI here because
 * this payload has to run before the MMU is on and with caches off; a
 * table-driven implementation buys nothing on that path.
 *
 * Field multiplication is done with the generic GF(2^8) routine rather than
 * open-coded pextrm/xor tricks. InvMixColumns is four of them per column and
 * the payload runs this a handful of times per container: clarity wins.
 */

#include "goat/aes.h"
#include "goat/util.h"

static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
};

/* Inverse S-box, derived once and used by InvSubBytes. */
static uint8_t inv_sbox[256];
static int     inv_sbox_ready;

static void build_inv_sbox(void) {
    for (int i = 0; i < 256; i++) {
        inv_sbox[sbox[i]] = (uint8_t)i;
    }
    inv_sbox_ready = 1;
}

static const uint8_t rcon[] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

#define AES_NK 8    /* 256-bit key: eight words */
#define AES_NR 14   /* fourteen rounds      */

static uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    while (b) {
        if (b & 1) p ^= a;
        uint8_t hi = a & 0x80;
        a <<= 1;
        if (hi) a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

static uint32_t sub_word(uint32_t w) {
    return ((uint32_t)sbox[(w >> 24) & 0xFF] << 24) |
           ((uint32_t)sbox[(w >> 16) & 0xFF] << 16) |
           ((uint32_t)sbox[(w >> 8) & 0xFF] << 8)   |
           ((uint32_t)sbox[w & 0xFF]);
}

static uint32_t rot_word(uint32_t w) {
    return (w << 8) | (w >> 24);
}

int goat_aes_decrypt_init(goat_aes_key_t *key, const uint8_t key_bytes[GOAT_AES_KEY_SIZE]) {
    if (!inv_sbox_ready) build_inv_sbox();

    uint32_t *w = key->round_keys;
    const unsigned total_words = 4 * (AES_NR + 1);

    for (unsigned i = 0; i < AES_NK; i++) {
        w[i] = ((uint32_t)key_bytes[4 * i + 0] << 24) |
               ((uint32_t)key_bytes[4 * i + 1] << 16) |
               ((uint32_t)key_bytes[4 * i + 2] << 8)  |
               ((uint32_t)key_bytes[4 * i + 3]);
    }

    for (unsigned i = AES_NK; i < total_words; i++) {
        uint32_t temp = w[i - 1];
        if (i % AES_NK == 0) {
            temp = sub_word(rot_word(temp)) ^ ((uint32_t)rcon[i / AES_NK - 1] << 24);
        } else if (i % AES_NK == 4) {
            temp = sub_word(temp);
        }
        w[i] = w[i - AES_NK] ^ temp;
    }
    return 0;
}

/* State layout: byte 4*c + r is state[r][c], i.e. the column-major layout
 * the specification draws reading down each column first. */
static void add_round_key(uint8_t *st, const uint32_t *rk) {
    for (unsigned c = 0; c < 4; c++) {
        uint32_t word = rk[c];
        st[4 * c + 0] ^= (uint8_t)(word >> 24);
        st[4 * c + 1] ^= (uint8_t)(word >> 16);
        st[4 * c + 2] ^= (uint8_t)(word >> 8);
        st[4 * c + 3] ^= (uint8_t)(word);
    }
}

static void inv_sub_bytes(uint8_t *st) {
    for (int i = 0; i < 16; i++) st[i] = inv_sbox[st[i]];
}

static void inv_shift_rows(uint8_t *st) {
    uint8_t tmp[16];
    for (unsigned c = 0; c < 4; c++) {
        for (unsigned r = 0; r < 4; r++) {
            /* Row r is rotated right by r: new[r][c] = old[r][(c - r) mod 4] */
            unsigned src_c = (c + 4 - r) % 4;
            tmp[4 * c + r] = st[4 * src_c + r];
        }
    }
    for (int i = 0; i < 16; i++) st[i] = tmp[i];
}

static void inv_mix_columns(uint8_t *st) {
    for (unsigned c = 0; c < 4; c++) {
        uint8_t *col = st + 4 * c;
        uint8_t a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
        col[0] = gmul(a0, 0x0e) ^ gmul(a1, 0x0b) ^ gmul(a2, 0x0d) ^ gmul(a3, 0x09);
        col[1] = gmul(a0, 0x09) ^ gmul(a1, 0x0e) ^ gmul(a2, 0x0b) ^ gmul(a3, 0x0d);
        col[2] = gmul(a0, 0x0d) ^ gmul(a1, 0x09) ^ gmul(a2, 0x0e) ^ gmul(a3, 0x0b);
        col[3] = gmul(a0, 0x0b) ^ gmul(a1, 0x0d) ^ gmul(a2, 0x09) ^ gmul(a3, 0x0e);
    }
}

void goat_aes_decrypt_block(const goat_aes_key_t *key, uint8_t block[GOAT_AES_BLOCK_SIZE]) {
    if (!inv_sbox_ready) build_inv_sbox();

    const uint32_t *rk = key->round_keys;

    add_round_key(block, rk + 4 * AES_NR);

    for (int round = AES_NR - 1; round > 0; round--) {
        inv_shift_rows(block);
        inv_sub_bytes(block);
        add_round_key(block, rk + 4 * round);
        inv_mix_columns(block);
    }

    inv_shift_rows(block);
    inv_sub_bytes(block);
    add_round_key(block, rk);
}

void goat_aes_cbc_decrypt(const goat_aes_key_t *key, uint8_t *data, size_t blocks,
                          uint8_t iv[GOAT_AES_IV_SIZE]) {
    for (size_t b = 0; b < blocks; b++) {
        uint8_t *cipher = data + b * GOAT_AES_BLOCK_SIZE;

        /* The chaining value is this block's ciphertext, so keep a copy
         * before decrypting in place. */
        uint8_t prev[GOAT_AES_BLOCK_SIZE];
        for (int i = 0; i < GOAT_AES_BLOCK_SIZE; i++) prev[i] = cipher[i];

        goat_aes_decrypt_block(key, cipher);

        for (int i = 0; i < GOAT_AES_BLOCK_SIZE; i++) {
            cipher[i] ^= iv[i];
            iv[i] = prev[i];
        }
    }
}

uint64_t goat_aes_unpad(const uint8_t *data, size_t blocks_bytes) {
    if (blocks_bytes == 0 || (blocks_bytes % GOAT_AES_BLOCK_SIZE) != 0) {
        return (uint64_t)-1;
    }

    uint8_t pad = data[blocks_bytes - 1];
    if (pad == 0 || pad > GOAT_AES_BLOCK_SIZE) return (uint64_t)-1;
    for (uint32_t i = 0; i < pad; i++) {
        if (data[blocks_bytes - 1 - i] != pad) return (uint64_t)-1;
    }
    return blocks_bytes - pad;
}
