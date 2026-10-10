#include "goat/util.h"

int goat_memeq(const void *a, const void *b, size_t len) {
    const uint8_t *pa = (const uint8_t *)a;
    const uint8_t *pb = (const uint8_t *)b;
    uint8_t diff = 0;

    for (size_t i = 0; i < len; i++) {
        diff |= (uint8_t)(pa[i] ^ pb[i]);
    }
    /* diff is zero only when every byte matched. */
    return diff == 0;
}

void goat_load_be64(const uint8_t *in, unsigned limbs, uint64_t *out) {
    for (unsigned i = 0; i < limbs; i++) {
        const uint8_t *p = in + (limbs - 1 - i) * 8;
        uint64_t v = 0;
        for (int b = 0; b < 8; b++) {
            v = (v << 8) | p[b];
        }
        out[i] = v;
    }
}

void goat_store_be64(uint8_t *out, unsigned limbs, const uint64_t *in) {
    for (unsigned i = 0; i < limbs; i++) {
        uint8_t *p = out + (limbs - 1 - i) * 8;
        uint64_t v = in[i];
        for (int b = 7; b >= 0; b--) {
            p[b] = (uint8_t)(v & 0xFF);
            v >>= 8;
        }
    }
}

void goat_hex(const uint8_t *data, size_t len, char separator, char *out,
              size_t out_size) {
    static const char digits[] = "0123456789abcdef";
    size_t used = 0;

    for (size_t i = 0; i < len; i++) {
        if (i && separator) {
            if (used + 1 >= out_size) break;
            out[used++] = separator;
        }
        if (used + 2 >= out_size) break;
        out[used++] = digits[(data[i] >> 4) & 0xF];
        out[used++] = digits[data[i] & 0xF];
    }
    out[used] = 0;
}
