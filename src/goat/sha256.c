/* SHA-256 (FIPS 180-4).
 *
 * Written from the specification rather than ported: message schedule is
 * computed in place, no word-width tricks. The only thing that matters for
 * correctness review is that the round function matches the published
 * constant table and rotation counts, which the host tests check against the
 * FIPS 180-4 example vectors.
 */

#include "goat/sha256.h"
#include "goat/util.h"

static const uint32_t K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

static uint32_t rotr(uint32_t x, unsigned n) {
    return (x >> n) | (x << (32 - n));
}

static void compress(uint32_t state[8], const uint8_t block[64]) {
    uint32_t w[64];

    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i * 4 + 0] << 24) |
               ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8)  |
               ((uint32_t)block[i * 4 + 3]);
    }
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

    for (int i = 0; i < 64; i++) {
        uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + S1 + ch + K[i] + w[i];
        uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + maj;

        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

void goat_sha256_init(goat_sha256_ctx *ctx) {
    ctx->state[0] = 0x6a09e667u; ctx->state[1] = 0xbb67ae85u;
    ctx->state[2] = 0x3c6ef372u; ctx->state[3] = 0xa54ff53au;
    ctx->state[4] = 0x510e527fu; ctx->state[5] = 0x9b05688cu;
    ctx->state[6] = 0x1f83d9abu; ctx->state[7] = 0x5be0cd19u;
    ctx->bits = 0;
    ctx->used = 0;
}

void goat_sha256_update(goat_sha256_ctx *ctx, const uint8_t *data, size_t len) {
    ctx->bits += (uint64_t)len * 8;

    if (ctx->used) {
        size_t fill = 64 - ctx->used;
        if (fill > len) fill = len;
        for (size_t i = 0; i < fill; i++) ctx->block[ctx->used + i] = data[i];
        ctx->used += fill;
        data += fill;
        len -= fill;
        if (ctx->used == 64) {
            compress(ctx->state, ctx->block);
            ctx->used = 0;
        }
    }

    while (len >= 64) {
        compress(ctx->state, data);
        data += 64;
        len -= 64;
    }

    if (len) {
        for (size_t i = 0; i < len; i++) ctx->block[i] = data[i];
        ctx->used = len;
    }
}

void goat_sha256_final(goat_sha256_ctx *ctx, uint8_t digest[GOAT_SHA256_DIGEST_SIZE]) {
    uint64_t bits = ctx->bits;
    uint8_t pad[72];
    uint32_t padlen = 1;

    while (((ctx->used + padlen) % 64) != 56) padlen++;
    pad[0] = 0x80;
    for (uint32_t i = 1; i < padlen; i++) pad[i] = 0;
    for (int i = 0; i < 8; i++) pad[padlen + i] = (uint8_t)(bits >> (56 - 8 * i));

    goat_sha256_update(ctx, pad, padlen + 8);

    /* The length we just fed is not message data; undo it so a caller that
     * keeps updating after final() does not see a bogus bit count. */
    ctx->bits = bits;

    for (int i = 0; i < 8; i++) {
        digest[i * 4 + 0] = (uint8_t)(ctx->state[i] >> 24);
        digest[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        digest[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
        digest[i * 4 + 3] = (uint8_t)(ctx->state[i]);
    }
}

void goat_sha256(const uint8_t *data, size_t len,
                 uint8_t digest[GOAT_SHA256_DIGEST_SIZE]) {
    goat_sha256_ctx ctx;
    goat_sha256_init(&ctx);
    goat_sha256_update(&ctx, data, len);
    goat_sha256_final(&ctx, digest);
}
