#ifndef GOAT_SHA256_H
#define GOAT_SHA256_H

#include <stdint.h>
#include <stddef.h>

/* SHA-256, streaming interface plus a one-shot helper.
 *
 * Used for two things: the payload digest recorded in the sealed container,
 * and the digest the container's RSA signature is checked against. Both need
 * to agree bit-for-bit with the host tool that produced the container, so the
 * implementation follows FIPS 180-4 exactly.
 */

#define GOAT_SHA256_DIGEST_SIZE 32

typedef struct {
    uint32_t state[8];
    uint64_t bits;
    uint8_t  block[64];
    size_t   used;
} goat_sha256_ctx;

void goat_sha256_init(goat_sha256_ctx *ctx);
void goat_sha256_update(goat_sha256_ctx *ctx, const uint8_t *data, size_t len);
void goat_sha256_final(goat_sha256_ctx *ctx, uint8_t digest[GOAT_SHA256_DIGEST_SIZE]);

void goat_sha256(const uint8_t *data, size_t len,
                 uint8_t digest[GOAT_SHA256_DIGEST_SIZE]);

#endif /* GOAT_SHA256_H */
