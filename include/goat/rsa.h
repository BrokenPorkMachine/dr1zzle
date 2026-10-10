#ifndef GOAT_RSA_H
#define GOAT_RSA_H

#include <stdint.h>

/* Minimal RSA public-key operations for verifying the container signature.
 *
 * Only the public half is implemented, and only verification: the payload has
 * no private key and never needs one. The container carries the verifying key
 * as part of its certificate, so a sealed payload can be checked on the
 * device without the sealer's private material being present.
 *
 * Verification is PKCS#1 v1.5 with SHA-256, matching the signature the host
 * tool produces. That is deliberate -- v1.5 rather than PSS, because the
 * DigestInfo prefix comparison is easy to keep constant-time-ish and the
 * threat model here is integrity of a self-published container, not an
 * adversary who controls a signing oracle.
 */

#define GOAT_RSA_MAX_LIMBS 64   /* supports up to 4096-bit keys */

typedef struct {
    unsigned   limbs;                              /* 64-bit words in the modulus */
    uint64_t   n[GOAT_RSA_MAX_LIMBS];              /* modulus, little-endian limbs */
    uint64_t   e[GOAT_RSA_MAX_LIMBS];              /* public exponent */
    uint64_t   rr[GOAT_RSA_MAX_LIMBS];             /* R^2 mod n, Montgomery form */
    uint64_t   one[GOAT_RSA_MAX_LIMBS];            /* R mod n                  */
    uint64_t   k;                                  /* -n^-1 mod 2^64           */
    unsigned   e_bits;                             /* significant exponent bits */
} goat_rsa_pub_t;

/* Big-endian modulus/exponent octet strings, as the certificate stores them.
 * A leading zero octet is tolerated (DER INTEGER encodings sometimes carry
 * one). Returns 0 on success, -1 if the size is not one this build supports. */
int goat_rsa_pub_init(goat_rsa_pub_t *pub,
                      const uint8_t *n, unsigned n_len,
                      const uint8_t *e, unsigned e_len);

/* Verify a PKCS#1 v1.5 signature over an already-computed SHA-256 digest.
 * sig_len must equal the modulus length in bytes. Returns 0 on success. */
int goat_rsa_verify_sha256(const goat_rsa_pub_t *pub,
                           const uint8_t *sig, unsigned sig_len,
                           const uint8_t digest[32]);

#endif /* GOAT_RSA_H */
