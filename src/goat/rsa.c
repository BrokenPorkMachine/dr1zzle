/* RSA verification: Montgomery multiplication plus PKCS#1 v1.5 unpadding.
 *
 * The modulus is odd, which is what makes Montgomery's trick applicable, and
 * a 64-limb ceiling covers the key sizes this container format uses. Field
 * arithmetic is schoolbook with CIOS-style reduction, using 64x64->128
 * multiplies; that is the whole reason this is cheap on a 64-bit CPU.
 *
 * This is verification only. There is no CRT, no blinding and no private key,
 * because a device that could recompute signatures would not need to verify
 * signatures.
 */

#include "goat/rsa.h"
#include "goat/util.h"

#define MAX_L GOAT_RSA_MAX_LIMBS

/* --- field helpers ------------------------------------------------------- */

/* Compare a[0..s) with b[0..s): returns -1, 0 or 1 (a<b, a==b, a>b). */
static int limb_cmp(const uint64_t *a, const uint64_t *b, unsigned s) {
    for (int i = (int)s - 1; i >= 0; i--) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}

/* a[0..s) -= b[0..s), assuming a >= b. */
static void limb_sub(uint64_t *a, const uint64_t *b, unsigned s) {
    unsigned __int128 borrow = 0;
    for (unsigned i = 0; i < s; i++) {
        unsigned __int128 diff = (unsigned __int128)a[i] - b[i] - borrow;
        a[i] = (uint64_t)diff;
        borrow = (diff >> 64) ? 1 : 0;
    }
}

/* Montgomery multiplication: T = a*b*R^-1 mod n, R = 2^(64*s).
 *
 * Both inputs must already be reduced (< n) and in the caller's limb array.
 * The scratch is one limb larger than the modulus so the reduction carry can
 * spill out of the loop. */
static void mont_mul(const uint64_t *a, const uint64_t *b, uint64_t *out,
                     const goat_rsa_pub_t *pub) {
    unsigned s = pub->limbs;
    const uint64_t *n = pub->n;
    uint64_t inv = pub->k;

    uint64_t t[MAX_L + 2];
    for (unsigned i = 0; i < s + 2; i++) t[i] = 0;

    for (unsigned i = 0; i < s; i++) {
        /* t += a * b[i] */
        unsigned __int128 carry = 0;
        for (unsigned j = 0; j < s; j++) {
            unsigned __int128 sum = (unsigned __int128)t[j]
                                  + (unsigned __int128)a[j] * b[i] + carry;
            t[j] = (uint64_t)sum;
            carry = sum >> 64;
        }
        unsigned __int128 tail = (unsigned __int128)t[s] + carry;
        t[s] = (uint64_t)tail;
        t[s + 1] = (uint64_t)(tail >> 64);

        /* m = t[0] * (-n^-1) mod 2^64 */
        uint64_t m = (uint64_t)(t[0] * inv);

        /* t += m * n, which cancels t[0] by construction */
        unsigned __int128 c = ((unsigned __int128)m * n[0] + t[0]) >> 64;
        for (unsigned j = 1; j < s; j++) {
            unsigned __int128 sum = (unsigned __int128)t[j]
                                  + (unsigned __int128)m * n[j] + c;
            t[j - 1] = (uint64_t)sum;
            c = sum >> 64;
        }
        unsigned __int128 tail2 = (unsigned __int128)t[s] + c;
        t[s - 1] = (uint64_t)tail2;
        t[s] = t[s + 1] + (uint64_t)(tail2 >> 64);
    }

    /* One conditional subtraction is enough: t < 2n on exit. */
    if (limb_cmp(t, n, s) >= 0) {
        limb_sub(t, n, s);
    }
    if (limb_cmp(t, n, s) >= 0) {
        limb_sub(t, n, s);
    }

    for (unsigned i = 0; i < s; i++) out[i] = t[i];
}

/* out = 2*a mod n, in place. */
static void mod_double(uint64_t *a, const uint64_t *n, unsigned s) {
    uint64_t carry = a[s - 1] >> 63;
    for (int i = (int)s - 1; i > 0; i--) {
        a[i] = (a[i] << 1) | (a[i - 1] >> 63);
    }
    a[0] <<= 1;
    if (carry || limb_cmp(a, n, s) >= 0) {
        limb_sub(a, n, s);
    }
}

/* Load a big-endian octet string into little-endian limbs, left-padding. */
static int load_be(const uint8_t *in, unsigned in_len, unsigned limbs,
                   uint64_t *out) {
    while (in_len > 1 && in[0] == 0) {
        in++;
        in_len--;
    }
    if (in_len > limbs * 8) return -1;

    for (unsigned i = 0; i < limbs; i++) out[i] = 0;

    /* Fill from the least significant octet. */
    for (unsigned i = 0; i < in_len; i++) {
        uint8_t byte = in[in_len - 1 - i];
        unsigned limb = i / 8;
        unsigned shift = (i % 8) * 8;
        out[limb] |= (uint64_t)byte << shift;
    }
    return 0;
}

int goat_rsa_pub_init(goat_rsa_pub_t *pub,
                      const uint8_t *n, unsigned n_len,
                      const uint8_t *e, unsigned e_len) {
    /* Trim a leading zero octet so a DER INTEGER with a sign bit set still
     * counts as one byte of modulus. */
    while (n_len > 1 && n[0] == 0) { n++; n_len--; }
    while (e_len > 1 && e[0] == 0) { e++; e_len--; }

    unsigned limbs = (unsigned)((n_len + 7) / 8);
    if (limbs == 0 || limbs > GOAT_RSA_MAX_LIMBS) return -1;

    pub->limbs = limbs;

    if (load_be(n, n_len, limbs, pub->n) != 0) return -1;
    if (load_be(e, e_len, limbs, pub->e) != 0) return -1;

    /* Most significant significant bit position of the exponent. */
    unsigned e_bits = 0;
    for (int i = limbs - 1; i >= 0; i--) {
        if (pub->e[i]) {
            uint64_t v = pub->e[i];
            unsigned top = 0;
            while (v) { v >>= 1; top++; }
            e_bits = (unsigned)i * 64 + top;
            break;
        }
    }
    pub->e_bits = e_bits;

    /* -n^-1 mod 2^64 by Newton iteration: every step doubles the number of
     * correct bits, so five steps from an 8-bit seed are enough. */
    uint64_t inv = pub->n[0];
    for (int i = 0; i < 5; i++) {
        inv = inv * (2 - pub->n[0] * inv);
    }
    pub->k = (uint64_t)(0 - inv);

    /* R mod n by doubling a single bit n_bits times, then R^2 mod n in
     * Montgomery form. */
    uint64_t r[MAX_L];
    for (unsigned i = 0; i < limbs; i++) r[i] = 0;
    r[0] = 1;
    for (unsigned i = 0; i < limbs * 64; i++) {
        mod_double(r, pub->n, limbs);
    }
    for (unsigned i = 0; i < limbs; i++) pub->one[i] = r[i];

    mont_mul(r, r, pub->rr, pub);

    return 0;
}

/* out = a^e mod n, square-and-multiply from the exponent's top bit down. */
static void modexp(const goat_rsa_pub_t *pub, const uint64_t *a, uint64_t *out) {
    unsigned s = pub->limbs;
    uint64_t acc[MAX_L], base[MAX_L];

    for (unsigned i = 0; i < s; i++) acc[i] = pub->one[i];
    for (unsigned i = 0; i < s; i++) base[i] = a[i];

    for (int bit = (int)pub->e_bits - 1; bit >= 0; bit--) {
        mont_mul(acc, acc, acc, pub);
        if ((pub->e[bit / 64] >> (bit % 64)) & 1) {
            mont_mul(acc, base, acc, pub);
        }
    }

    /* Leave Montgomery form. */
    uint64_t one[8] = {1};
    for (unsigned i = 1; i < 8; i++) one[i] = 0;
    mont_mul(acc, one, out, pub);
}

/* DigestInfo prefix for SHA-256 (RFC 8017 section 9.2 note 1). */
static const uint8_t digestinfo_sha256[] = {
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20
};

int goat_rsa_verify_sha256(const goat_rsa_pub_t *pub,
                           const uint8_t *sig, unsigned sig_len,
                           const uint8_t digest[32]) {
    unsigned s = pub->limbs;
    if (sig_len != s * 8) return -1;

    uint64_t sig_limbs[MAX_L];
    if (load_be(sig, sig_len, s, sig_limbs) != 0) return -1;

    if (limb_cmp(sig_limbs, pub->n, s) >= 0) return -1;

    uint64_t result[MAX_L];
    modexp(pub, sig_limbs, result);

    /* Back to a big-endian octet string of exactly sig_len bytes. */
    uint8_t em[MAX_L * 8];
    goat_store_be64(em, s, result);

    /* EM = 0x00 0x01 PS 0x00 T, with at least eight 0xFF bytes of PS. */
    if (em[0] != 0x00 || em[1] != 0x01) return -1;

    unsigned pos = 2;
    while (pos < sig_len && em[pos] == 0xFF) pos++;
    if (pos < 10 || pos >= sig_len) return -1;   /* fewer than 8 FF bytes */
    if (em[pos] != 0x00) return -1;
    pos++;

    unsigned t_len = (unsigned)sizeof(digestinfo_sha256) + 32;
    if (pos + t_len > sig_len) return -1;

    if (!goat_memeq(em + pos, digestinfo_sha256, sizeof(digestinfo_sha256))) {
        return -1;
    }
    return goat_memeq(em + pos + sizeof(digestinfo_sha256), digest, 32) ? 0 : -1;
}
