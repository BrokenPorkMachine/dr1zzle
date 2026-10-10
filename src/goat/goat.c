/* Container parse, verify, decrypt, enter.
 *
 * ---------------------------------------------------------------------------
 * Order of operations matters
 * ---------------------------------------------------------------------------
 *
 * goat_parse() only walks TLVs: no memory is trusted from it, and nothing is
 * executed. Verification comes next, and it is the only place the AES key is
 * accepted -- a container whose signature does not check out never gets
 * decrypted, so a bad image cannot waste the key holder's time or wedge the
 * boot with a half-decrypted payload in SRAM.
 *
 * Digestion is checked after decryption, against the plaintext that actually
 * landed at load_base, so the check is over real bytes rather than over what
 * the container claims it sealed.
 */

#include "goat/goat.h"
#include "goat/asn1.h"
#include "goat/aes.h"
#include "goat/rsa.h"
#include "goat/sha256.h"
#include "goat/util.h"
#include "memory_map.h"
#include "string.h"
#include "uart.h"
#include "util.h"

const uint8_t goat_magic[GOAT_MAGIC_SIZE] = { 'G', 'O', 'A', 'T', 0x01 };

/* Staged container pointer; see goat.h. Set by the `goat load` command. */
const uint8_t *goat_staged_container;

/* --- parse --------------------------------------------------------------- */

static int parse_payload(der_tlv_t *seq, goat_container_t *c) {
    der_tlv_t t[4];
    int n = 0;
    der_iter_t it;
    der_iter_init(&it, seq);
    while (n < 4 && der_iter_next(&it, &t[n]) == 0) n++;
    if (n != 4) return -1;

    if (der_get_octets(&t[0], &c->payload_sha, &c->payload_sha_len) != 0) return -1;
    if (c->payload_sha_len != GOAT_SHA256_DIGEST_SIZE) return -1;
    if (der_get_uint(&t[1], &c->payload_len) != 0) return -1;
    if (der_get_uint(&t[2], &c->load_base) != 0) return -1;
    if (der_get_uint(&t[3], &c->entry_off) != 0) return -1;
    if (c->payload_len == 0 || c->payload_len > 0x8000000u) return -1;
    if (c->entry_off > c->payload_len) return -1;
    return 0;
}

static int parse_encryption(der_tlv_t *seq, goat_container_t *c) {
    der_tlv_t t[3];
    int n = 0;
    der_iter_t it;
    der_iter_init(&it, seq);
    while (n < 3 && der_iter_next(&it, &t[n]) == 0) n++;
    if (n < 2) return -1;

    if (der_get_octets(&t[0], &c->iv, &c->iv_len) != 0) return -1;
    if (c->iv_len != GOAT_AES_IV_SIZE) return -1;

    if (der_get_octets(&t[1], &c->cipher, &c->cipher_len) != 0) return -1;
    if (c->cipher_len == 0 || (c->cipher_len % GOAT_AES_BLOCK_SIZE) != 0) return -1;
    if (c->payload_len > c->cipher_len) return -1;

    /* keyWrap is optional. Anything after it is a parse failure rather than
     * something to skip: the container layout is fixed by this version. */
    c->has_keywrap = 0;
    if (n == 3) {
        der_tlv_t w[2];
        int wn = 0;
        der_iter_t wit;
        der_iter_init(&wit, &t[2]);
        while (wn < 2 && der_iter_next(&wit, &w[wn]) == 0) wn++;
        if (wn != 2) return -1;
        if (der_get_uint(&w[0], &c->keywrap_algo) != 0) return -1;
        if (der_get_octets(&w[1], &c->keywrap_blob, &c->keywrap_blob_len) != 0) return -1;
        c->has_keywrap = 1;
    }
    return 0;
}

static int parse_certificate(der_tlv_t *seq, goat_container_t *c) {
    der_tlv_t t[7];
    int n = 0;
    der_iter_t it;
    der_iter_init(&it, seq);
    while (n < 7 && der_iter_next(&it, &t[n]) == 0) n++;
    if (n != 7) return -1;

    /* Signed region runs from the first child to the end of the public key. */
    c->cert_tbs = t[0].start;
    c->cert_tbs_len = (uint32_t)((t[5].start - t[0].start) + t[5].total_len);

    if (der_get_uint(&t[0], &c->cert_serial) != 0) return -1;
    if (der_expect(&t[1], DER_TAG_UTF8_STRING) != 0) return -1;
    if (der_expect(&t[2], DER_TAG_UTF8_STRING) != 0) return -1;
    c->issuer = t[1].content;  c->issuer_len = t[1].content_len;
    c->subject = t[2].content; c->subject_len = t[2].content_len;
    if (der_get_uint(&t[3], &c->not_before) != 0) return -1;
    if (der_get_uint(&t[4], &c->not_after) != 0) return -1;

    if (!der_expect(&t[5], DER_TAG_SEQUENCE)) return -1;
    der_tlv_t k[2];
    int kn = 0;
    der_iter_t kit;
    der_iter_init(&kit, &t[5]);
    while (kn < 2 && der_iter_next(&kit, &k[kn]) == 0) kn++;
    if (kn != 2) return -1;
    if (der_get_octets(&k[0], &c->modulus, &c->modulus_len) != 0) return -1;
    if (der_get_octets(&k[1], &c->exponent, &c->exponent_len) != 0) return -1;

    if (der_get_octets(&t[6], &c->cert_selfsig, &c->cert_selfsig_len) != 0) return -1;
    if (c->modulus_len < 64 || c->modulus_len > 512) return -1;
    return 0;
}

int goat_parse(const uint8_t *der, uint32_t len, goat_container_t *c) {
    for (uint32_t i = 0; i < sizeof(*c); i++) ((uint8_t *)c)[i] = 0;

    der_tlv_t top, magic, version, body, payload, encryption, cert, sig;
    if (der_tlv(der, len, &top) != 0) return -1;
    if (!der_expect(&top, DER_TAG_SEQUENCE)) return -1;

    der_iter_t it;
    der_iter_init(&it, &top);

    if (der_iter_next(&it, &magic) != 0) return -1;
    if (der_get_octets(&magic, 0, 0) != 0) return -1;
    if (magic.content_len != GOAT_MAGIC_SIZE) return -1;
    if (!goat_memeq(magic.content, goat_magic, GOAT_MAGIC_SIZE)) return -1;

    if (der_iter_next(&it, &version) != 0) return -1;
    uint64_t v;
    if (der_get_uint(&version, &v) != 0) return -1;
    if (v != GOAT_VERSION) return -1;

    if (der_iter_next(&it, &body) != 0) return -1;
    if (der_expect(&body, DER_TAG_SEQUENCE) != 0) return -1;
    c->signed_region = body.start;
    c->signed_region_len = body.total_len;

    der_iter_t bit;
    der_iter_init(&bit, &body);
    if (der_iter_next(&bit, &payload) != 0) return -1;
    if (parse_payload(&payload, c) != 0) return -1;
    if (der_iter_next(&bit, &encryption) != 0) return -1;
    if (parse_encryption(&encryption, c) != 0) return -1;
    if (der_iter_next(&bit, &cert) != 0) return -1;
    if (parse_certificate(&cert, c) != 0) return -1;
    if (der_iter_next(&bit, &payload) == 0) return -1;   /* no fourth member */

    if (der_iter_next(&it, &sig) != 0) return -1;
    if (der_get_octets(&sig, &c->signature, &c->signature_len) != 0) return -1;
    if (c->signature_len == 0) return -1;
    if (der_iter_next(&it, &payload) == 0) return -1;    /* no trailing member */

    return 0;
}

/* --- verify -------------------------------------------------------------- */

static int load_cert_key(const goat_container_t *c, goat_rsa_pub_t *pub) {
    return goat_rsa_pub_init(pub, c->modulus, c->modulus_len,
                             c->exponent, c->exponent_len);
}

int goat_cert_ok(const goat_container_t *c) {
    goat_rsa_pub_t pub;
    uint8_t digest[GOAT_SHA256_DIGEST_SIZE];

    if (load_cert_key(c, &pub) != 0) return -1;
    goat_sha256(c->cert_tbs, c->cert_tbs_len, digest);
    if (goat_rsa_verify_sha256(&pub, c->cert_selfsig, c->cert_selfsig_len,
                               digest) != 0) {
        return -1;
    }
    return 0;
}

int goat_verify(const goat_container_t *c) {
    goat_rsa_pub_t pub;
    uint8_t digest[GOAT_SHA256_DIGEST_SIZE];

    /* The container signature is checked with the key the certificate
     * vouches for, so a certificate that does not verify itself cannot be
     * used to bless a container. */
    if (goat_cert_ok(c) != 0) return -1;
    if (load_cert_key(c, &pub) != 0) return -1;

    goat_sha256(c->signed_region, c->signed_region_len, digest);
    return goat_rsa_verify_sha256(&pub, c->signature, c->signature_len, digest);
}

int goat_digest_ok(const goat_container_t *c, const uint8_t *payload,
                   uint64_t len) {
    uint8_t digest[GOAT_SHA256_DIGEST_SIZE];
    goat_sha256(payload, (size_t)len, digest);
    return goat_memeq(digest, c->payload_sha, GOAT_SHA256_DIGEST_SIZE) ? 0 : -1;
}

/* --- decrypt and enter --------------------------------------------------- */

int goat_decrypt(const goat_container_t *c, const uint8_t key[32],
                 uint64_t *load_base_out, uint64_t *entry_out) {
    /* Refuse to decrypt across the container itself: the ciphertext aliases
     * the staged buffer, and an overlapping destination would corrupt the
     * plaintext mid-stream. */
    uint64_t cb = (uint64_t)(uintptr_t)c->cipher;
    uint64_t ce = cb + c->cipher_len;
    uint64_t lb = c->load_base;
    uint64_t le = lb + c->cipher_len;
    if (lb < ce && cb < le) return -1;
    if (le > SRAM_BASE + SRAM_SIZE) return -1;

    goat_aes_key_t ak;
    if (goat_aes_decrypt_init(&ak, key) != 0) return -1;

    uint8_t iv[GOAT_AES_IV_SIZE];
    for (int i = 0; i < GOAT_AES_IV_SIZE; i++) iv[i] = c->iv[i];

    uint8_t *dst = (uint8_t *)(uintptr_t)c->load_base;
    for (uint32_t i = 0; i < c->cipher_len; i++) dst[i] = c->cipher[i];

    goat_aes_cbc_decrypt(&ak, dst, c->cipher_len / GOAT_AES_BLOCK_SIZE, iv);

    uint64_t plain_len = goat_aes_unpad(dst, c->cipher_len);
    if (plain_len == (uint64_t)-1) return -1;
    if (plain_len != c->payload_len) return -1;
    if (goat_digest_ok(c, dst, plain_len) != 0) return -1;

    *load_base_out = c->load_base;
    *entry_out = c->load_base + c->entry_off;
    return 0;
}

void goat_enter(uint64_t entry) {
    /* Enter masked, with the MMU and caches still off, exactly as the entry
     * contract for a payload launched from pwndfu. The image was verified and
     * its digest checked before this point: everything up to here is
     * sandboxing, this is the jump. */
    __asm__ volatile("msr daifset, #0xf" ::: "memory");
    __asm__ volatile("dsb sy" ::: "memory");
    __asm__ volatile("ic iallu" ::: "memory");
    __asm__ volatile("dsb sy; isb" ::: "memory");

    /* __asm__ rather than asm: the payload is built with -std=c11, where
     * asm is not a keyword and the register-asm extension is only spelled
     * the double-underscore way. This keeps the launch arguments pinned to
     * the registers the payload reads them from. */
    register uint64_t x0 __asm__("x0") = g_boot_dtb;
    register uint64_t x1 __asm__("x1") = GOAT_LAUNCH_TAG;
    register uint64_t x2 __asm__("x2") = (uint64_t)(uintptr_t)goat_staged_container;

    __asm__ volatile("br %0" :: "r"(entry), "r"(x0), "r"(x1), "r"(x2)
                     : "memory");
    __builtin_unreachable();
}

/* --- report -------------------------------------------------------------- */

void goat_report(const goat_container_t *c) {
    char hex[128];

    uart_puts("goat: magic=");
    for (int i = 0; i < GOAT_MAGIC_SIZE; i++) {
        uart_putc(goat_magic[i] >= 32 && goat_magic[i] < 127 ? (char)goat_magic[i] : '?');
    }
    uart_puts(" version=");
    uart_puts(utoa_hex(GOAT_VERSION));
    uart_puts("\n");

    uart_puts("  payload sha256=");
    goat_hex(c->payload_sha, c->payload_sha_len, 0, hex, sizeof(hex));
    uart_puts(hex);
    uart_puts("\n");

    uart_puts("  length=0x");
    uart_puts(utoa_hex(c->payload_len));
    uart_puts(" loadBase=0x");
    uart_puts(utoa_hex(c->load_base));
    uart_puts(" entryOff=0x");
    uart_puts(utoa_hex(c->entry_off));
    uart_puts("\n");

    uart_puts("  cipher=0x");
    uart_puts(utoa_hex(c->cipher_len));
    uart_puts(" bytes at 0x");
    uart_puts(utoa_hex((uint64_t)(uintptr_t)c->cipher));
    uart_puts(", iv=");
    goat_hex(c->iv, c->iv_len, 0, hex, sizeof(hex));
    uart_puts(hex);
    uart_puts("\n");

    uart_puts("  cert serial=0x");
    uart_puts(utoa_hex(c->cert_serial));
    uart_puts(" subject=");
    char name[64];
    uint32_t n = c->subject_len < sizeof(name) - 1 ? c->subject_len
                                                   : (uint32_t)sizeof(name) - 1;
    for (uint32_t i = 0; i < n; i++) name[i] = (char)c->subject[i];
    name[n] = 0;
    uart_puts(name);
    uart_puts(" key=0x");
    uart_puts(utoa(c->modulus_len * 8));
    uart_puts(" bit\n");

    uart_puts("  keywrap=");
    uart_puts(c->has_keywrap ? "present" : "none");
    if (c->has_keywrap) {
        uart_puts(" (algo=");
        uart_puts(utoa_hex(c->keywrap_algo));
        uart_puts(")");
    }
    uart_puts("\n");

    uart_puts("  signature=0x");
    uart_puts(utoa_hex(c->signature_len));
    uart_puts(" bytes over ");
    uart_puts(utoa(c->signed_region_len));
    uart_puts(" body bytes\n");
}
