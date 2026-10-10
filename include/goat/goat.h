#ifndef GOAT_H
#define GOAT_H

#include <stdint.h>

/* GOAT container: the signed, encrypted packaging the loader consumes.
 *
 * ---------------------------------------------------------------------------
 * Container layout (DER)
 * ---------------------------------------------------------------------------
 *
 *   Container ::= SEQUENCE {
 *       magic     OCTET STRING,        -- "GOAT\1"
 *       version   INTEGER,             -- 1
 *       body      SEQUENCE {           -- everything the signature covers
 *           payload    SEQUENCE {
 *               sha256   OCTET STRING, -- 32-byte digest of the plaintext
 *               length   INTEGER,     -- plaintext length in bytes
 *               loadBase INTEGER,     -- where the plaintext is decrypted to
 *               entryOff INTEGER      -- entry offset from loadBase
 *           }
 *           encryption SEQUENCE {
 *               iv       OCTET STRING, -- 16-byte CBC IV
 *               cipher   OCTET STRING, -- AES-256-CBC ciphertext
 *               keyWrap  SEQUENCE {    -- OPTIONAL
 *                   algo INTEGER,      -- 1 = RSA-PKCS#1 v1.5 wrapped key
 *                   blob OCTET STRING
 *               }
 *           }
 *           certificate SEQUENCE {
 *               serial    INTEGER,
 *               issuer    UTF8String,
 *               subject   UTF8String,
 *               notBefore INTEGER,
 *               notAfter  INTEGER,
 *               pub       SEQUENCE {
 *                   n OCTET STRING,    -- modulus, big-endian
 *                   e OCTET STRING     -- exponent, big-endian
 *               }
 *               selfSig  OCTET STRING   -- over DER(serial..pub)
 *           }
 *       }
 *       signature OCTET STRING         -- RSA-PKCS#1 v1.5 over DER(body)
 *   }
 *
 * Why this shape: it mirrors the useful half of IMG4 without its baggage --
 * the payload is accounted for twice (digest inside the container, signature
 * over the whole body), it is encrypted so the image at rest is inert, and the
 * verifying key travels inside the container so the device never needs the
 * sealer's private key.
 *
 * The AES key is NOT in the container. The user supplies it: it is either
 * handed over directly (`goat key`) or wrapped to the certificate's public key
 * for the user to unwrap on the host.
 */

#define GOAT_MAGIC_SIZE 5
extern const uint8_t goat_magic[GOAT_MAGIC_SIZE];
#define GOAT_VERSION 1

/* Where a pushed container is staged before it is parsed, verified and
 * decrypted. The window is whatever SRAM is left after the payload image,
 * heap, stack and snapshot record: the linker reserves it (linker/a11.ld,
 * section .stage), so a payload that grows makes the window smaller instead
 * of overlapping it. The symbols are address-of, so the values are the
 * linker's, not a second copy of the layout. */
extern char __stage_base, __stage_limit;

#define GOAT_STAGE_BASE ((uint64_t)(uintptr_t)&__stage_base)
#define GOAT_STAGE_SIZE ((uint64_t)(uintptr_t)(&__stage_limit - &__stage_base))

/* x1 when a goat-launched payload is entered: 'goat' in big endian, so a
 * payload can tell it was started by this loader rather than by the boot
 * chain. x2 carries the container pointer. x0 keeps the boot device tree. */
#define GOAT_LAUNCH_TAG 0x676F6174ULL

/* Signed-but-not-yet-run state of a parsed container. */
typedef struct {
    const uint8_t *payload_sha;   uint32_t payload_sha_len;
    uint64_t       payload_len;
    uint64_t       load_base;
    uint64_t       entry_off;

    const uint8_t *iv;    uint32_t iv_len;
    const uint8_t *cipher; uint32_t cipher_len;

    int            has_keywrap;
    uint64_t       keywrap_algo;
    const uint8_t *keywrap_blob; uint32_t keywrap_blob_len;

    uint64_t       cert_serial;
    const uint8_t *issuer; uint32_t issuer_len;
    const uint8_t *subject; uint32_t subject_len;
    uint64_t       not_before;
    uint64_t       not_after;
    const uint8_t *modulus;  uint32_t modulus_len;
    const uint8_t *exponent; uint32_t exponent_len;
    const uint8_t *cert_selfsig; uint32_t cert_selfsig_len;

    /* The DER bytes of `body`, which is what the container signature is over. */
    const uint8_t *signed_region;
    uint32_t       signed_region_len;

    /* The certificate's own signed region: DER bytes from `serial` to the end
     * of `pub`. Also what the cert self-signature covers. */
    const uint8_t *cert_tbs;
    uint32_t       cert_tbs_len;

    const uint8_t *signature;
    uint32_t       signature_len;
} goat_container_t;

/* Parse the TLV tree at `der`. Pointers in `out` alias `der`; they stay valid
 * as long as the container buffer does. Returns 0 on success. */
int goat_parse(const uint8_t *der, uint32_t len, goat_container_t *out);

/* Certificate self-signature check (the cert vouches for its own key). */
int goat_cert_ok(const goat_container_t *c);

/* Container signature check, using the public key embedded in the
 * certificate. Both this and goat_cert_ok must pass before the payload is
 * trusted enough to decrypt. */
int goat_verify(const goat_container_t *c);

/* Digest check against an already-decrypted plaintext buffer. */
int goat_digest_ok(const goat_container_t *c, const uint8_t *payload,
                   uint64_t len);

/* Decrypt the ciphertext to load_base with the 32-byte AES key. Returns 0 on
 * success and fills *_load_base / *_entry with the launch addresses. */
int goat_decrypt(const goat_container_t *c, const uint8_t key[32],
                 uint64_t *load_base_out, uint64_t *entry_out);

/* Enter the decrypted payload. Never returns. */
void goat_enter(uint64_t entry) __attribute__((noreturn));

/* Pointer to the container currently staged in SRAM. Published to a launched
 * payload in x2, and what `goat status` reports. Zero when nothing is
 * staged. */
extern const uint8_t *goat_staged_container;

/* Human-readable report, printed on the serial console. */
void goat_report(const goat_container_t *c);

#endif /* GOAT_H */
