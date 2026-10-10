#ifndef GOAT_ASN1_H
#define GOAT_ASN1_H

#include <stdint.h>

/* Minimal DER reader.
 *
 * Enough of X.690 to walk the container: tag, definite length (short and long
 * form), and iteration over the children of a SEQUENCE. Indefinite lengths are
 * rejected -- DER does not permit them, and accepting one would mean accepting
 * a BER stream, which changes what "verify" means.
 *
 * The reader never dereferences past the end of the buffer it is given. Every
 * length is checked against the enclosing TLV before use, because a truncated
 * container is exactly what a hostile upload looks like.
 */

#define DER_TAG_EOC           0x00
#define DER_TAG_BOOLEAN       0x01
#define DER_TAG_INTEGER       0x02
#define DER_TAG_BIT_STRING    0x03
#define DER_TAG_OCTET_STRING  0x04
#define DER_TAG_NULL          0x05
#define DER_TAG_UTF8_STRING   0x0C
#define DER_TAG_SEQUENCE      0x30   /* constructed bit | 0x10 */
#define DER_TAG_SET           0x31

typedef struct {
    const uint8_t *start;    /* the tag octet, inside the caller's buffer */
    uint8_t        tag;
    int            constructed;
    const uint8_t *content;
    uint32_t       content_len;
    uint32_t       total_len;   /* tag + length octets + content */
} der_tlv_t;

/* Parse one TLV from buf[0..len). Returns 0 on success. */
int der_tlv(const uint8_t *buf, uint32_t len, der_tlv_t *out);

typedef struct {
    const uint8_t *buf;
    uint32_t       len;
    uint32_t       off;
} der_iter_t;

void der_iter_init(der_iter_t *it, const der_tlv_t *constructed);
/* Returns 0 with `out` filled for the next child, -1 at the end or on error. */
int der_iter_next(der_iter_t *it, der_tlv_t *out);

int  der_expect(const der_tlv_t *tlv, uint8_t tag);

/* Read a non-negative INTEGER that fits in 64 bits. Returns -1 if the value
 * is larger, or negative. */
int  der_get_uint(const der_tlv_t *tlv, uint64_t *out);

/* Fetch an OCTET STRING's content pointer and length. */
int  der_get_octets(const der_tlv_t *tlv, const uint8_t **data, uint32_t *len);

#endif /* GOAT_ASN1_H */
