/* DER reader (X.690 subset).
 *
 * Deliberately small: it parses exactly one container layout and rejects
 * anything it does not recognise rather than trying to be a general ASN.1
 * stack. Every length is validated before the corresponding pointer is handed
 * out, so a caller can never be handed a pointer past the end of the buffer.
 */

#include "goat/asn1.h"

int der_tlv(const uint8_t *buf, uint32_t len, der_tlv_t *out) {
    if (len < 2) return -1;

    uint32_t idx = 1;
    out->start = buf;
    out->tag = buf[0];
    out->constructed = (buf[0] & 0x20) != 0;

    /* Low tag numbers only (0..30). High-tag-number form would move the tag
     * out of the first octet and is not used by this container. */
    if ((buf[0] & 0x1F) == 0x1F) return -1;

    uint8_t l0 = buf[1];
    uint32_t content_len;

    if (l0 < 0x80) {
        content_len = l0;
        idx = 2;
    } else if (l0 == 0x80) {
        /* Indefinite length: BER only, not DER. */
        return -1;
    } else {
        unsigned octets = l0 & 0x7F;
        if (octets > 4) return -1;          /* >4 GiB, absurd for our use */
        if (len < 2u + octets) return -1;

        content_len = 0;
        for (unsigned i = 0; i < octets; i++) {
            content_len = (content_len << 8) | buf[2 + i];
        }
        idx = 2 + octets;

        /* Leading length octets must not be zero: that is the BER
         * non-minimal encoding DER forbids. */
        if (octets > 1 && buf[2] == 0) return -1;
    }

    if (content_len > len - idx) return -1;

    out->content = buf + idx;
    out->content_len = content_len;
    out->total_len = idx + content_len;
    return 0;
}

void der_iter_init(der_iter_t *it, const der_tlv_t *tlv) {
    it->buf = tlv->content;
    it->len = tlv->content_len;
    it->off = 0;
}

int der_iter_next(der_iter_t *it, der_tlv_t *out) {
    if (it->off >= it->len) return -1;

    if (der_tlv(it->buf + it->off, it->len - it->off, out) != 0) return -1;

    it->off += out->total_len;
    return 0;
}

int der_expect(const der_tlv_t *tlv, uint8_t tag) {
    if (tlv->tag != tag) return -1;
    return 0;
}

int der_get_uint(const der_tlv_t *tlv, uint64_t *out) {
    if (tlv->tag != DER_TAG_INTEGER) return -1;
    if (tlv->content_len == 0) return -1;
    if (tlv->content[0] & 0x80) return -1;    /* negative */
    if (tlv->content_len > 9) return -1;
    if (tlv->content_len == 9 && tlv->content[0] != 0) return -1;

    uint64_t v = 0;
    for (uint32_t i = 0; i < tlv->content_len; i++) {
        v = (v << 8) | tlv->content[i];
    }
    *out = v;
    return 0;
}

int der_get_octets(const der_tlv_t *tlv, const uint8_t **data, uint32_t *len) {
    if (tlv->tag != DER_TAG_OCTET_STRING) return -1;
    /* Null out-parameters are allowed: parsing the tag is still a check. */
    if (data) *data = tlv->content;
    if (len) *len = tlv->content_len;
    return 0;
}
