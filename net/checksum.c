#include "internal.h"

/* RFC 1071 one's complement sum. Every layer of the stack shares these three
 * helpers so there is exactly one implementation of the arithmetic. */

uint32_t net_checksum_add(uint32_t sum, const uint8_t *data, size_t length) {
    while (length > 1u) {
        sum += net_read16(data);
        data += 2;
        length -= 2u;
    }
    if (length) sum += (uint32_t)data[0] << 8;
    return sum;
}

uint16_t net_checksum_finish(uint32_t sum) {
    while (sum >> 16) sum = (sum & 0xffffu) + (sum >> 16);
    return (uint16_t)~sum;
}

uint16_t net_checksum(const uint8_t *data, size_t length) {
    return net_checksum_finish(net_checksum_add(0u, data, length));
}

uint16_t net_transport_checksum(drizzle_family_t family, const uint8_t *source,
                                const uint8_t *destination, uint8_t protocol,
                                const uint8_t *segment, size_t length) {
    size_t address_length = (family == DR1ZZLE_AF_INET6) ? 16u : 4u;
    uint8_t trailer[4];
    uint32_t sum = 0u;

    /* The pseudo header length field is 16 bits, so anything larger could not
     * be represented on the wire anyway. Callers fragment-free at 1500 bytes. */
    if (length > 0xffffu) return 0u;

    sum = net_checksum_add(sum, source, address_length);
    sum = net_checksum_add(sum, destination, address_length);

    net_write16(trailer, (uint16_t)protocol);
    net_write16(trailer + 2, (uint16_t)length);
    sum = net_checksum_add(sum, trailer, sizeof trailer);

    return net_checksum_finish(net_checksum_add(sum, segment, length));
}