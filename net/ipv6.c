#include "internal.h"
#include <string.h>

/* IPv6 (RFC 8200) with the ICMPv6 pieces a host needs: echo, error messages,
 * and neighbour discovery delegation to net_ndp_input.
 *
 * Extension headers are skipped only when they are hop-by-hop or routing with a
 * recognized next header; anything else is dropped rather than misparsed.
 */

#define DR1ZZLE_IPPROTO_HOPOPTS 0u
#define DR1ZZLE_IPPROTO_ROUTING 43u

static int address_is_unspecified_v6(const uint8_t *address) {
    size_t index;
    for (index = 0u; index < 16u; index++) {
        if (address[index] != 0u) return 0;
    }
    return 1;
}

static int address_is_multicast_v6(const uint8_t *address) {
    return address[0] == 0xffu;
}

static int address_is_loopback_v6(const uint8_t *address) {
    static const uint8_t loopback[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    return memcmp(address, loopback, 16u) == 0;
}

void net_ipv6_reply_echo(const uint8_t *source, const uint8_t *destination,
                         const uint8_t *payload, size_t length) {
    uint8_t reply[DR1ZZLE_ETH_MTU];
    drizzle_endpoint_t endpoint;

    if (length > sizeof reply) return;
    memcpy(reply, payload, length);
    reply[0] = (uint8_t)DR1ZZLE_ICMP6_ECHO_REPLY;
    reply[1] = 0u;
    net_write16(reply + 2, 0u);
    net_write16(reply + 2, net_transport_checksum(DR1ZZLE_AF_INET6, source, destination,
                                                  (uint8_t)DR1ZZLE_IPPROTO_ICMP6, reply,
                                                  length));
    (void)destination;
    endpoint.family = DR1ZZLE_AF_INET6;
    memcpy(endpoint.address, source, 16u);
    endpoint.port = 0u;
    net_ip_send(DR1ZZLE_AF_INET6, &endpoint, (uint8_t)DR1ZZLE_IPPROTO_ICMP6, reply, length,
                64u);
}

void net_ipv6_unreachable(const uint8_t *source, const uint8_t *destination, uint8_t code,
                          const uint8_t *offending, size_t length) {
    uint8_t message[8u + DR1ZZLE_IPV4_HEADER + 8u];
    size_t quoted = length;
    size_t total;
    drizzle_endpoint_t endpoint;

    if (quoted > DR1ZZLE_IPV4_HEADER + 8u) quoted = DR1ZZLE_IPV4_HEADER + 8u;
    total = 8u + quoted;

    memset(message, 0, 8u);
    message[0] = (uint8_t)DR1ZZLE_ICMP6_DEST_UNREACHABLE;
    message[1] = code;
    memcpy(message + 8, offending, quoted);
    net_write16(message + 2, net_transport_checksum(DR1ZZLE_AF_INET6, source, destination,
                                                  (uint8_t)DR1ZZLE_IPPROTO_ICMP6, message,
                                                  total));
    (void)destination;
    endpoint.family = DR1ZZLE_AF_INET6;
    memcpy(endpoint.address, source, 16u);
    endpoint.port = 0u;
    net_ip_send(DR1ZZLE_AF_INET6, &endpoint, (uint8_t)DR1ZZLE_IPPROTO_ICMP6, message, total,
                64u);
}

/* Walks hop-by-hop / destination-opts / routing headers. Returns the offset of
 * the upper-layer header, or 0 when the chain is not something we will parse. */
static size_t skip_extension_headers(const uint8_t *payload, size_t length, uint8_t *protocol) {
    size_t offset = 40u;
    uint8_t next = payload[6];

    while (next == DR1ZZLE_IPPROTO_HOPOPTS || next == DR1ZZLE_IPPROTO_ROUTING ||
           next == 60u /* destination options */) {
        size_t header_length;
        if (offset + 8u > length) return 0u;
        next = payload[offset];
        header_length = ((size_t)payload[offset + 1] + 1u) * 8u;
        if (header_length < 8u || offset + header_length > length) return 0u;
        offset += header_length;
    }
    *protocol = next;
    return offset;
}

void net_ipv6_input(const uint8_t *source, const uint8_t *payload, size_t length) {
    size_t header_length;
    size_t payload_length;
    uint8_t protocol;
    drizzle_endpoint_t from;
    drizzle_endpoint_t to;
    const uint8_t *body;
    size_t body_length;

    if (length < 40u) {
        drizzle_net_count_drop();
        return;
    }
    if ((payload[0] >> 4) != 6u) {
        drizzle_net_count_drop();
        return;
    }
    payload_length = net_read16(payload + 4);
    if (40u + payload_length > length) {
        drizzle_net_count_drop();
        return;
    }
    if (payload[7] == 0u) { /* hop limit exhausted */
        net_ipv6_unreachable(source, source, (uint8_t)DR1ZZLE_ICMP6_TIME_EXCEEDED, payload,
                             payload_length);
        return;
    }

    header_length = skip_extension_headers(payload, 40u + payload_length, &protocol);
    if (header_length == 0u) {
        drizzle_net_count_drop();
        return;
    }

    body = payload + header_length;
    body_length = payload_length - (header_length - 40u);

    from.family = DR1ZZLE_AF_INET6;
    from.port = 0u;
    memcpy(from.address, payload + 8, 16u);
    to.family = DR1ZZLE_AF_INET6;
    to.port = 0u;
    memcpy(to.address, payload + 24, 16u);

    (void)source;

    if (!drizzle_net_has_v6()) return;
    if (!address_is_loopback_v6(to.address) && !address_is_multicast_v6(to.address) &&
        !address_is_unspecified_v6(to.address) &&
        memcmp(to.address, drizzle_net_v6(), 16u) != 0) {
        return; /* not addressed to us */
    }

    switch (protocol) {
        case DR1ZZLE_IPPROTO_ICMP6:
            /* Echo is the only message handled here; neighbour discovery is
             * routed by type inside the dispatcher. */
            if (body_length >= 4u &&
                (body[0] == (uint8_t)DR1ZZLE_ICMP6_ECHO_REQUEST ||
                 body[0] == (uint8_t)DR1ZZLE_ICMP6_NEIGHBOR_SOLICIT ||
                 body[0] == (uint8_t)DR1ZZLE_ICMP6_NEIGHBOR_ADVERT)) {
                uint16_t received = net_read16(body + 2);
                if (received == 0u ||
                    net_transport_checksum(DR1ZZLE_AF_INET6, from.address, to.address,
                                           (uint8_t)DR1ZZLE_IPPROTO_ICMP6, body,
                                           body_length) == 0u) {
                    if (body[0] == (uint8_t)DR1ZZLE_ICMP6_ECHO_REQUEST) {
                        net_ipv6_reply_echo(from.address, to.address, body, body_length);
                    } else {
                        net_ndp_input(from.address, body, body_length);
                    }
                } else {
                    drizzle_net_count_drop();
                }
            }
            break;
        case DR1ZZLE_IPPROTO_UDP: {
            uint8_t *segment = (uint8_t *)body;
            size_t segment_length = body_length;
            if (body_length < DR1ZZLE_UDP_HEADER) break;
            net_nat_input(DR1ZZLE_AF_INET6, &from, &to, protocol, &segment,
                          &segment_length);
            drizzle_udp_input(&from, &to, segment, segment_length);
            break;
        }
        case DR1ZZLE_IPPROTO_TCP: {
            uint8_t *segment = (uint8_t *)body;
            size_t segment_length = body_length;
            net_nat_input(DR1ZZLE_AF_INET6, &from, &to, protocol, &segment,
                          &segment_length);
            drizzle_tcp_input(&from, &to, segment, segment_length);
            break;
        }
        default:
            break;
    }
}

int net_ipv6_send(const drizzle_endpoint_t *destination, const uint8_t *payload,
                  size_t length, uint8_t protocol, unsigned ttl) {
    uint8_t frame[DR1ZZLE_ETH_MTU];
    uint8_t *body = frame + 40u;
    uint8_t hardware[DR1ZZLE_MAC_LEN];
    drizzle_endpoint_t source;
    size_t body_length = length;
    unsigned hop_limit = ttl;

    if (length + 40u > sizeof frame) {
        drizzle_net_count_drop();
        return -1;
    }
    if (!drizzle_net_has_v6()) return -1;

    memcpy(body, payload, length);

    source.family = DR1ZZLE_AF_INET6;
    source.port = destination->port;
    memcpy(source.address, drizzle_net_v6(), 16u);

    net_nat_output(DR1ZZLE_AF_INET6, &source, destination, protocol, &body, &body_length,
                   &hop_limit);
    if (body != (uint8_t *)payload && body != (frame + 40u)) {
        memmove(frame + 40u, body, body_length);
    }

    if (!net_next_hop(DR1ZZLE_AF_INET6, destination->address, hardware)) {
        drizzle_net_count_drop();
        return -1;
    }

    memset(frame, 0, 40u);
    frame[0] = 0x60u; /* version 6, no traffic class or flow label */
    net_write16(frame + 4, (uint16_t)body_length);
    frame[6] = protocol;
    frame[7] = (uint8_t)hop_limit;
    memcpy(frame + 8, source.address, 16u);
    memcpy(frame + 24, destination->address, 16u);

    net_link_send(hardware, drizzle_net_mac(), (uint16_t)DR1ZZLE_ETHERTYPE_IPV6, frame,
                  40u + body_length);
    return 0;
}