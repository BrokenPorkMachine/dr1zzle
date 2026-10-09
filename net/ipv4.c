#include "internal.h"
#include <string.h>

/* IPv4 (RFC 791) with the ICMPv4 subset the stack actually uses. There is no
 * fragmentation and no reassembly: a datagram that does not fit is reported as
 * unreachable rather than split. */

#define DR1ZZLE_IPV4_FLAG_DF 0x4000u /* don't fragment, in network order */
#define DR1ZZLE_IPV4_FLAG_MF 0x2000u

#define DR1ZZLE_ICMP_HEADER 8u

static int address_is_any_v4(const uint8_t *address) {
    size_t index;
    for (index = 0u; index < 4u; index++) {
        if (address[index] != 0u) return 0;
    }
    return 1;
}

static int address_is_broadcast_v4(const uint8_t *address) {
    size_t index;
    for (index = 0u; index < 4u; index++) {
        if (address[index] != 0xffu) return 0;
    }
    return 1;
}

/* Echo reply. Answers the request as it arrived, preserving identifier and
 * payload so the originator can match it. */
void net_ipv4_reply_echo(const uint8_t *source, const uint8_t *destination,
                         const uint8_t *payload, size_t length) {
    uint8_t reply[DR1ZZLE_ETH_MTU];
    drizzle_endpoint_t endpoint;

    if (length > sizeof reply) return;
    memcpy(reply, payload, length);
    reply[0] = (uint8_t)DR1ZZLE_ICMP_ECHO_REPLY;
    net_write16(reply + 2, 0u);
    net_write16(reply + 2, net_checksum(reply, length));

    (void)destination;
    endpoint.family = DR1ZZLE_AF_INET;
    memcpy(endpoint.address, source, 4u);
    endpoint.port = 0u;
    net_ip_send(DR1ZZLE_AF_INET, &endpoint, (uint8_t)DR1ZZLE_IPPROTO_ICMP, reply, length,
                64u);
}

void net_ipv4_unreachable(drizzle_family_t family, const uint8_t *source, uint8_t protocol,
                          const uint8_t *payload, size_t length) {
    uint8_t message[DR1ZZLE_ICMP_HEADER + DR1ZZLE_IPV4_HEADER + 8u];
    size_t quoted = length;
    size_t total;
    drizzle_endpoint_t endpoint;

    (void)family;
    (void)protocol;
    if (quoted > DR1ZZLE_IPV4_HEADER + 8u) quoted = DR1ZZLE_IPV4_HEADER + 8u;
    total = DR1ZZLE_ICMP_HEADER + quoted;

    memset(message, 0, DR1ZZLE_ICMP_HEADER);
    message[0] = (uint8_t)DR1ZZLE_ICMP_DEST_UNREACHABLE;
    message[1] = 3u; /* port unreachable */
    memcpy(message + DR1ZZLE_ICMP_HEADER, payload, quoted);
    net_write16(message + 2, net_checksum(message, total));

    endpoint.family = DR1ZZLE_AF_INET;
    memcpy(endpoint.address, source, 4u);
    endpoint.port = 0u;
    net_ip_send(DR1ZZLE_AF_INET, &endpoint, (uint8_t)DR1ZZLE_IPPROTO_ICMP, message, total,
                64u);
}

static void handle_icmp(const uint8_t *source, const uint8_t *payload, size_t length) {
    if (length < DR1ZZLE_ICMP_HEADER) {
        drizzle_net_count_drop();
        return;
    }
    /* Verify only when the sender supplied a checksum; zero means "absent". */
    if (net_read16(payload + 2) != 0u && net_checksum(payload, length) != 0u) {
        drizzle_net_count_drop();
        return;
    }
    if (payload[0] == (uint8_t)DR1ZZLE_ICMP_ECHO_REQUEST) {
        net_ipv4_reply_echo(source, source, payload, length);
    }
    /* Destination-unreachable is not fed back into the transports here; they
     * learn about a dead peer from their own retransmission budget. */
}

void net_ipv4_input(const uint8_t *source, const uint8_t *payload, size_t length) {
    size_t header_length;
    size_t total_length;
    uint16_t fragment;
    uint8_t protocol;
    drizzle_endpoint_t from;
    drizzle_endpoint_t to;
    const uint8_t *body;
    size_t body_length;

    if (length < DR1ZZLE_IPV4_HEADER) {
        drizzle_net_count_drop();
        return;
    }
    if ((payload[0] >> 4) != 4u) {
        drizzle_net_count_drop();
        return;
    }
    header_length = (size_t)(payload[0] & 0x0fu) * 4u;
    if (header_length < DR1ZZLE_IPV4_HEADER || header_length > length) {
        drizzle_net_count_drop();
        return;
    }
    total_length = net_read16(payload + 2);
    if (total_length < header_length || total_length > length) {
        /* Never guess at a length we cannot verify. */
        drizzle_net_count_drop();
        return;
    }
    if (net_checksum(payload, header_length) != 0u) {
        drizzle_net_count_drop();
        return;
    }

    fragment = net_read16(payload + 6);
    if ((fragment & 0x1fffu) != 0u || (fragment & DR1ZZLE_IPV4_FLAG_MF) != 0u) {
        /* Reassembly is deliberately absent. */
        net_ipv4_unreachable(DR1ZZLE_AF_INET, source, payload[9], payload, total_length);
        return;
    }
    if (payload[8] == 0u) {
        net_ipv4_unreachable(DR1ZZLE_AF_INET, source, payload[9], payload, total_length);
        return;
    }

    protocol = payload[9];
    body = payload + header_length;
    body_length = total_length - header_length;

    from.family = DR1ZZLE_AF_INET;
    from.port = 0u;
    memcpy(from.address, payload + 12, 4u);
    to.family = DR1ZZLE_AF_INET;
    to.port = 0u;
    memcpy(to.address, payload + 16, 4u);

    (void)source;

    if (!drizzle_net_has_v4()) return;
    if (!drizzle_endpoint_is_loopback(&to) && !address_is_broadcast_v4(to.address) &&
        !address_is_any_v4(to.address) && memcmp(to.address, drizzle_net_v4(), 4u) != 0) {
        return; /* not for us */
    }

    switch (protocol) {
        case DR1ZZLE_IPPROTO_ICMP:
            handle_icmp(from.address, body, body_length);
            break;
        case DR1ZZLE_IPPROTO_UDP: {
            uint8_t *segment = (uint8_t *)body;
            size_t segment_length = body_length;
            if (body_length < DR1ZZLE_UDP_HEADER) break;
            /* NAT restores the original destination port before demux, so the
             * transport layer only ever sees local ports. */
            net_nat_input(DR1ZZLE_AF_INET, &from, &to, protocol, &segment,
                          &segment_length);
            drizzle_udp_input(&from, &to, segment, segment_length);
            break;
        }
        case DR1ZZLE_IPPROTO_TCP: {
            uint8_t *segment = (uint8_t *)body;
            size_t segment_length = body_length;
            net_nat_input(DR1ZZLE_AF_INET, &from, &to, protocol, &segment,
                          &segment_length);
            drizzle_tcp_input(&from, &to, segment, segment_length);
            break;
        }
        default:
            break;
    }
}

int net_ipv4_send(const drizzle_endpoint_t *destination, const uint8_t *payload,
                  size_t length, uint8_t protocol, unsigned ttl) {
    uint8_t frame[DR1ZZLE_ETH_MTU];
    uint8_t *body = frame + DR1ZZLE_IPV4_HEADER;
    uint8_t hardware[DR1ZZLE_MAC_LEN];
    drizzle_endpoint_t source;
    size_t body_length = length;
    unsigned hop_limit = ttl;

    if (length + DR1ZZLE_IPV4_HEADER > sizeof frame) {
        drizzle_net_count_drop();
        return -1;
    }
    if (!drizzle_net_has_v4()) return -1;

    memcpy(body, payload, length);

    source.family = DR1ZZLE_AF_INET;
    source.port = destination->port;
    memcpy(source.address, drizzle_net_v4(), 4u);

    /* NAT rewrites the source address and port, and may replace the payload
     * with a translated copy. */
    net_nat_output(DR1ZZLE_AF_INET, &source, destination, protocol, &body, &body_length,
                   &hop_limit);
    if (body != (uint8_t *)payload && body != (frame + DR1ZZLE_IPV4_HEADER)) {
        memmove(frame + DR1ZZLE_IPV4_HEADER, body, body_length);
    }

    if (!net_next_hop(DR1ZZLE_AF_INET, destination->address, hardware)) {
        drizzle_net_count_drop();
        return -1;
    }

    memset(frame, 0, DR1ZZLE_IPV4_HEADER);
    frame[0] = 0x45u; /* version 4, five 32-bit words of header */
    net_write16(frame + 2, (uint16_t)(DR1ZZLE_IPV4_HEADER + body_length));
    net_write16(frame + 4, 0u); /* identification */
    net_write16(frame + 6, (uint16_t)DR1ZZLE_IPV4_FLAG_DF);
    frame[8] = (uint8_t)hop_limit;
    frame[9] = protocol;
    net_write16(frame + 10, 0u);
    memcpy(frame + 12, source.address, 4u);
    memcpy(frame + 16, destination->address, 4u);
    net_write16(frame + 10, net_checksum(frame, DR1ZZLE_IPV4_HEADER));

    net_link_send(hardware, drizzle_net_mac(), (uint16_t)DR1ZZLE_ETHERTYPE_IPV4, frame,
                  DR1ZZLE_IPV4_HEADER + body_length);
    return 0;
}