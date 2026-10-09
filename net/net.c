#include "internal.h"
#include <string.h>
#include "drizzle/udp.h"
#include "drizzle/tcp.h"
#include "drizzle/dns.h"

/* Stack glue: configuration, frame dispatch, the pending-resolution queue, and
 * the endpoint helpers shared by every layer. */

#define DR1ZZLE_PENDING_MAX 8u
#define DR1ZZLE_PENDING_PAYLOAD 600u

typedef struct {
    int in_use;
    drizzle_family_t family;
    drizzle_endpoint_t destination;
    uint8_t protocol;
    unsigned ttl;
    size_t length;
    uint8_t payload[DR1ZZLE_PENDING_PAYLOAD];
} pending_datagram_t;

static const drizzle_link_t *active_link;
static uint8_t local_mac[DR1ZZLE_MAC_LEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
static uint8_t v4_address[4];
static uint8_t v4_netmask[4];
static uint8_t v4_gateway[4];
static uint8_t v6_address[16];
static uint8_t v6_gateway[16];
static unsigned v6_prefix;
static int has_v4;
static int has_v6;
static drizzle_net_state_t net_state = DR1ZZLE_NET_DOWN;

static uint64_t frames_rx;
static uint64_t frames_tx;
static uint64_t bytes_rx;
static uint64_t bytes_tx;
static uint64_t drops;

static pending_datagram_t pending[DR1ZZLE_PENDING_MAX];

/* ---- configuration ---- */

void drizzle_net_set_link(const drizzle_link_t *link) {
    active_link = link;
}

const drizzle_link_t *drizzle_net_link(void) {
    return active_link;
}

int drizzle_net_link_up(void) {
    return active_link != NULL && active_link->transmit != NULL;
}

void drizzle_net_set_mac(const uint8_t hardware[DR1ZZLE_MAC_LEN]) {
    memcpy(local_mac, hardware, DR1ZZLE_MAC_LEN);
}

const uint8_t *drizzle_net_mac(void) {
    return local_mac;
}

drizzle_net_state_t drizzle_net_state(void) {
    return net_state;
}

void drizzle_net_configure_v4(const uint8_t address[4], const uint8_t netmask[4],
                              const uint8_t gateway[4]) {
    memcpy(v4_address, address, 4u);
    memcpy(v4_netmask, netmask, 4u);
    memcpy(v4_gateway, gateway, 4u);
    has_v4 = 1;
    net_state = DR1ZZLE_NET_UP;
}

void drizzle_net_configure_v6(const uint8_t address[16], unsigned prefix_length,
                              const uint8_t gateway[16]) {
    memcpy(v6_address, address, 16u);
    memcpy(v6_gateway, gateway, 16u);
    v6_prefix = prefix_length;
    has_v6 = 1;
    if (net_state != DR1ZZLE_NET_UP) net_state = DR1ZZLE_NET_UP;
}

int drizzle_net_has_v4(void) {
    return has_v4;
}

int drizzle_net_has_v6(void) {
    return has_v6;
}

const uint8_t *drizzle_net_v4(void) {
    return has_v4 ? v4_address : NULL;
}

const uint8_t *drizzle_net_v6(void) {
    return has_v6 ? v6_address : NULL;
}

const uint8_t *drizzle_net_v4_netmask(void) {
    return has_v4 ? v4_netmask : NULL;
}

const uint8_t *drizzle_net_v4_gateway(void) {
    return has_v4 ? v4_gateway : NULL;
}

const uint8_t *drizzle_net_v6_gateway(void) {
    return has_v6 ? v6_gateway : NULL;
}

unsigned drizzle_net_v6_prefix_length(void) {
    return v6_prefix;
}

void drizzle_net_count_rx(size_t length) {
    frames_rx++;
    bytes_rx += length;
}

void drizzle_net_count_tx(size_t length) {
    frames_tx++;
    bytes_tx += length;
}

void drizzle_net_count_drop(void) {
    drops++;
}

uint64_t drizzle_net_frames_rx(void) {
    return frames_rx;
}

uint64_t drizzle_net_frames_tx(void) {
    return frames_tx;
}

uint64_t drizzle_net_bytes_rx(void) {
    return bytes_rx;
}

uint64_t drizzle_net_bytes_tx(void) {
    return bytes_tx;
}

uint64_t drizzle_net_drops(void) {
    return drops;
}

/* ---- lifecycle ---- */

void drizzle_net_init(void) {
    size_t index;
    memset(pending, 0, sizeof pending);
    for (index = 0u; index < DR1ZZLE_PENDING_MAX; index++) {
        pending[index].in_use = 0;
    }
    has_v4 = 0;
    has_v6 = 0;
    net_state = DR1ZZLE_NET_DOWN;
}

void drizzle_net_poll(void) {
    const drizzle_link_t *link = drizzle_net_link();
    if (link && link->receive) link->receive();
    net_neighbor_tick();
    net_ip_send_flush();
    net_nat_tick();
    drizzle_tcp_poll();
    drizzle_dns_poll();
}

void drizzle_net_receive(const uint8_t *frame, size_t length) {
    uint16_t ethertype;

    drizzle_net_count_rx(length);
    if (length < DR1ZZLE_ETH_HEADER) {
        drizzle_net_count_drop();
        return;
    }

    ethertype = net_read16(frame + 12);
    if (ethertype == (uint16_t)DR1ZZLE_ETHERTYPE_VLAN) {
        /* Single-tagged VLAN: step over the tag. */
        if (length < DR1ZZLE_ETH_HEADER + 4u) {
            drizzle_net_count_drop();
            return;
        }
        ethertype = net_read16(frame + 16);
        net_arp_input(frame + 18, length - 18u);
        if (ethertype == (uint16_t)DR1ZZLE_ETHERTYPE_IPV4) {
            net_ipv4_input(frame + 18, length - 18u);
        } else if (ethertype == (uint16_t)DR1ZZLE_ETHERTYPE_IPV6) {
            net_ipv6_input(frame + 18, length - 18u);
        }
        return;
    }

    switch (ethertype) {
        case DR1ZZLE_ETHERTYPE_ARP:
            net_arp_input(frame + DR1ZZLE_ETH_HEADER, length - DR1ZZLE_ETH_HEADER);
            break;
        case DR1ZZLE_ETHERTYPE_IPV4:
            net_ipv4_input(frame + DR1ZZLE_ETH_HEADER, length - DR1ZZLE_ETH_HEADER);
            break;
        case DR1ZZLE_ETHERTYPE_IPV6:
            net_ipv6_input(frame + DR1ZZLE_ETH_HEADER, length - DR1ZZLE_ETH_HEADER);
            break;
        default:
            drizzle_net_count_drop();
            break;
    }
}

/* ---- transmit dispatch ---- */

int net_ip_send(drizzle_family_t family, const drizzle_endpoint_t *destination,
                uint8_t protocol, const uint8_t *payload, size_t length, unsigned ttl) {
    if (!drizzle_net_link_up()) return -1;
    if (family == DR1ZZLE_AF_INET6) {
        return net_ipv6_send(destination, payload, length, protocol, ttl);
    }
    return net_ipv4_send(destination, payload, length, protocol, ttl);
}

static void pending_flush_one(void) {
    size_t index;
    for (index = 0u; index < DR1ZZLE_PENDING_MAX; index++) {
        pending_datagram_t *slot = &pending[index];
        if (!slot->in_use) continue;
        /* Attempt in place. On success the entry is retired. */
        if (net_ip_send(slot->family, &slot->destination, slot->protocol, slot->payload,
                        slot->length, slot->ttl) == 0) {
            slot->in_use = 0;
        } else {
            /* Still blocked on resolution; retry the others so one stuck
             * neighbour cannot stall the queue. */
        }
    }
}

void net_ip_send_flush(void) {
    pending_flush_one();
}

void net_ip_send_queued(drizzle_family_t family, const drizzle_endpoint_t *destination,
                        uint8_t protocol, const uint8_t *payload, size_t length,
                        unsigned ttl) {
    size_t index;
    pending_datagram_t *slot = NULL;

    for (index = 0u; index < DR1ZZLE_PENDING_MAX; index++) {
        if (!pending[index].in_use) {
            slot = &pending[index];
            break;
        }
    }
    if (!slot) {
        /* Queue full: the newest datagram is the one worth keeping. */
        drizzle_net_count_drop();
        return;
    }
    if (length > sizeof slot->payload) {
        drizzle_net_count_drop();
        return;
    }
    slot->in_use = 1;
    slot->family = family;
    slot->destination = *destination;
    slot->protocol = protocol;
    slot->ttl = ttl;
    slot->length = length;
    memcpy(slot->payload, payload, length);
}

/* ---- endpoint helpers ---- */

void drizzle_endpoint_v4(drizzle_endpoint_t *endpoint, uint16_t port,
                         const uint8_t address[4]) {
    endpoint->family = DR1ZZLE_AF_INET;
    endpoint->port = port;
    memcpy(endpoint->address, address, 4u);
    memset(endpoint->address + 4, 0, DR1ZZLE_IP_MAX - 4u);
}

void drizzle_endpoint_v6(drizzle_endpoint_t *endpoint, uint16_t port,
                         const uint8_t address[16]) {
    endpoint->family = DR1ZZLE_AF_INET6;
    endpoint->port = port;
    memcpy(endpoint->address, address, 16u);
}

int drizzle_endpoint_equal(const drizzle_endpoint_t *left, const drizzle_endpoint_t *right) {
    size_t length;
    if (!left || !right) return 0;
    if (left->family != right->family || left->port != right->port) return 0;
    length = (left->family == DR1ZZLE_AF_INET6) ? 16u : 4u;
    return memcmp(left->address, right->address, length) == 0;
}

int drizzle_endpoint_is_unspecified(const drizzle_endpoint_t *endpoint) {
    size_t index;
    size_t length;
    if (!endpoint) return 1;
    length = (endpoint->family == DR1ZZLE_AF_INET6) ? 16u : 4u;
    for (index = 0u; index < length; index++) {
        if (endpoint->address[index] != 0u) return 0;
    }
    return 1;
}

int drizzle_endpoint_is_loopback(const drizzle_endpoint_t *endpoint) {
    static const uint8_t loopback6[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    size_t index;
    if (!endpoint) return 0;
    if (endpoint->family == DR1ZZLE_AF_INET6) {
        return memcmp(endpoint->address, loopback6, 16u) == 0;
    }
    for (index = 0u; index < 3u; index++) {
        if (endpoint->address[index] != 0u) return 0;
    }
    return endpoint->address[3] == 1u;
}

int drizzle_endpoint_is_multicast(const drizzle_endpoint_t *endpoint) {
    size_t index;
    if (!endpoint) return 0;
    if (endpoint->family == DR1ZZLE_AF_INET6) return endpoint->address[0] == 0xffu;
    for (index = 0u; index < 3u; index++) {
        if (endpoint->address[index] != 0u) return 0;
    }
    return endpoint->address[3] >= 224u && endpoint->address[3] <= 239u;
}

int drizzle_endpoint_is_link_local(const drizzle_endpoint_t *endpoint) {
    if (!endpoint || endpoint->family != DR1ZZLE_AF_INET6) return 0;
    if (endpoint->address[0] != 0xfeu) return 0;
    return (endpoint->address[1] & 0xc0u) == 0x80u;
}

static size_t append_text(char *buffer, size_t capacity, size_t offset, const char *text) {
    while (*text && offset + 1u < capacity) {
        buffer[offset] = *text;
        offset++;
        text++;
    }
    return offset;
}

static size_t append_decimal(char *buffer, size_t capacity, size_t offset, uint32_t value) {
    char digits[12];
    size_t count = 0u;
    do {
        digits[count] = (char)('0' + (value % 10u));
        value /= 10u;
        count++;
    } while (value && count < sizeof digits);
    while (count) {
        if (offset + 1u < capacity) buffer[offset] = digits[--count];
        offset++;
    }
    return offset;
}

static const char hex_digits[] = "0123456789abcdef";

static size_t append_hex(char *buffer, size_t capacity, size_t offset, uint8_t value) {
    if (offset + 2u < capacity) {
        buffer[offset] = hex_digits[(value >> 4) & 0xfu];
        buffer[offset + 1u] = hex_digits[value & 0xfu];
    }
    return offset + 2u;
}

int drizzle_endpoint_text(const drizzle_endpoint_t *endpoint, char *buffer, size_t capacity) {
    size_t offset = 0u;
    size_t index;

    if (!buffer || capacity == 0u) return 0;
    buffer[0] = 0;
    if (!endpoint) return 0;

    if (endpoint->family == DR1ZZLE_AF_INET6) {
        /* RFC 5952: compress the longest run of zero groups. */
        int best_start = -1;
        int best_length = 0;
        int run_start = -1;
        int run_length = 0;
        uint16_t groups[8];

        for (index = 0u; index < 8u; index++) {
            groups[index] = (uint16_t)(((uint16_t)endpoint->address[index * 2u] << 8) |
                                       endpoint->address[index * 2u + 1u]);
            if (groups[index] == 0u) {
                if (run_start < 0) {
                    run_start = (int)index;
                    run_length = 1;
                } else {
                    run_length++;
                }
                if (run_length > best_length) {
                    best_length = run_length;
                    best_start = run_start;
                }
            } else {
                run_start = -1;
                run_length = 0;
            }
        }
        if (best_length < 2) {
            best_start = -1;
            best_length = 0;
        }

        for (index = 0u; index < 8u; index++) {
            if ((int)index == best_start) {
                offset = append_text(buffer, capacity, offset, "::");
                index += (size_t)best_length - 1u;
                continue;
            }
            if (index > 0u && (int)index != best_start + best_length) {
                offset = append_text(buffer, capacity, offset, ":");
            }
            if (groups[index] > 0x0fffu) {
                if (offset + 1u < capacity) {
                    buffer[offset] = hex_digits[(groups[index] >> 12) & 0xfu];
                }
                offset = append_hex(buffer, capacity, offset,
                                    (uint8_t)((groups[index] >> 8) & 0xffu));
                offset = append_hex(buffer, capacity, offset,
                                    (uint8_t)(groups[index] & 0xffu));
            } else if (groups[index] > 0x00ffu) {
                if (offset + 1u < capacity) {
                    buffer[offset] = hex_digits[(groups[index] >> 8) & 0xfu];
                }
                offset++;
                offset = append_hex(buffer, capacity, offset, (uint8_t)(groups[index] & 0xffu));
            } else {
                offset = append_decimal(buffer, capacity, offset, groups[index]);
            }
        }
    } else {
        for (index = 0u; index < 4u; index++) {
            if (index) offset = append_text(buffer, capacity, offset, ".");
            offset = append_decimal(buffer, capacity, offset, endpoint->address[index]);
        }
    }
    if (offset + 1u < capacity) {
        buffer[offset] = ':';
        buffer[offset + 1u] = 0;
        return (int)(offset + 1u);
    }
    return (int)offset;
}

static int parse_decimal(const char **cursor, uint32_t *value, uint32_t limit) {
    uint32_t accumulated = 0u;
    const char *scan = *cursor;
    int digits = 0;

    while (*scan >= '0' && *scan <= '9') {
        accumulated = accumulated * 10u + (uint32_t)(*scan - '0');
        if (accumulated > limit) return 0;
        scan++;
        digits++;
    }
    if (digits == 0) return 0;
    *cursor = scan;
    *value = accumulated;
    return 1;
}

static int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int parse_ipv4(const char *text, uint8_t out[4]) {
    const char *cursor = text;
    unsigned index;

    for (index = 0u; index < 4u; index++) {
        uint32_t value = 0u;
        if (!parse_decimal(&cursor, &value, 255u)) return 0;
        out[index] = (uint8_t)value;
        if (index < 3u) {
            if (*cursor != '.') return 0;
            cursor++;
        }
    }
    return *cursor == 0;
}

/* RFC 4291 text form, including "::" run compression. Groups are split into the
 * part before and after the gap so each side can be placed without guessing. */
static int parse_ipv6(const char *text, uint8_t out[16]) {
    uint16_t head[8];
    uint16_t tail[8];
    unsigned head_count = 0u;
    unsigned tail_count = 0u;
    const char *cursor = text;
    int seen_gap = 0;
    unsigned index;

    memset(head, 0, sizeof head);
    memset(tail, 0, sizeof tail);

    if (cursor[0] == ':') {
        if (cursor[1] != ':') return 0;
        seen_gap = 1;
        cursor += 2;
    }

    while (*cursor) {
        uint32_t value = 0u;
        unsigned digits = 0u;

        while (hex_value(*cursor) >= 0) {
            value = value * 16u + (uint32_t)hex_value(*cursor);
            cursor++;
            if (++digits > 4u) return 0;
        }
        if (digits == 0u) return 0;

        if (seen_gap) {
            if (tail_count >= 8u) return 0;
            tail[tail_count++] = (uint16_t)value;
        } else {
            if (head_count >= 8u) return 0;
            head[head_count++] = (uint16_t)value;
        }

        if (*cursor == ':') {
            cursor++;
            if (*cursor == ':') {
                if (seen_gap) return 0;
                seen_gap = 1;
                cursor++;
                if (!*cursor) break;
            } else if (!*cursor) {
                return 0; /* a lone trailing colon is not valid */
            }
        } else {
            break;
        }
    }

    if (!seen_gap && head_count != 8u) return 0;
    if (seen_gap && head_count + tail_count > 8u) return 0;

    memset(out, 0, 16u);
    for (index = 0u; index < head_count; index++) {
        out[index * 2u] = (uint8_t)(head[index] >> 8);
        out[index * 2u + 1u] = (uint8_t)head[index];
    }
    for (index = 0u; index < tail_count; index++) {
        unsigned slot = 8u - tail_count + index;
        out[slot * 2u] = (uint8_t)(tail[index] >> 8);
        out[slot * 2u + 1u] = (uint8_t)tail[index];
    }
    return 1;
}

int drizzle_endpoint_parse(const char *text, drizzle_endpoint_t *endpoint) {
    uint8_t scratch[16];
    char work[72];
    size_t length;
    unsigned colons = 0u;
    size_t index;
    const char *port_text = NULL;
    uint32_t port = 0u;

    if (!text || !endpoint) return 0;
    memset(endpoint, 0, sizeof *endpoint);

    length = strlen(text);
    if (length == 0u || length >= sizeof work) return 0;
    memcpy(work, text, length + 1u);

    for (index = 0u; index < length; index++) {
        if (work[index] == ':') colons++;
    }

    if (colons >= 2u) {
        if (!parse_ipv6(work, scratch)) {
            /* Try again without a trailing ":port". */
            size_t colon_index = length;
            while (colon_index > 0u) {
                if (work[colon_index - 1u] == ':') break;
                colon_index--;
            }
            if (colon_index == 0u) return 0;
            work[colon_index - 1u] = 0;
            if (!parse_ipv6(work, scratch)) return 0;
            port_text = text + colon_index;
        }
        drizzle_endpoint_v6(endpoint, 0, scratch);
    } else {
        if (colons == 1u) {
            char *colon = strchr(work, ':');
            *colon = 0;
            port_text = text + (size_t)(colon - work) + 1u;
        }
        if (!parse_ipv4(work, scratch)) return 0;
        drizzle_endpoint_v4(endpoint, 0, scratch);
    }

    if (port_text) {
        const char *cursor = port_text;
        if (!parse_decimal(&cursor, &port, 65535u)) return 0;
        if (*cursor) return 0;
        endpoint->port = (uint16_t)port;
    }
    return 1;
}