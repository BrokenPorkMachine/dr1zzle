#include "internal.h"
#include <string.h>
#include "drizzle/udp.h"

/* UDP. Ports are bound across both address families at once, which is what lets
 * a single DNS or console port answer on IPv4 and IPv6 without duplicating
 * registration. */

#define DR1ZZLE_UDP_BIND_MAX 8u
#define DR1ZZLE_UDP_RECV_MAX 1500u

typedef struct {
    uint16_t port;
    int bound;
    drizzle_endpoint_t source;
    size_t length;
    uint8_t data[DR1ZZLE_UDP_RECV_MAX];
} udp_binding_t;

static udp_binding_t bindings[DR1ZZLE_UDP_BIND_MAX];
static uint16_t local_port = DR1ZZLE_UDP_LOCAL_PORT_DEFAULT;

static udp_binding_t *net_udp_binding(uint16_t port) {
    size_t index;
    for (index = 0u; index < DR1ZZLE_UDP_BIND_MAX; index++) {
        if (bindings[index].bound && bindings[index].port == port) return &bindings[index];
    }
    return NULL;
}

static udp_binding_t *udp_claim(uint16_t port) {
    size_t index;
    udp_binding_t *slot = NULL;
    for (index = 0u; index < DR1ZZLE_UDP_BIND_MAX; index++) {
        if (bindings[index].bound && bindings[index].port == port) return &bindings[index];
        if (!bindings[index].bound && !slot) slot = &bindings[index];
    }
    if (slot) {
        memset(slot, 0, sizeof *slot);
        slot->bound = 1;
        slot->port = port;
    }
    return slot;
}

int drizzle_udp_bind(uint16_t port) {
    if (!udp_claim(port)) return 0;
    /* Binding is also how a client reserves the port its replies arrive on, so
     * outbound sends adopt it as the source port. */
    local_port = port;
    return 1;
}

void drizzle_udp_set_local_port(uint16_t port) {
    local_port = port;
}

uint16_t drizzle_udp_local_port(void) {
    return local_port;
}

void drizzle_udp_unbind(uint16_t port) {
    udp_binding_t *slot = net_udp_binding(port);
    if (!slot) return;
    if (local_port == port) local_port = DR1ZZLE_UDP_LOCAL_PORT_DEFAULT;
    memset(slot, 0, sizeof *slot);
}

uint16_t drizzle_udp_bound_count(void) {
    uint16_t count = 0u;
    size_t index;
    for (index = 0u; index < DR1ZZLE_UDP_BIND_MAX; index++) {
        if (bindings[index].bound) count++;
    }
    return count;
}

int drizzle_udp_send_to(const drizzle_endpoint_t *destination, const uint8_t *data,
                        size_t length) {
    uint8_t segment[DR1ZZLE_UDP_HEADER + DR1ZZLE_ETH_MTU];
    size_t total = DR1ZZLE_UDP_HEADER + length;
    const uint8_t *local = (destination->family == DR1ZZLE_AF_INET6) ? drizzle_net_v6()
                                                                    : drizzle_net_v4();
    uint16_t checksum;

    if (total > sizeof segment) return -1;
    if (destination->family == DR1ZZLE_AF_INET && !drizzle_net_has_v4()) return -1;
    if (destination->family == DR1ZZLE_AF_INET6 && !drizzle_net_has_v6()) return -1;

    net_write16(segment, local_port);
    net_write16(segment + 2, destination->port);
    net_write16(segment + 4, (uint16_t)total);
    net_write16(segment + 6, 0u);
    memcpy(segment + DR1ZZLE_UDP_HEADER, data, length);

    checksum = net_transport_checksum(destination->family, local, destination->address,
                                      (uint8_t)DR1ZZLE_IPPROTO_UDP, segment, total);
    /* Over IPv4 a zero checksum means "absent"; send all ones instead so the
     * result is unambiguous. IPv6 requires the checksum outright. */
    if (checksum == 0u) checksum = 0xffffu;
    net_write16(segment + 6, checksum);

    return net_ip_send(destination->family, destination, (uint8_t)DR1ZZLE_IPPROTO_UDP,
                       segment, total, 64u);
}

int drizzle_udp_send_v4(const uint8_t address[4], uint16_t port, const uint8_t *data,
                        size_t length) {
    drizzle_endpoint_t destination;
    drizzle_endpoint_v4(&destination, port, address);
    return drizzle_udp_send_to(&destination, data, length);
}

int drizzle_udp_receive(uint16_t port, uint8_t *buffer, size_t capacity,
                        drizzle_endpoint_t *source) {
    udp_binding_t *slot = net_udp_binding(port);
    size_t copy;

    if (!slot || slot->length == 0u) return -1;
    copy = slot->length < capacity ? slot->length : capacity;
    memcpy(buffer, slot->data, copy);
    if (source) *source = slot->source;
    slot->length = 0u;
    return (int)copy;
}

void drizzle_udp_input(const drizzle_endpoint_t *source,
                       const drizzle_endpoint_t *destination, const uint8_t *payload,
                       size_t length) {
    uint16_t source_port;
    uint16_t declared_length;
    udp_binding_t *slot;

    if (length < DR1ZZLE_UDP_HEADER) {
        drizzle_net_count_drop();
        return;
    }
    source_port = net_read16(payload);
    declared_length = net_read16(payload + 2);
    if (declared_length < DR1ZZLE_UDP_HEADER || declared_length > length) {
        drizzle_net_count_drop();
        return;
    }

    /* Only one datagram may be pending per port; a full slot drops the new
     * arrival rather than overwriting a datagram the reader has not seen. */
    slot = net_udp_binding(destination->port);
    if (!slot) return;

    slot->source = *source;
    slot->length = declared_length - DR1ZZLE_UDP_HEADER;
    if (slot->length > DR1ZZLE_UDP_RECV_MAX) slot->length = DR1ZZLE_UDP_RECV_MAX;
    memcpy(slot->data, payload + DR1ZZLE_UDP_HEADER, slot->length);
}

void drizzle_udp_discard(uint16_t port, const drizzle_endpoint_t *source) {
    udp_binding_t *slot = net_udp_binding(port);
    if (!slot) return;
    if (source && !drizzle_endpoint_equal(&slot->source, source)) return;
    slot->length = 0u;
}