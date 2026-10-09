#include "internal.h"
#include <string.h>

/* Ethernet II framing and the neighbour cache that resolves next hops for both
 * address families. */

#define DR1ZZLE_NEIGHBOR_MAX 16u
#define DR1ZZLE_NEIGHBOR_TTL_MS 30000u
#define DR1ZZLE_NEIGHBOR_RETRY_MS 1000u

typedef struct {
    drizzle_family_t family;
    uint8_t address[DR1ZZLE_IP_MAX];
    uint8_t hardware[DR1ZZLE_MAC_LEN];
    uint32_t learned_ms;
    uint32_t solicited_ms;
    int in_use;
    int resolved;
} neighbor_entry_t;

static neighbor_entry_t neighbors[DR1ZZLE_NEIGHBOR_MAX];
static const uint8_t broadcast_mac[DR1ZZLE_MAC_LEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

static size_t address_length_of(drizzle_family_t family) {
    return (family == DR1ZZLE_AF_INET6) ? 16u : 4u;
}

static int addresses_equal(const uint8_t *left, const uint8_t *right, size_t length) {
    return memcmp(left, right, length) == 0;
}

static neighbor_entry_t *neighbor_find(drizzle_family_t family, const uint8_t *address) {
    size_t index;
    size_t length = address_length_of(family);
    for (index = 0u; index < DR1ZZLE_NEIGHBOR_MAX; index++) {
        neighbor_entry_t *entry = &neighbors[index];
        if (entry->in_use && entry->family == family &&
            addresses_equal(entry->address, address, length)) {
            return entry;
        }
    }
    return NULL;
}

static neighbor_entry_t *neighbor_allocate(void) {
    size_t index;
    neighbor_entry_t *oldest = NULL;
    for (index = 0u; index < DR1ZZLE_NEIGHBOR_MAX; index++) {
        if (!neighbors[index].in_use) return &neighbors[index];
        if (!oldest || neighbors[index].learned_ms < oldest->learned_ms) {
            oldest = &neighbors[index];
        }
    }
    /* Every slot is in use: recycle the least recently resolved one. */
    if (oldest) memset(oldest, 0, sizeof *oldest);
    return oldest;
}

static void solicit(drizzle_family_t family, const uint8_t *address) {
    if (family == DR1ZZLE_AF_INET6) {
        net_ndp_solicit(address);
    } else {
        net_arp_request(address);
    }
}

void net_neighbor_learn(drizzle_family_t family, const uint8_t *address,
                        const uint8_t hardware[DR1ZZLE_MAC_LEN]) {
    size_t length = address_length_of(family);
    neighbor_entry_t *entry = neighbor_find(family, address);
    if (!entry) entry = neighbor_allocate();
    if (!entry) return;
    entry->family = family;
    memcpy(entry->address, address, length);
    memcpy(entry->hardware, hardware, DR1ZZLE_MAC_LEN);
    entry->learned_ms = (uint32_t)drizzle_time_ms();
    entry->in_use = 1;
    entry->resolved = 1;
    /* This reply is very likely what a queued packet was blocked on. */
    net_ip_send_flush();
}

int net_neighbor_resolve(drizzle_family_t family, const uint8_t *address,
                         uint8_t hardware[DR1ZZLE_MAC_LEN]) {
    size_t length = address_length_of(family);
    neighbor_entry_t *entry;
    uint32_t now = (uint32_t)drizzle_time_ms();

    if (family == DR1ZZLE_AF_INET6 && address[0] == 0xffu) {
        /* IPv6 multicast maps onto 33:33 plus the low 32 bits of the address,
         * which covers solicited-node (ff02::1:ff00:0/104) and all-nodes. */
        hardware[0] = 0x33u;
        hardware[1] = 0x33u;
        hardware[2] = address[12];
        hardware[3] = address[13];
        hardware[4] = address[14];
        hardware[5] = address[15];
        return 1;
    }

    entry = neighbor_find(family, address);
    if (entry && entry->resolved && (now - entry->learned_ms) < DR1ZZLE_NEIGHBOR_TTL_MS) {
        memcpy(hardware, entry->hardware, DR1ZZLE_MAC_LEN);
        return 1;
    }

    if (!entry) entry = neighbor_allocate();
    if (!entry) return 0;

    entry->family = family;
    memcpy(entry->address, address, length);
    entry->resolved = 0;
    entry->in_use = 1;

    /* Ask, but no more than once per retry interval, so an absent neighbour
     * cannot be used to spin the transmit path. */
    if ((now - entry->solicited_ms) >= DR1ZZLE_NEIGHBOR_RETRY_MS ||
        entry->solicited_ms == 0u) {
        entry->solicited_ms = now ? now : 1u;
        solicit(family, address);
    }
    return 0;
}

void net_neighbor_forget(const uint8_t *address) {
    size_t index;
    for (index = 0u; index < DR1ZZLE_NEIGHBOR_MAX; index++) {
        if (neighbors[index].in_use &&
            addresses_equal(neighbors[index].address, address,
                            address_length_of(neighbors[index].family))) {
            memset(&neighbors[index], 0, sizeof neighbors[index]);
        }
    }
}

void net_neighbor_tick(void) {
    size_t index;
    uint32_t now = (uint32_t)drizzle_time_ms();
    for (index = 0u; index < DR1ZZLE_NEIGHBOR_MAX; index++) {
        if (neighbors[index].in_use && neighbors[index].resolved &&
            (now - neighbors[index].learned_ms) >= DR1ZZLE_NEIGHBOR_TTL_MS) {
            memset(&neighbors[index], 0, sizeof neighbors[index]);
        }
    }
}

void net_neighbor_flush(void) {
    memset(neighbors, 0, sizeof neighbors);
}

int net_on_local_link(const uint8_t *destination) {
    const uint8_t *netmask;
    const uint8_t *local;
    size_t index;

    if (!drizzle_net_has_v4()) return 0;
    netmask = drizzle_net_v4_netmask();
    local = drizzle_net_v4();
    if (!netmask || !local) return 0;
    for (index = 0u; index < 4u; index++) {
        if ((destination[index] & netmask[index]) != (local[index] & netmask[index])) {
            return 0;
        }
    }
    return 1;
}

int net_next_hop(drizzle_family_t family, const uint8_t *destination,
                 uint8_t hardware[DR1ZZLE_MAC_LEN]) {
    const uint8_t *next = destination;

    if (family == DR1ZZLE_AF_INET) {
        if (!drizzle_net_has_v4()) return 0;
        if (!net_on_local_link(destination)) {
            next = drizzle_net_v4_gateway();
            if (!net_on_local_link(next) && net_neighbor_resolve(DR1ZZLE_AF_INET, next,
                                                                  hardware)) {
                return 1;
            }
            if (!next[0] && !next[1] && !next[2] && !next[3]) return 0;
        }
    } else {
        if (!drizzle_net_has_v6()) return 0;
        /* Anything that is not link-local and not a solicited-node multicast
         * is expected to leave through the configured gateway. */
        if (!net_on_local_link_v6(destination) && destination[0] != 0xffu) {
            next = drizzle_net_v6_gateway();
            if (!next[0] && !next[1] && !next[2] && !next[3]) return 0;
        }
    }
    return net_neighbor_resolve(family, next, hardware);
}

int net_on_local_link_v6(const uint8_t *destination) {
    const uint8_t *local;
    unsigned prefix = drizzle_net_v6_prefix_length();
    size_t bytes;
    size_t bits;
    size_t index;

    if (!drizzle_net_has_v6()) return 0;
    /* Link-local neighbours are always reachable directly. */
    if (destination[0] == 0xfeu && (destination[1] & 0xc0u) == 0x80u) return 1;
    local = drizzle_net_v6();
    if (!local || prefix == 0u) return 0;

    bytes = (size_t)(prefix / 8u);
    bits = prefix % 8u;
    for (index = 0u; index < bytes; index++) {
        if (local[index] != destination[index]) return 0;
    }
    if (bits) {
        uint8_t mask = (uint8_t)(0xffu << (8u - bits));
        if ((local[bytes] & mask) != (destination[bytes] & mask)) return 0;
    }
    return 1;
}

void net_link_send_raw(const uint8_t *frame, size_t length) {
    const drizzle_link_t *link = drizzle_net_link();
    if (!link || !link->transmit) return;
    link->transmit(frame, length);
    drizzle_net_count_tx(length);
}

void net_link_send(const uint8_t destination[DR1ZZLE_MAC_LEN],
                   const uint8_t source[DR1ZZLE_MAC_LEN], uint16_t ethertype,
                   const uint8_t *payload, size_t payload_length) {
    uint8_t frame[DR1ZZLE_ETH_MTU + DR1ZZLE_ETH_HEADER];
    if (payload_length + DR1ZZLE_ETH_HEADER > sizeof frame) return;
    memcpy(frame, destination, DR1ZZLE_MAC_LEN);
    memcpy(frame + 6, source, DR1ZZLE_MAC_LEN);
    net_write16(frame + 12, ethertype);
    memcpy(frame + DR1ZZLE_ETH_HEADER, payload, payload_length);
    net_link_send_raw(frame, payload_length + DR1ZZLE_ETH_HEADER);
}