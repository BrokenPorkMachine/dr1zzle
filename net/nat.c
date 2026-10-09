#include "internal.h"
#include <string.h>
#include "drizzle/nat.h"

/* Source-hiding masquerade.
 *
 * Outbound packets have their source address replaced with the host's public
 * address and their source port replaced with an allocated one. A table entry
 * remembers that pairing so the response stream can be recognised on the way
 * back in and mapped to the port the local socket actually used.
 *
 * This is deliberately single-link and IPv4-only: it hides one host behind the
 * link's own address, which is what a device sharing its connection needs. It is
 * not a router and does not forward between interfaces.
 */

#define DR1ZZLE_NAT_MAX 16u
#define DR1ZZLE_NAT_IDLE_MS 120000u
#define DR1ZZLE_NAT_PORT_MIN 40000u
#define DR1ZZLE_NAT_PORT_MAX 60000u

typedef struct {
    int in_use;
    uint8_t protocol;
    uint32_t remote;       /* host-order IPv4 address of the peer */
    uint16_t remote_port;  /* peer's port */
    uint16_t public_port;  /* port the peer sees */
    uint16_t local_port;   /* the socket's own port, pre-translation */
    uint32_t touched_ms;
} nat_entry_t;

static nat_entry_t entries[DR1ZZLE_NAT_MAX];
static uint8_t public_address[4];
static uint16_t public_base;
static uint32_t expired_count;
static int active;

void drizzle_nat_enable(const uint8_t address[4], uint16_t port) {
    memcpy(public_address, address, 4u);
    public_base = port;
    active = 1;
}

void drizzle_nat_disable(void) {
    memset(entries, 0, sizeof entries);
    active = 0;
    public_base = 0u;
}

int drizzle_nat_enabled(void) {
    return active;
}

unsigned drizzle_nat_connection_count(void) {
    unsigned count = 0u;
    size_t index;
    for (index = 0u; index < DR1ZZLE_NAT_MAX; index++) {
        if (entries[index].in_use) count++;
    }
    return count;
}

uint32_t drizzle_nat_expired(void) {
    return expired_count;
}

static nat_entry_t *lookup_outbound(uint8_t protocol, uint32_t remote, uint16_t remote_port) {
    size_t index;
    for (index = 0u; index < DR1ZZLE_NAT_MAX; index++) {
        nat_entry_t *entry = &entries[index];
        if (!entry->in_use) continue;
        if (entry->protocol == protocol && entry->remote == remote &&
            entry->remote_port == remote_port) {
            return entry;
        }
    }
    return NULL;
}

static nat_entry_t *lookup_inbound(uint8_t protocol, uint32_t remote, uint16_t remote_port,
                                   uint16_t public_port) {
    size_t index;
    for (index = 0u; index < DR1ZZLE_NAT_MAX; index++) {
        nat_entry_t *entry = &entries[index];
        if (!entry->in_use) continue;
        if (entry->protocol != protocol || entry->public_port != public_port) continue;
        if (entry->remote != remote || entry->remote_port != remote_port) continue;
        entry->touched_ms = (uint32_t)drizzle_time_ms();
        return entry;
    }
    return NULL;
}

static nat_entry_t *allocate_entry(void) {
    size_t index;
    nat_entry_t *oldest = NULL;
    for (index = 0u; index < DR1ZZLE_NAT_MAX; index++) {
        if (!entries[index].in_use) return &entries[index];
        if (!oldest || entries[index].touched_ms < oldest->touched_ms) {
            oldest = &entries[index];
        }
    }
    /* Table full: drop the least recently active conversation. */
    memset(oldest, 0, sizeof *oldest);
    return oldest;
}

static uint16_t choose_public_port(void) {
    uint16_t offset;
    for (offset = 0u; offset <= (uint16_t)(DR1ZZLE_NAT_PORT_MAX - DR1ZZLE_NAT_PORT_MIN);
         offset++) {
        uint16_t candidate = (uint16_t)(public_base + offset);
        size_t index;
        int conflict = 0;
        if (candidate < DR1ZZLE_NAT_PORT_MIN || candidate > DR1ZZLE_NAT_PORT_MAX) continue;
        for (index = 0u; index < DR1ZZLE_NAT_MAX; index++) {
            if (entries[index].in_use && entries[index].public_port == candidate) {
                conflict = 1;
                break;
            }
        }
        if (!conflict) return candidate;
    }
    return 0u;
}

static int nat_handles(uint8_t protocol) {
    return protocol == (uint8_t)DR1ZZLE_IPPROTO_TCP ||
           protocol == (uint8_t)DR1ZZLE_IPPROTO_UDP;
}

void net_nat_output(drizzle_family_t family, drizzle_endpoint_t *source,
                    const drizzle_endpoint_t *destination, uint8_t protocol,
                    uint8_t **payload, size_t *length, unsigned *ttl) {
    nat_entry_t *entry;
    uint32_t remote;
    uint16_t allocated;

    (void)ttl;
    (void)length;
    if (!active || family != DR1ZZLE_AF_INET) return;
    if (!nat_handles(protocol)) return;
    /* Traffic already on the link is not hidden. */
    if (net_on_local_link(destination->address)) return;
    /* A segment must be at least large enough to carry the port being changed. */
    if (!*payload || *length < 4u) return;

    remote = net_read32(destination->address);

    entry = lookup_outbound(protocol, remote, destination->port);
    if (!entry) {
        allocated = choose_public_port();
        if (allocated == 0u) return;
        entry = allocate_entry();
        if (!entry) return;
        entry->in_use = 1;
        entry->protocol = protocol;
        entry->remote = remote;
        entry->remote_port = destination->port;
        entry->local_port = source->port;
        entry->public_port = allocated;
        entry->touched_ms = (uint32_t)drizzle_time_ms();
    }
    entry->touched_ms = (uint32_t)drizzle_time_ms();

    memcpy(source->address, public_address, 4u);
    source->port = entry->public_port;

    /* The transport header carries the same port, so patch it in place. */
    net_write16(*payload, entry->public_port);
}

int net_nat_input(drizzle_family_t family, const drizzle_endpoint_t *source,
                  drizzle_endpoint_t *destination, uint8_t protocol,
                  uint8_t **payload, size_t *length) {
    nat_entry_t *entry;

    if (!active || family != DR1ZZLE_AF_INET) return 0;
    if (!nat_handles(protocol)) return 0;
    if (!*payload || !length || *length < 4u) return 0;

    /* Only packets aimed at the public address can be replies we care about. */
    if (memcmp(destination->address, public_address, 4u) != 0) return 0;

    entry = lookup_inbound(protocol, net_read32(source->address), source->port,
                           destination->port);
    if (!entry) return 0;

    /* Restore the port the local socket is bound to. */
    net_write16(*payload, entry->local_port);
    destination->port = entry->local_port;
    return 1;
}

void net_nat_tick(void) {
    size_t index;
    uint32_t now = (uint32_t)drizzle_time_ms();
    for (index = 0u; index < DR1ZZLE_NAT_MAX; index++) {
        if (entries[index].in_use &&
            (now - entries[index].touched_ms) >= DR1ZZLE_NAT_IDLE_MS) {
            memset(&entries[index], 0, sizeof entries[index]);
            expired_count++;
        }
    }
}