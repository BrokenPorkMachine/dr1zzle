#include "internal.h"
#include <string.h>

/* ICMPv6 neighbour discovery (RFC 4861), the IPv6 counterpart of ARP. Only the
 * pieces a host needs are implemented: solicitation, advertisement, and
 * answering a neighbour solicitation. The link-layer MAC for multicast
 * destinations is derived by the neighbour cache, so nothing here needs to
 * know about Ethernet framing. */

#define DR1ZZLE_NDP_OPT_SOURCE_LINK 1u
#define DR1ZZLE_NDP_OPT_TARGET_LINK 2u

#define DR1ZZLE_NDP_LINKADDR_LEN 8u /* type, length, 6 bytes of address */

#define DR1ZZLE_NDP_FLAG_SOLICITED 0x40000000u
#define DR1ZZLE_NDP_FLAG_OVERRIDE 0x20000000u

static void write_option(uint8_t *destination, uint8_t type, const uint8_t *hardware) {
    destination[0] = type;
    destination[1] = 2u; /* length in units of 8-byte options */
    memcpy(destination + 2, hardware, DR1ZZLE_MAC_LEN);
}

static const uint8_t *find_option(const uint8_t *options, size_t length, uint8_t type,
                                  size_t *option_length) {
    size_t offset = 0u;
    while (offset + 2u <= length) {
        size_t total = (size_t)options[offset + 1] * 8u;
        if (total == 0u || offset + total > length) return NULL;
        if (options[offset] == type) {
            if (option_length) *option_length = total;
            return options + offset;
        }
        offset += total;
    }
    return NULL;
}

void net_ndp_solicit(const uint8_t *target) {
    /* Solicited-node multicast address ff02::1:ffXX:XXXX. The IPv6 layer fills
     * in the checksum, which is why the field is left zero here. */
    uint8_t destination[16];
    uint8_t message[32u + DR1ZZLE_NDP_LINKADDR_LEN];
    drizzle_endpoint_t endpoint;

    memset(destination, 0, sizeof destination);
    destination[0] = 0xffu;
    destination[1] = 0x02u;
    destination[11] = 0x01u;
    destination[12] = 0xffu;
    memcpy(destination + 13, target + 13, 3u);

    memset(message, 0, sizeof message);
    message[0] = (uint8_t)DR1ZZLE_ICMP6_NEIGHBOR_SOLICIT;
    net_write32(message + 8, 0u); /* reserved */
    memcpy(message + 12, target, 16u);
    write_option(message + 28, (uint8_t)DR1ZZLE_NDP_OPT_SOURCE_LINK, drizzle_net_mac());

    endpoint.family = DR1ZZLE_AF_INET6;
    memcpy(endpoint.address, destination, 16u);
    endpoint.port = 0u;

    net_ip_send(DR1ZZLE_AF_INET6, &endpoint, (uint8_t)DR1ZZLE_IPPROTO_ICMP6, message,
                sizeof message, 255u);
}

void net_ndp_input(const uint8_t *source, const uint8_t *payload, size_t length) {
    uint8_t type;
    size_t option_length = 0u;
    const uint8_t *option;

    if (length < 32u) {
        drizzle_net_count_drop();
        return;
    }
    type = payload[0];
    if (payload[1] != 0u) return; /* only code 0 is defined for ND */

    if (type == DR1ZZLE_ICMP6_NEIGHBOR_ADVERT) {
        const uint8_t *target = payload + 8;
        option = find_option(payload + 32, length - 32u,
                             (uint8_t)DR1ZZLE_NDP_OPT_TARGET_LINK, &option_length);
        if (!option || option_length < DR1ZZLE_NDP_LINKADDR_LEN) return;
        /* Bit 5 is the router flag, bit 6 "override". A solicited address is
         * unicast; a multicast advertisement must not enter the cache. */
        if ((net_read32(payload + 4) & 0x20u) == 0u) {
            net_neighbor_learn(DR1ZZLE_AF_INET6, target, option + 2);
        }
    } else if (type == DR1ZZLE_ICMP6_NEIGHBOR_SOLICIT) {
        const uint8_t *target = payload + 8;
        const uint8_t *local_address;
        uint8_t reply[32u + DR1ZZLE_NDP_LINKADDR_LEN];
        drizzle_endpoint_t destination;

        if (!drizzle_net_has_v6()) return;
        local_address = drizzle_net_v6();
        if (memcmp(target, local_address, 16u) != 0) return;

        option = find_option(payload + 32, length - 32u,
                             (uint8_t)DR1ZZLE_NDP_OPT_SOURCE_LINK, &option_length);
        if (!option || option_length < DR1ZZLE_NDP_LINKADDR_LEN) return;

        memset(reply, 0, sizeof reply);
        reply[0] = (uint8_t)DR1ZZLE_ICMP6_NEIGHBOR_ADVERT;
        net_write32(reply + 4, DR1ZZLE_NDP_FLAG_SOLICITED | DR1ZZLE_NDP_FLAG_OVERRIDE);
        memcpy(reply + 12, local_address, 16u);
        write_option(reply + 28, (uint8_t)DR1ZZLE_NDP_OPT_TARGET_LINK, drizzle_net_mac());

        /* Reply to whoever asked, not to the address that was solicited. */
        destination.family = DR1ZZLE_AF_INET6;
        memcpy(destination.address, source, 16u);
        destination.port = 0u;
        net_ip_send(DR1ZZLE_AF_INET6, &destination, (uint8_t)DR1ZZLE_IPPROTO_ICMP6,
                    reply, sizeof reply, 255u);
    }
}