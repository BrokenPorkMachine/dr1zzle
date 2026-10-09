#ifndef DR1ZZLE_NET_INTERNAL_H
#define DR1ZZLE_NET_INTERNAL_H

#include <drizzle/net.h>
#include <drizzle/time.h>
#include <stddef.h>
#include <stdint.h>

/* ---- byte order ------------------------------------------------------- */

static inline uint16_t net_read16(const uint8_t *source) {
    return (uint16_t)(((uint16_t)source[0] << 8) | (uint16_t)source[1]);
}

static inline uint32_t net_read32(const uint8_t *source) {
    return ((uint32_t)source[0] << 24) | ((uint32_t)source[1] << 16) |
           ((uint32_t)source[2] << 8) | (uint32_t)source[3];
}

static inline void net_write16(uint8_t *destination, uint16_t value) {
    destination[0] = (uint8_t)(value >> 8);
    destination[1] = (uint8_t)value;
}

static inline void net_write32(uint8_t *destination, uint32_t value) {
    destination[0] = (uint8_t)(value >> 24);
    destination[1] = (uint8_t)(value >> 16);
    destination[2] = (uint8_t)(value >> 8);
    destination[3] = (uint8_t)value;
}

/* Unaligned reads are done byte-wise so the code never depends on packing
 * rules or the alignment of a received frame. */

/* ---- checksums -------------------------------------------------------- */

uint32_t net_checksum_add(uint32_t sum, const uint8_t *data, size_t length);
uint16_t net_checksum_finish(uint32_t sum);
uint16_t net_checksum(const uint8_t *data, size_t length);

/* Transport checksum over the IPv4 or IPv6 pseudo header. */
uint16_t net_transport_checksum(drizzle_family_t family, const uint8_t *source,
                                const uint8_t *destination, uint8_t protocol,
                                const uint8_t *segment, size_t length);

/* ---- link ------------------------------------------------------------- */

#define DR1ZZLE_ETHERTYPE_IPV4 0x0800u
#define DR1ZZLE_ETHERTYPE_ARP 0x0806u
#define DR1ZZLE_ETHERTYPE_IPV6 0x86ddu
#define DR1ZZLE_ETHERTYPE_VLAN 0x8100u

/* Builds an Ethernet header at the front of frame and hands it to the link. */
void net_link_send(const uint8_t destination[DR1ZZLE_MAC_LEN],
                   const uint8_t source[DR1ZZLE_MAC_LEN], uint16_t ethertype,
                   const uint8_t *payload, size_t payload_length);
void net_link_send_raw(const uint8_t *frame, size_t length);

/* Counters, maintained by the link layer. */
void drizzle_net_count_rx(size_t length);
void drizzle_net_count_tx(size_t length);
void drizzle_net_count_drop(void);

/* ---- neighbour cache (shared by ARP and NDP) -------------------------- */

int net_neighbor_resolve(drizzle_family_t family, const uint8_t *address,
                         uint8_t hardware[DR1ZZLE_MAC_LEN]);
void net_neighbor_learn(drizzle_family_t family, const uint8_t *address,
                        const uint8_t hardware[DR1ZZLE_MAC_LEN]);
void net_neighbor_forget(const uint8_t *address);
void net_neighbor_tick(void);
/* Discards everything and re-sends solicitations for the entries still needed
 * by the pending transmit queue. */
void net_neighbor_flush(void);

/* Sends an ARP request or a neighbour solicitation for the address. */
void net_arp_request(const uint8_t *address);
void net_ndp_solicit(const uint8_t *target);

/* True when the destination is on our own link and needs no gateway. */
int net_on_local_link(const uint8_t *destination);
int net_on_local_link_v6(const uint8_t *destination);

/* Resolves the MAC to send a datagram for `destination` through, taking the
 * configured gateway when the destination is off-link. Returns 1 on success. */
int net_next_hop(drizzle_family_t family, const uint8_t *destination,
                 uint8_t hardware[DR1ZZLE_MAC_LEN]);

/* ---- IP output -------------------------------------------------------- */

/* Hands a payload to the IP layer for transmission. `ttl` is the IPv4 TTL or
 * the IPv6 hop limit. Returns 0 on success. NAT and the pending-resolution
 * queue live behind this call. */
int net_ip_send(drizzle_family_t family, const drizzle_endpoint_t *destination,
                uint8_t protocol, const uint8_t *payload, size_t length,
                unsigned ttl);

/* Family-specific transmit. `destination` identifies the peer; the source
 * address is taken from the local configuration and may be rewritten by NAT. */
int net_ipv4_send(const drizzle_endpoint_t *destination, const uint8_t *payload,
                  size_t length, uint8_t protocol, unsigned ttl);
int net_ipv6_send(const drizzle_endpoint_t *destination, const uint8_t *payload,
                  size_t length, uint8_t protocol, unsigned ttl);

/* Records a payload that could not go out yet because the next hop is
 * unresolved. Flushed automatically once a reply arrives. */
void net_ip_send_queued(drizzle_family_t family, const drizzle_endpoint_t *destination,
                        uint8_t protocol, const uint8_t *payload, size_t length,
                        unsigned ttl);

/* Re-attempts every queued payload. Called after any resolution event. */
void net_ip_send_flush(void);

/* ---- IP input --------------------------------------------------------- */

void net_ipv4_input(const uint8_t *source, const uint8_t *payload, size_t length);
void net_ipv6_input(const uint8_t *source, const uint8_t *payload, size_t length);

void net_ipv4_reply_echo(const uint8_t *source, const uint8_t *destination,
                         const uint8_t *payload, size_t length);
void net_ipv6_reply_echo(const uint8_t *source, const uint8_t *destination,
                         const uint8_t *payload, size_t length);
void net_ipv4_unreachable(drizzle_family_t family, const uint8_t *source, uint8_t protocol,
                          const uint8_t *payload, size_t length);
void net_ipv6_unreachable(const uint8_t *source, const uint8_t *destination,
                          uint8_t code, const uint8_t *offending, size_t length);

/* ---- ARP / NDP -------------------------------------------------------- */

void net_arp_input(const uint8_t *payload, size_t length);
void net_ndp_input(const uint8_t *source, const uint8_t *payload, size_t length);

/* ---- NAT -------------------------------------------------------------- */

void net_nat_output(drizzle_family_t family, drizzle_endpoint_t *source,
                    const drizzle_endpoint_t *destination, uint8_t protocol,
                    uint8_t **payload, size_t *length, unsigned *ttl);
/* Inbound translation. Returns 1 when the packet matched a tracked
 * conversation, in which case the destination port has been restored to the
 * value the local socket is bound to. `payload` is the transport header, which
 * may be patched in place. */
int net_nat_input(drizzle_family_t family, const drizzle_endpoint_t *source,
                  drizzle_endpoint_t *destination, uint8_t protocol,
                  uint8_t **payload, size_t *length);
void net_nat_tick(void);

/* ---- ICMP ------------------------------------------------------------- */

#define DR1ZZLE_ICMP_ECHO_REPLY 0u
#define DR1ZZLE_ICMP_DEST_UNREACHABLE 3u
#define DR1ZZLE_ICMP_ECHO_REQUEST 8u
#define DR1ZZLE_ICMP_TIME_EXCEEDED 11u

#define DR1ZZLE_ICMP6_DEST_UNREACHABLE 1u
#define DR1ZZLE_ICMP6_PACKET_TOO_BIG 2u
#define DR1ZZLE_ICMP6_TIME_EXCEEDED 3u
#define DR1ZZLE_ICMP6_ECHO_REQUEST 128u
#define DR1ZZLE_ICMP6_ECHO_REPLY 129u
#define DR1ZZLE_ICMP6_NEIGHBOR_SOLICIT 135u
#define DR1ZZLE_ICMP6_NEIGHBOR_ADVERT 136u

#endif