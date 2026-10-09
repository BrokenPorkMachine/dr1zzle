#ifndef DRIZZLE_DHCP_H
#define DRIZZLE_DHCP_H

#include <stdint.h>

/* DHCPv4 client (RFC 2131) in the four-packet DISCOVER/OFFER/REQUEST/ACK
 * sequence. Until it completes the link has no address, so the poll loop drives
 * it exactly like the rest of the stack.
 *
 * Everything it learns -- address, netmask, gateway, DNS servers, lease time --
 * is pushed into the network configuration as it arrives, so higher layers work
 * unchanged once it binds.
 */
void drizzle_dhcp_start(void);
void drizzle_dhcp_poll(void);

int drizzle_dhcp_bound(void);
uint32_t drizzle_dhcp_lease_seconds(void);

/* Decoding is separated from the wire so it can be tested without a timer. */
int net_dhcp_decode(const uint8_t *message, size_t length, uint32_t *offered_address,
                    uint32_t *netmask, uint32_t *gateway, uint8_t (*dns)[4],
                    unsigned *dns_count, uint32_t *lease_seconds);

#endif