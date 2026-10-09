#ifndef DRIZZLE_NAT_H
#define DRIZZLE_NAT_H

#include <drizzle/net.h>
#include <stddef.h>
#include <stdint.h>

/* Source-hiding masquerade, the arrangement a phone uses when sharing a
 * connection: outbound packets get the host's address and a rewritten port,
 * and inbound packets are matched back to the connection that owns them.
 *
 * This is a single-link NAT. It hides one host behind the link's own address;
 * it is not a router and does not forward between interfaces.
 */
void drizzle_nat_enable(const uint8_t public_address[4], uint16_t public_port);
void drizzle_nat_disable(void);
int drizzle_nat_enabled(void);

/* Inbound connections currently tracked. */
unsigned drizzle_nat_connection_count(void);

/* Expired entries reclaimed by the poll timer. */
uint32_t drizzle_nat_expired(void);

#endif
