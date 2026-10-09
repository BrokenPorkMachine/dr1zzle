#ifndef DRIZZLE_DNS_H
#define DRIZZLE_DNS_H

#include <drizzle/net.h>
#include <stddef.h>
#include <stdint.h>

/* Minimal stub resolver plus a tiny authoritative server for the local name.
 *
 * The resolver issues A and AAAA in parallel so callers can prefer IPv6 and
 * fall back without a second round trip. Answers are cached for the TTL the
 * authority returned.
 */
void drizzle_dns_init(const uint8_t servers[4][4], unsigned server_count);
void drizzle_dns_set_hostname(const char *name);

/* Synchronous resolve with an internal retry budget. Returns 1 on success and
 * fills family/address for the best available result. Prefers IPv6. */
int drizzle_dns_resolve(const char *name, drizzle_family_t *family, uint8_t *address);

void drizzle_dns_poll(void);

/* Number of cached entries. */
unsigned drizzle_dns_cache_count(void);

/* --- tiny authoritative server -----------------------------------------
 * Answers A and AAAA queries for the configured local hostname using the
 * host's current addresses, and refuses everything else. Lets a known device
 * be reached by name over the console's link.
 */
void drizzle_dns_server_enable(uint16_t port);
void drizzle_dns_server_disable(void);

#endif
