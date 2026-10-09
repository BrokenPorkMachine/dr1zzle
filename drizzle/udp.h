#ifndef DRIZZLE_UDP_H
#define DRIZZLE_UDP_H

#include <drizzle/net.h>
#include <stddef.h>
#include <stdint.h>

#define DR1ZZLE_UDP_LOCAL_PORT_DEFAULT 49152u

/* UDP. Ports are addressed by number across both families at once, which is what
 * lets one port answer on IPv4 and IPv6 without registering it twice.
 *
 * Binding a port also reserves it as the source port for outbound sends, and is
 * where replies to those sends are delivered. That is what lets a client work
 * without a separate socket table.
 */
int drizzle_udp_bind(uint16_t port);
void drizzle_udp_unbind(uint16_t port);
void drizzle_udp_set_local_port(uint16_t port);
uint16_t drizzle_udp_local_port(void);

/* Sends to an explicit endpoint. Returns bytes handed to the IP layer. */
int drizzle_udp_send_to(const drizzle_endpoint_t *destination, const uint8_t *data,
                        size_t length);

/* Convenience wrapper against the default route. */
int drizzle_udp_send_v4(const uint8_t address[4], uint16_t port, const uint8_t *data,
                        size_t length);

/* Drains up to one datagram. Returns the byte count, or -1 when nothing is
 * pending. The source endpoint is filled in when non-NULL. */
int drizzle_udp_receive(uint16_t port, uint8_t *buffer, size_t capacity,
                        drizzle_endpoint_t *source);

/* Internal: hands a decoded datagram from the IP layer up to the bound port. */
void drizzle_udp_input(const drizzle_endpoint_t *source,
                       const drizzle_endpoint_t *destination, const uint8_t *payload,
                       size_t length);

/* Internal: drops state for a port the IP layer has decided is unreachable. */
void drizzle_udp_discard(uint16_t port, const drizzle_endpoint_t *source);

uint16_t drizzle_udp_bound_count(void);
void drizzle_udp_reset(void);

#endif
