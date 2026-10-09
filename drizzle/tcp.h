#ifndef DRIZZLE_TCP_H
#define DRIZZLE_TCP_H

#include <drizzle/net.h>
#include <stddef.h>
#include <stdint.h>

/* Opaque connection handle. NULL means "no such socket". */
typedef struct drizzle_socket drizzle_socket_t;

#define DR1ZZLE_TCP_DEFAULT_BACKLOG 2u

/* Listening socket. Backlog is how many completed handshakes may queue. */
drizzle_socket_t *drizzle_tcp_listen(uint16_t port, unsigned backlog);

/* Returns a pending connection, or NULL. */
drizzle_socket_t *drizzle_tcp_accept(drizzle_socket_t *listener);

/* Queues bytes for transmission. Returns bytes accepted, which is less than
 * length only when the transmit buffer is nearly full. */
int drizzle_tcp_send(drizzle_socket_t *socket, const uint8_t *data, size_t length);

/* Copies up to one segment out of the receive buffer. Returns bytes copied, or
 * -1 when nothing is buffered. */
int drizzle_tcp_receive(drizzle_socket_t *socket, uint8_t *buffer, size_t capacity);

/* True once the peer has closed its sending half. */
int drizzle_tcp_eof(drizzle_socket_t *socket);

int drizzle_tcp_close(drizzle_socket_t *socket);

const drizzle_endpoint_t *drizzle_tcp_local(const drizzle_socket_t *socket);
const drizzle_endpoint_t *drizzle_tcp_peer(const drizzle_socket_t *socket);
drizzle_family_t drizzle_tcp_family(const drizzle_socket_t *socket);

/* Bytes currently queued but not yet acknowledged on the wire. */
size_t drizzle_tcp_pending(const drizzle_socket_t *socket);

/* Internal: service retransmission timers and transmit windows. */
void drizzle_tcp_poll(void);

/* Internal: deliver a decoded segment from the IP layer. */
void drizzle_tcp_input(const drizzle_endpoint_t *source, const drizzle_endpoint_t *destination,
                       const uint8_t *payload, size_t length);

/* Internal: drop every connection that matches a now-unreachable peer. */
void drizzle_tcp_discard(const drizzle_endpoint_t *source);

void drizzle_tcp_reset(void);

#endif
