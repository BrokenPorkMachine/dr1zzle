#include <drizzle/tcp.h>

struct drizzle_socket { int unused; };

drizzle_socket_t *drizzle_tcp_listen(uint16_t port, unsigned backlog) { (void)port; (void)backlog; return 0; }
drizzle_socket_t *drizzle_tcp_accept(drizzle_socket_t *listener) { (void)listener; return 0; }
int drizzle_tcp_send(drizzle_socket_t *socket, const uint8_t *data, size_t length) { (void)socket; (void)data; (void)length; return -1; }
int drizzle_tcp_receive(drizzle_socket_t *socket, uint8_t *buffer, size_t capacity) { (void)socket; (void)buffer; (void)capacity; return -1; }
int drizzle_tcp_eof(drizzle_socket_t *socket) { (void)socket; return 1; }
int drizzle_tcp_close(drizzle_socket_t *socket) { (void)socket; return -1; }
const drizzle_endpoint_t *drizzle_tcp_local(const drizzle_socket_t *socket) { (void)socket; return 0; }
const drizzle_endpoint_t *drizzle_tcp_peer(const drizzle_socket_t *socket) { (void)socket; return 0; }
drizzle_family_t drizzle_tcp_family(const drizzle_socket_t *socket) { (void)socket; return DR1ZZLE_AF_UNSPEC; }
size_t drizzle_tcp_pending(const drizzle_socket_t *socket) { (void)socket; return 0u; }
void drizzle_tcp_poll(void) {}
void drizzle_tcp_input(const drizzle_endpoint_t *source, const drizzle_endpoint_t *destination, const uint8_t *payload, size_t length) { (void)source; (void)destination; (void)payload; (void)length; }
void drizzle_tcp_discard(const drizzle_endpoint_t *source) { (void)source; }
void drizzle_tcp_reset(void) {}
