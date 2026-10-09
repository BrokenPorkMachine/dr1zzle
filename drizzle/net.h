#ifndef DRIZZLE_NET_H
#define DRIZZLE_NET_H

#include <stddef.h>
#include <stdint.h>

/* Frame sizing. The stack never fragments and never reassembles, so the
 * largest datagram it will build is a full Ethernet payload. */
#define DR1ZZLE_ETH_MTU 1500u
#define DR1ZZLE_ETH_HEADER 14u
#define DR1ZZLE_IPV4_HEADER 20u
#define DR1ZZLE_UDP_HEADER 8u
#define DR1ZZLE_TCP_HEADER 20u

#define DR1ZZLE_MAC_LEN 6u
#define DR1ZZLE_IP_MAX 16u

typedef enum {
    DR1ZZLE_AF_UNSPEC = 0,
    DR1ZZLE_AF_INET = 4,
    DR1ZZLE_AF_INET6 = 6
} drizzle_family_t;

typedef struct {
    drizzle_family_t family;
    uint8_t address[DR1ZZLE_IP_MAX];
    uint16_t port;
} drizzle_endpoint_t;

/* Internet protocol numbers used by the stack. */
#define DR1ZZLE_IPPROTO_ICMP 1u
#define DR1ZZLE_IPPROTO_TCP 6u
#define DR1ZZLE_IPPROTO_UDP 17u
#define DR1ZZLE_IPPROTO_ICMP6 58u

/* ---- link layer ------------------------------------------------------- */

/* The entire hardware contract for the stack: given a fully formed Ethernet
 * frame, put it on the wire. Anything that can satisfy this -- a QEMU
 * virtio-net transport today, an SDIO WiFi transport tomorrow -- is a valid
 * link. No layer above knows which one it is attached to. */
typedef struct drizzle_link {
    void (*transmit)(const uint8_t *frame, size_t length);
    void (*receive)(void); /* optional: drain the link into the stack */
    const char *name;
} drizzle_link_t;

void drizzle_net_set_link(const drizzle_link_t *link);
const drizzle_link_t *drizzle_net_link(void);
int drizzle_net_link_up(void);
uint64_t drizzle_net_frames_rx(void);
uint64_t drizzle_net_frames_tx(void);
uint64_t drizzle_net_bytes_rx(void);
uint64_t drizzle_net_bytes_tx(void);
uint64_t drizzle_net_drops(void);

/* ---- addressing ------------------------------------------------------- */

void drizzle_net_set_mac(const uint8_t hardware[DR1ZZLE_MAC_LEN]);
const uint8_t *drizzle_net_mac(void);

/* ---- lifecycle -------------------------------------------------------- */

typedef enum {
    DR1ZZLE_NET_DOWN = 0,
    DR1ZZLE_NET_CONFIGURING,
    DR1ZZLE_NET_UP
} drizzle_net_state_t;

void drizzle_net_init(void);

/* Service the whole stack: link drain, protocol timers, TCP retransmission,
 * NAT expiry, DNS retries. Call from the main poll loop. */
void drizzle_net_poll(void);

drizzle_net_state_t drizzle_net_state(void);
void drizzle_net_configure_v4(const uint8_t address[4], const uint8_t netmask[4],
                              const uint8_t gateway[4]);
void drizzle_net_configure_v6(const uint8_t address[16], unsigned prefix_length,
                              const uint8_t gateway[16]);
int drizzle_net_has_v4(void);
int drizzle_net_has_v6(void);
const uint8_t *drizzle_net_v4(void);
const uint8_t *drizzle_net_v6(void);
const uint8_t *drizzle_net_v4_netmask(void);
const uint8_t *drizzle_net_v4_gateway(void);
const uint8_t *drizzle_net_v6_gateway(void);
unsigned drizzle_net_v6_prefix_length(void);

/* Feed one received Ethernet frame into the stack. */
void drizzle_net_receive(const uint8_t *frame, size_t length);
int drizzle_net_send_udp_v4(const uint8_t destination[4], uint16_t source_port,
                            uint16_t destination_port, const uint8_t *payload,
                            size_t length);

/* Endpoint helpers. */
void drizzle_endpoint_v4(drizzle_endpoint_t *endpoint, uint16_t port, const uint8_t address[4]);
void drizzle_endpoint_v6(drizzle_endpoint_t *endpoint, uint16_t port, const uint8_t address[16]);
int drizzle_endpoint_equal(const drizzle_endpoint_t *left, const drizzle_endpoint_t *right);
int drizzle_endpoint_is_unspecified(const drizzle_endpoint_t *endpoint);
int drizzle_endpoint_is_loopback(const drizzle_endpoint_t *endpoint);
int drizzle_endpoint_is_multicast(const drizzle_endpoint_t *endpoint);
int drizzle_endpoint_is_link_local(const drizzle_endpoint_t *endpoint);
/* Renders as text. Returns the number of characters written. */
int drizzle_endpoint_text(const drizzle_endpoint_t *endpoint, char *buffer, size_t capacity);
/* Parses dotted-quad IPv4 text. Returns 1 on success. */
int drizzle_endpoint_parse(const char *text, drizzle_endpoint_t *endpoint);

#endif
