#ifndef NET_H
#define NET_H

#include <stdint.h>

/* Ethernet/IPv4/TCP, sized for a point-to-point link.
 *
 * The link here is USB CDC-ECM: one host, one device, no DHCP server and no
 * router. Both ends default to static addresses (device 192.168.42.1, host
 * 192.168.42.2) because that is what a direct USB-ethernet attachment looks
 * like, and ARP is all the resolution the link needs.
 */

#define NET_MTU 1514

/* Pre-configured device address.
 *
 * This is not a default in the weak sense of "what we use until DHCP
 * answers": there is no DHCP client on this link, and the point of the
 * address being fixed is that the remote side can connect without being
 * told anything. `goat push`, `goat shell` and the ssh/scp invocations in
 * the specification all name 192.168.42.1, and the host tool defaults to
 * it. Change it here and the host tool needs --address; leave it and the
 * two sides agree by construction.
 *
 * Octet order is the wire order the IPv4 header uses, so the constant is
 * written the same way round as the address reads on the wire. */
#define NET_DEFAULT_IPV4    0xC0A82A01u   /* 192.168.42.1 */
#define NET_DEFAULT_NETMASK 0xFFFFFF00u   /* /24 */
#define NET_DEFAULT_GATEWAY 0xC0A82A02u   /* 192.168.42.2 */

/* Installs NET_DEFAULT_IPV4 as the device address. Idempotent, so bring-up
 * can call it without tracking whether it already did; this is what makes
 * the stack answer ARP for our address from the first frame. */
void net_configure_static(void);

typedef struct tcp_socket tcp_socket_t;

/* Install the link senders/consumers. `send_frame` is called with a complete
 * Ethernet frame; `recv_frame` must be fed frames as they arrive off the wire
 * (see cdc_ecm.c). */
void net_send_frame(const uint8_t *frame, uint16_t len);
void net_recv_frame(const uint8_t *frame, uint16_t len);

/* Static interface configuration. Defaults: 192.168.42.1 / 24. */
void net_init(void);
void net_poll(void);
void net_set_address(uint32_t ip, const uint8_t mac[6]);
uint32_t net_ip(void);
const uint8_t *net_mac(void);
void net_configure_static(void);

/* Diagnostics for the shell. */
void net_report(void);

/* --- TCP server side ---------------------------------------------------- */

/* Sockets are created by listening. */
tcp_socket_t *tcp_listen(uint16_t port);
void tcp_close(tcp_socket_t *s);

/* Application hooks. */
void tcp_set_on_data(tcp_socket_t *s,
                     void (*on_data)(tcp_socket_t *s, const uint8_t *data,
                                     uint16_t len));
void tcp_set_on_close(tcp_socket_t *s, void (*on_close)(tcp_socket_t *s));

/* Read received bytes out of the socket (application side). */
uint16_t tcp_recv(tcp_socket_t *s, uint8_t *data, uint16_t max_len);

/* Queue bytes for delivery. Returns the number accepted. */
uint16_t tcp_send(tcp_socket_t *s, const uint8_t *data, uint16_t len);

int tcp_established(tcp_socket_t *s);

#endif /* NET_H */
