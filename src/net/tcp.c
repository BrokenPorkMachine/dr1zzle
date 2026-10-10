/* Ethernet + ARP + ICMP + IPv4 + TCP, device side.
 *
 * ---------------------------------------------------------------------------
 * Why this is not the other net/ file
 * ---------------------------------------------------------------------------
 *
 * The previous net/tcp.c parsed frames and then threw the results away: every
 * transmit helper was a stub, so nothing ever left the device. This is the
 * replacement, one path that owns both directions, built for the link this
 * payload actually has (a single host over CDC-ECM):
 *
 *   RX: usb_cdc_rx() -> net_recv_frame() -> ARP / ICMP / TCP dispatch
 *   TX: tcp_send()  -> TCP segment -> IPv4 -> ARP lookup -> usb_send_frame()
 *
 * Retransmission is deliberately simple: one unacked window per socket,
 * resent on the timer until acknowledged. Enough for an interactive shell or
 * a container push over a wired link, and correct rather than fast -- a host
 * that drops packets makes us look slow, not wrong.
 *
 * Sequence numbers use a fixed initial value rather than a random one. There
 * is no off-path adversary on a point-to-point link, so guessing resistance
 * buys nothing here and costs a source of entropy we do not have.
 */

#include "net.h"
#include "usb.h"
#include "console.h"
#include "string.h"
#include "timer.h"
#include "util.h"

#define MAX_PACKET 512
#define TX_BUF 2048
#define RX_BUF 2048
#define MAX_SOCKETS 4
#define INITIAL_SEQ 0x1000

/* --- interface config ---------------------------------------------------- */

static uint8_t if_mac[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
static uint8_t if_ip[4]  = { 192, 168, 123, 10 };
static uint8_t if_gateway[4] = { 192, 168, 123, 1 };

/* --- byte order and checksum -------------------------------------------- */

static uint16_t rd16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static uint32_t rd32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}
static void wr16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static void wr32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v;
}

static uint16_t checksum(const void *data, int len) {
    const uint8_t *p = (const uint8_t *)data;
    uint32_t sum = 0;
    for (int i = 0; i + 1 < len; i += 2) {
        sum += (uint32_t)((p[i] << 8) | p[i + 1]);
    }
    if (len & 1) sum += (uint32_t)(p[len - 1] << 8);
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)(~sum & 0xFFFF);
}

/* --- ARP cache ----------------------------------------------------------- */

static struct {
    uint32_t ip;
    uint8_t mac[6];
    uint64_t expires_ms;
} arp_cache[4];

static void arp_cache_add(uint32_t ip, const uint8_t *mac) {
    for (int i = 0; i < 4; i++) {
        if (arp_cache[i].ip == ip) {
            for (int j = 0; j < 6; j++) arp_cache[i].mac[j] = mac[j];
            arp_cache[i].expires_ms = timer_now_ms() + 60000;
            return;
        }
    }
    for (int i = 0; i < 4; i++) {
        if (arp_cache[i].ip == 0) {
            arp_cache[i].ip = ip;
            for (int j = 0; j < 6; j++) arp_cache[i].mac[j] = mac[j];
            arp_cache[i].expires_ms = timer_now_ms() + 60000;
            return;
        }
    }
}

static const uint8_t *arp_cache_lookup(uint32_t ip) {
    uint64_t now = timer_now_ms();
    for (int i = 0; i < 4; i++) {
        if (arp_cache[i].ip == ip && arp_cache[i].expires_ms > now) {
            return arp_cache[i].mac;
        }
    }
    return 0;
}

/* --- sockets ------------------------------------------------------------- */

struct tcp_socket {
    uint16_t local_port;
    uint16_t remote_port;
    uint32_t remote_ip;
    int state;
    uint32_t snd_una;      /* oldest unacknowledged byte */
    uint32_t snd_nxt;      /* next byte to send           */
    uint32_t rcv_nxt;      /* next byte the peer sends    */
    uint8_t tx_buf[TX_BUF];
    uint16_t tx_len;       /* queued, including unacked   */
    uint16_t unacked;      /* bytes already on the wire   */
    uint64_t last_send_ms;
    int retries;
    uint8_t rx_buf[RX_BUF];
    uint16_t rx_len;
    void (*on_data)(tcp_socket_t *s, const uint8_t *data, uint16_t len);
    void (*on_close)(tcp_socket_t *s);
    int active;
};

enum {
    T_CLOSED = 0, T_LISTEN, T_SYN_RCVD, T_ESTABLISHED, T_CLOSE_WAIT, T_LAST_ACK
};

static tcp_socket_t sockets[MAX_SOCKETS];

static const uint8_t ETH_BROADCAST[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

/* Forward declarations: TX and RX call each other. */
static void arp_send(uint16_t opcode, const uint8_t target_ip[4],
                     const uint8_t target_mac[6]);

/* --- frame transmit ------------------------------------------------------ */

static uint16_t ip_id;

/* Build an IPv4 header into out[0..20). Returns 0 on success. */
static int build_ipv4_header(uint8_t *out, uint8_t proto,
                             const uint8_t dst_ip[4], uint16_t payload_len) {
    out[0] = 0x45;      /* version 4, 5 words of header */
    out[1] = 0;
    wr16(out + 2, (uint16_t)(payload_len + 20));
    wr16(out + 4, ++ip_id);
    wr16(out + 6, 0x4000);        /* don't fragment */
    out[8] = 64;                  /* ttl */
    out[9] = proto;
    wr16(out + 10, 0);
    memcpy(out + 12, if_ip, 4);
    memcpy(out + 16, dst_ip, 4);
    wr16(out + 10, checksum(out, 20));
    return 0;
}

/* Send one IPv4 datagram. Resolves the next hop by ARP first; on a miss it
 * asks and lets the retry happen on the next poll, rather than sending into
 * the void. */
static void ip_send(const uint8_t dst_ip[4], uint8_t proto,
                    const uint8_t *payload, uint16_t len) {
    if (len + 20 + 14 > NET_MTU) return;

    static uint8_t frame[NET_MTU];
    uint32_t dst = rd32(dst_ip);
    
    /* Determine if destination is on local subnet (192.168.123.0/24) */
    uint32_t netmask = 0xFFFFFF00;
    uint32_t local_net = rd32(if_ip) & netmask;
    uint32_t dst_net = dst & netmask;
    
    /* If not on local subnet, route through gateway */
    uint32_t next_hop_ip;
    if (dst_net != local_net) {
        next_hop_ip = rd32(if_gateway);
    } else {
        next_hop_ip = dst;
    }
    
    const uint8_t *mac = arp_cache_lookup(next_hop_ip);

    if (!mac) {
        uint8_t next_hop_bytes[4];
        wr32(next_hop_bytes, next_hop_ip);
        arp_send(1, next_hop_bytes, if_mac);
        return;
    }

    memcpy(frame, mac, 6);
    memcpy(frame + 6, if_mac, 6);
    wr16(frame + 12, 0x0800);

    uint16_t ip_len = (uint16_t)(len + 20);
    build_ipv4_header(frame + 14, proto, dst_ip, len);
    for (uint16_t i = 0; i < len; i++) frame[14 + 20 + i] = payload[i];

    /* Ethernet minimum frame size: pad short datagrams. */
    if (ip_len < 46) {
        for (int i = ip_len; i < 46; i++) frame[14 + i] = 0;
        ip_len = 46;
    }
    net_send_frame(frame, (uint16_t)(14 + ip_len));
}

static void arp_send(uint16_t opcode, const uint8_t target_ip[4],
                     const uint8_t target_mac[6]) {
    static uint8_t arp[28];

    wr16(arp + 0, 0x0001);      /* hardware: ethernet */
    wr16(arp + 2, 0x0800);      /* protocol: IPv4 */
    arp[4] = 6;
    arp[5] = 4;
    wr16(arp + 6, opcode);
    memcpy(arp + 8, if_mac, 6);
    memcpy(arp + 14, if_ip, 4);
    memcpy(arp + 18, target_mac, 6);
    memcpy(arp + 24, target_ip, 4);

    static uint8_t frame[64];
    memcpy(frame, opcode == 1 ? ETH_BROADCAST : target_mac, 6);
    memcpy(frame + 6, if_mac, 6);
    wr16(frame + 12, 0x0806);
    for (int i = 0; i < 28; i++) frame[14 + i] = arp[i];
    net_send_frame(frame, 60);
}

/* --- TCP segment transmit ------------------------------------------------ */

static void tcp_send_segment(tcp_socket_t *s, uint8_t flags,
                             const uint8_t *data, uint16_t len) {
    static uint8_t seg[MAX_PACKET];

    if (len > MAX_PACKET - 20) len = (uint16_t)(MAX_PACKET - 20);

    wr16(seg + 0, s->local_port);
    wr16(seg + 2, s->remote_port);
    wr32(seg + 4, s->snd_nxt);
    wr32(seg + 8, s->rcv_nxt);
    seg[12] = 0x50;                 /* 5 words, no options */
    seg[13] = flags;
    wr16(seg + 14, RX_BUF);         /* advertised window */
    wr16(seg + 16, 0);
    wr16(seg + 18, 0);

    uint8_t dst_ip[4];
    wr32(dst_ip, s->remote_ip);

    /* Checksum over the pseudo header, which shares no layout with the
     * segment itself, so it is summed separately. */
    uint32_t sum = 0;
    for (int i = 0; i < 4; i += 2) {
        sum += (uint32_t)((if_ip[i] << 8) | if_ip[i + 1]);
        sum += (uint32_t)((dst_ip[i] << 8) | dst_ip[i + 1]);
    }
    sum += 6;
    sum += (uint32_t)(20 + len);
    for (int i = 0; i + 1 < 20 + len; i += 2) {
        sum += (uint32_t)((seg[i] << 8) | seg[i + 1]);
    }
    if ((20 + len) & 1) sum += (uint32_t)(seg[20 + len - 1] << 8);
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    wr16(seg + 16, (uint16_t)(~sum & 0xFFFF));

    for (uint16_t i = 0; i < len; i++) seg[20 + i] = data[i];

    ip_send(dst_ip, 6, seg, (uint16_t)(20 + len));
}

/* Push queued data out, one window at a time. Nothing new goes out while a
 * window is unacknowledged, which is why this is stop-and-wait and not a
 * sliding window. */
static void tcp_flush(tcp_socket_t *s) {
    if (s->state != T_ESTABLISHED) return;
    if (s->unacked > 0) return;
    if (s->tx_len == 0) return;

    uint16_t send = s->tx_len;
    if (send > MAX_PACKET - 20) send = (uint16_t)(MAX_PACKET - 20);

    tcp_send_segment(s, 0x18, s->tx_buf, send);
    s->unacked = send;
    s->snd_nxt += send;
    s->last_send_ms = timer_now_ms();
    s->retries = 0;
}

static void tcp_retransmit(tcp_socket_t *s) {
    if (s->unacked == 0) return;

    tcp_send_segment(s, 0x18, s->tx_buf, s->unacked);
    s->snd_nxt = s->snd_una + s->unacked;
    s->last_send_ms = timer_now_ms();

    if (++s->retries > 8) {
        if (s->on_close) s->on_close(s);
        s->active = 0;
        s->state = T_CLOSED;
    }
}

/* --- socket table -------------------------------------------------------- */

static tcp_socket_t *socket_alloc(void) {
    for (int i = 0; i < MAX_SOCKETS; i++) {
        tcp_socket_t *s = &sockets[i];
        if (!s->active) {
            memset(s, 0, sizeof(*s));
            s->active = 1;
            s->snd_una = INITIAL_SEQ;
            s->snd_nxt = INITIAL_SEQ;
            return s;
        }
    }
    return 0;
}

static tcp_socket_t *socket_find(uint16_t local_port, uint32_t remote_ip,
                                 uint16_t remote_port) {
    for (int i = 0; i < MAX_SOCKETS; i++) {
        tcp_socket_t *s = &sockets[i];
        if (s->active && s->local_port == local_port &&
            s->remote_ip == remote_ip && s->remote_port == remote_port) {
            return s;
        }
    }
    return 0;
}

/* --- receive path -------------------------------------------------------- */

static void handle_arp(const uint8_t *p, uint16_t len) {
    if (len < 28) return;

    uint16_t opcode = rd16(p + 6);
    const uint8_t *sender_mac = p + 8;
    const uint8_t *sender_ip = p + 14;
    const uint8_t *target_ip = p + 24;

    if (rd32(target_ip) != rd32(if_ip)) return;

    /* Learn the sender both ways: a request names the host and a reply
     * confirms it, and we need its MAC to send anything back. */
    arp_cache_add(rd32(sender_ip), sender_mac);

    if (opcode == 1) {
        arp_send(2, sender_ip, sender_mac);
    }
}

static void handle_icmp(const uint8_t dst_ip[4], const uint8_t *p, uint16_t len) {
    if (len < 8 || p[0] != 8) return;      /* only echo requests */

    static uint8_t reply[MAX_PACKET];
    uint16_t copy = (uint16_t)(len < sizeof(reply) ? len : sizeof(reply));

    for (uint16_t i = 0; i < copy; i++) reply[i] = p[i];
    reply[0] = 0;                          /* echo reply */
    reply[1] = 0;
    wr16(reply + 2, 0);
    for (uint16_t i = 4; i < 8 && i < copy; i++) reply[i] = p[i];
    wr16(reply + 2, checksum(reply, copy));

    ip_send(dst_ip, 1, reply, copy);
}

static void handle_tcp_segment(uint32_t src_ip, const uint8_t *p, uint16_t len) {
    if (len < 20) return;

    uint16_t src_port = rd16(p);
    uint16_t dst_port = rd16(p + 2);
    uint32_t seq = rd32(p + 4);
    uint32_t ack = rd32(p + 8);
    uint8_t flags = p[13];
    int hdr_len = (p[12] >> 4) * 4;
    if (hdr_len < 20 || hdr_len > len) return;

    tcp_socket_t *s = socket_find(dst_port, src_ip, src_port);

    if (!s) {
        /* Only a listening socket can adopt an unknown peer. */
        for (int i = 0; i < MAX_SOCKETS; i++) {
            tcp_socket_t *l = &sockets[i];
            if (l->active && l->state == T_LISTEN && l->local_port == dst_port) {
                s = l;
                s->remote_ip = src_ip;
                s->remote_port = src_port;
                s->state = T_SYN_RCVD;
                s->rcv_nxt = seq + 1;
                s->snd_nxt = INITIAL_SEQ;
                tcp_send_segment(s, 0x12, 0, 0);      /* SYN + ACK */
                s->snd_nxt = INITIAL_SEQ + 1;         /* the SYN counts */
                return;
            }
        }
        return;
    }

    if (flags & 0x04) {    /* RST */
        s->active = 0;
        s->state = T_CLOSED;
        if (s->on_close) s->on_close(s);
        return;
    }

    if (flags & 0x02) {    /* SYN on a live socket: re-send SYN + ACK */
        s->rcv_nxt = seq + 1;
        s->snd_nxt = INITIAL_SEQ;
        tcp_send_segment(s, 0x12, 0, 0);
        s->snd_nxt = INITIAL_SEQ + 1;
        return;
    }

    if (flags & 0x01) {    /* FIN */
        s->rcv_nxt = seq + 1;
        if (s->state == T_ESTABLISHED) {
            tcp_send_segment(s, 0x10, 0, 0);
            s->state = T_CLOSE_WAIT;
        }
        if (s->on_close) s->on_close(s);
        return;
    }

    if (flags & 0x10) {    /* ACK */
        if (s->state == T_SYN_RCVD && ack == s->snd_nxt) {
            s->state = T_ESTABLISHED;
            s->snd_una = ack;
            s->unacked = 0;
            s->tx_len = 0;
        } else if (s->state == T_ESTABLISHED && ack > s->snd_una) {
            uint32_t acked = ack - s->snd_una;
            if (acked <= s->unacked) {
                for (uint32_t i = 0; i + acked < s->tx_len; i++) {
                    s->tx_buf[i] = s->tx_buf[i + acked];
                }
                s->tx_len = (uint16_t)(s->tx_len - acked);
                s->unacked = (uint16_t)(s->unacked - acked);
                s->snd_una = ack;
                s->retries = 0;
                s->last_send_ms = timer_now_ms();
            }
        }
    }

    /* Delivered payload. */
    if (len > (uint16_t)hdr_len && s->state == T_ESTABLISHED) {
        const uint8_t *data = p + hdr_len;
        uint16_t data_len = (uint16_t)(len - hdr_len);
        uint16_t room = (uint16_t)(RX_BUF - s->rx_len);
        uint16_t take = data_len < room ? data_len : room;

        if (take) {
            uint8_t *at = s->rx_buf + s->rx_len;
            for (uint16_t i = 0; i < take; i++) at[i] = data[i];
            s->rx_len = (uint16_t)(s->rx_len + take);
            s->rcv_nxt += take;
            tcp_send_segment(s, 0x10, 0, 0);

            if (s->on_data) s->on_data(s, at, take);

            for (int i = 0; i + take < s->rx_len; i++) {
                s->rx_buf[i] = s->rx_buf[i + take];
            }
            s->rx_len = (uint16_t)(s->rx_len - take);
        }
    }
}

static void handle_ipv4(const uint8_t *p, uint16_t len) {
    if (len < 20) return;
    if ((p[0] >> 4) != 4) return;
    if (checksum(p, 20) != 0) return;
    if (rd32(p + 12) != rd32(if_ip)) return;

    uint16_t total = rd16(p + 2);
    if (total > len) return;

    uint8_t proto = p[9];
    uint16_t payload_len = (uint16_t)(total - 20);

    if (proto == 1) {
        handle_icmp(p + 16, p + 20, payload_len);
    } else if (proto == 6) {
        handle_tcp_segment(rd32(p + 16), p + 20, payload_len);
    }
}

/* --- public API ---------------------------------------------------------- */

/* Every byte this stack transmits -- the SYN-ACK that starts a session, the
 * ARP reply, the reply to a goatloader request -- leaves through
 * usb_cdc_tx_queue(). The queue is what makes the transmit path safe from the
 * places this stack is driven: it never waits for the bulk-IN endpoint, so a
 * send cannot wedge on a completion, and the interrupt path only ever
 * appends frames to it. usb_cdc_tx_pending() puts them on the wire, called
 * from net_poll() below. */
void net_send_frame(const uint8_t *frame, uint16_t len) {
    if (!frame || len < 14u) return;
    usb_cdc_tx_queue(frame, len);
}

void net_recv_frame(const uint8_t *frame, uint16_t len) {
    if (len < 14) return;

    /* Learn the peer's MAC from any frame it sent us. Without this, replying
     * to a TCP SYN needs an ARP round trip first, and the client's retry is
     * a second later: the connection would still work, just not promptly. */
    if (rd16(frame + 12) == 0x0800 && len >= 34) {
        arp_cache_add(rd32(frame + 26), frame + 6);
    }

    uint16_t ethertype = rd16(frame + 12);

    if (ethertype == 0x0806) {
        handle_arp(frame + 14, (uint16_t)(len - 14));
    } else if (ethertype == 0x0800) {
        handle_ipv4(frame + 14, (uint16_t)(len - 14));
    }
}

/* Delivers one buffered CDC-ECM frame to the stack, and services the socket
 * timers. This is the whole poll surface: the interrupt path buffers frames
 * (cdc_ecm.c) and this is where they become network events, so the stack's
 * static segment buffers stay single-owner. */
void net_poll(void) {
    usb_cdc_service();
    for (int i = 0; i < MAX_SOCKETS; i++) {
        tcp_socket_t *s = &sockets[i];
        if (!s->active) continue;

        if (s->state == T_LAST_ACK) {
            if (timer_now_ms() - s->last_send_ms > 1000) {
                s->active = 0;
                s->state = T_CLOSED;
            }
            continue;
        }

        if (s->state == T_ESTABLISHED) {
            tcp_flush(s);
            if (s->unacked && timer_now_ms() - s->last_send_ms > 500) {
                tcp_retransmit(s);
            }
        }
    }
    /* Anything a socket produced this pass is now in the transmit queue. */
    usb_cdc_tx_pending();
}

tcp_socket_t *tcp_listen(uint16_t port) {
    for (int i = 0; i < MAX_SOCKETS; i++) {
        if (sockets[i].active && sockets[i].state == T_LISTEN &&
            sockets[i].local_port == port) {
            return &sockets[i];
        }
    }
    tcp_socket_t *s = socket_alloc();
    if (!s) return 0;
    s->state = T_LISTEN;
    s->local_port = port;
    return s;
}

uint16_t tcp_recv(tcp_socket_t *s, uint8_t *data, uint16_t max_len) {
    if (!s || !s->active) return 0;
    uint16_t take = s->rx_len < max_len ? s->rx_len : max_len;
    for (uint16_t i = 0; i < take; i++) data[i] = s->rx_buf[i];
    for (int i = 0; i + take < s->rx_len; i++) {
        s->rx_buf[i] = s->rx_buf[i + take];
    }
    s->rx_len = (uint16_t)(s->rx_len - take);
    return take;
}

uint16_t tcp_send(tcp_socket_t *s, const uint8_t *data, uint16_t len) {
    if (!s || !s->active || len == 0) return 0;
    uint16_t room = (uint16_t)(TX_BUF - s->tx_len);
    uint16_t take = len < room ? len : room;
    for (uint16_t i = 0; i < take; i++) s->tx_buf[s->tx_len + i] = data[i];
    s->tx_len = (uint16_t)(s->tx_len + take);
    tcp_flush(s);
    return take;
}

int tcp_established(tcp_socket_t *s) {
    return s && s->active && s->state == T_ESTABLISHED;
}

void tcp_close(tcp_socket_t *s) {
    if (!s || !s->active) return;

    if (s->state == T_ESTABLISHED || s->state == T_CLOSE_WAIT) {
        tcp_send_segment(s, 0x11, 0, 0);      /* FIN + ACK */
        s->state = T_LAST_ACK;
        s->last_send_ms = timer_now_ms();
    } else {
        s->active = 0;
        s->state = T_CLOSED;
    }
}

void tcp_set_on_data(tcp_socket_t *s,
                     void (*on_data)(tcp_socket_t *, const uint8_t *, uint16_t)) {
    if (s && s->active) s->on_data = on_data;
}

void tcp_set_on_close(tcp_socket_t *s, void (*on_close)(tcp_socket_t *)) {
    if (s && s->active) s->on_close = on_close;
}

void net_set_address(uint32_t ip, const uint8_t mac[6]) {
    wr32(if_ip, ip);
    for (int i = 0; i < 6; i++) if_mac[i] = mac[i];
}

/* The pre-configured address. Kept as a function rather than a bare initial
 * on if_ip so that bring-up has one place to call, and so the value in the
 * header is the only one that has to agree with the host tool. */
void net_configure_static(void) {
    wr32(if_ip, NET_DEFAULT_IPV4);
    /* Configure the gateway for TCP/IP over USB - the connected host acts as gateway */
    static uint8_t gateway[4];
    gateway[0] = (NET_DEFAULT_GATEWAY >> 24) & 0xFF;
    gateway[1] = (NET_DEFAULT_GATEWAY >> 16) & 0xFF;
    gateway[2] = (NET_DEFAULT_GATEWAY >> 8) & 0xFF;
    gateway[3] = NET_DEFAULT_GATEWAY & 0xFF;
    /* Store gateway for routing decisions */
    extern uint8_t if_gateway[4];
    for (int i = 0; i < 4; i++) if_gateway[i] = gateway[i];
}

uint32_t net_ip(void) { return rd32(if_ip); }

const uint8_t *net_mac(void) { return if_mac; }

void net_report(void) {
    console_puts("net: link ");
    console_puts(usb_configured() ? "up" : "down");
    console_puts(" ip=");
    console_put_uint(if_ip[0]);
    console_putc('.');
    console_put_uint(if_ip[1]);
    console_putc('.');
    console_put_uint(if_ip[2]);
    console_putc('.');
    console_put_uint(if_ip[3]);
    console_puts(" netmask=");
    {
        uint32_t mask = NET_DEFAULT_NETMASK;
        console_put_uint((mask >> 24) & 0xffu); console_putc('.');
        console_put_uint((mask >> 16) & 0xffu); console_putc('.');
        console_put_uint((mask >> 8) & 0xffu);  console_putc('.');
        console_put_uint(mask & 0xffu);
    }
    console_puts(" gateway=");
    console_put_uint(if_gateway[0]);
    console_putc('.');
    console_put_uint(if_gateway[1]);
    console_putc('.');
    console_put_uint(if_gateway[2]);
    console_putc('.');
    console_put_uint(if_gateway[3]);
    console_puts(" mac=");
    for (int i = 0; i < 6; i++) {
        console_putc("0123456789abcdef"[if_mac[i] >> 4]);
        console_putc("0123456789abcdef"[if_mac[i] & 0xF]);
        if (i < 5) console_putc(':');
    }
    /* The goatloader is the only TCP service in this build, and it is bound
     * at bring-up, so "static" here means "configured, not negotiated": there
     * is no DHCP on the link to answer. */
    console_puts(" goatloader:1234 always-on\n");
}
