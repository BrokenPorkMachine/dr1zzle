#include "tcp.h"
#include "memory_map.h"
#include "timer.h"
#include "util.h"
#include "string.h"

/* Ethernet header */
typedef struct {
    uint8_t dst[6];
    uint8_t src[6];
    uint16_t ethertype;
} __attribute__((packed)) eth_hdr_t;

/* ARP packet */
typedef struct {
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t oper;
    uint8_t sha[6];
    uint8_t spa[4];
    uint8_t tha[6];
    uint8_t tpa[4];
} __attribute__((packed)) arp_pkt_t;

/* IP header */
typedef struct {
    uint8_t ver_ihl;
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t proto;
    uint16_t check;
    uint8_t src[4];
    uint8_t dst[4];
} __attribute__((packed)) ip_hdr_t;

/* TCP header */
typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint16_t off_flags;
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
} __attribute__((packed)) tcp_hdr_t;

/* TCP states */
typedef enum {
    TCP_CLOSED,
    TCP_LISTEN,
    TCP_SYN_SENT,
    TCP_SYN_RCVD,
    TCP_ESTABLISHED,
    TCP_FIN_WAIT1,
    TCP_FIN_WAIT2,
    TCP_CLOSE_WAIT,
    TCP_LAST_ACK,
    TCP_TIME_WAIT,
} tcp_state_t;

/* TCP socket */
typedef struct {
    uint16_t local_port;
    uint16_t remote_port;
    uint32_t remote_ip;
    tcp_state_t state;
    uint32_t local_seq;
    uint32_t remote_seq;
    uint32_t ack_seq;
    uint8_t rx_buf[2048];
    uint16_t rx_len;
    uint8_t tx_buf[2048];
    uint16_t tx_len;
    uint32_t last_ack;
    uint64_t last_send;
    uint8_t retransmit_count;
} tcp_socket_t;

/* TCP stack context */
static struct {
    uint8_t our_mac[6];
    uint8_t our_ip[4];
    tcp_socket_t sockets[4];
    uint32_t next_port;
} tcp_ctx;

/* ARP cache */
static struct {
    uint32_t ip;
    uint8_t mac[6];
    uint32_t expires;
} arp_cache[8];
static int arp_cache_count = 0;

static void handle_arp(const uint8_t *payload, int len);
static void send_arp_reply(const uint8_t *target_mac, uint32_t target_ip);
static void handle_ipv4(const uint8_t *payload, int len);
static void handle_icmp(const uint8_t *src_ip, const uint8_t *payload, int len);
static void send_ip_packet(uint32_t dst_ip, uint8_t proto, const uint8_t *payload, int len);
static void handle_tcp(uint32_t src_ip, const uint8_t *payload, int len);
static void handle_syn(tcp_socket_t *s, uint32_t remote_ip, uint16_t remote_port, uint32_t seq, uint16_t window);
static void handle_ack(tcp_socket_t *s, uint32_t ack);
static void handle_fin(tcp_socket_t *s, uint32_t seq);
static void handle_tcp_data(tcp_socket_t *s, const uint8_t *data, int len);
static void send_tcp_ack(tcp_socket_t *s);
static void send_tcp_packet(tcp_socket_t *s, uint8_t flags, int data_len, uint32_t seq, uint32_t ack, uint16_t window);
void usb_send_frame(const uint8_t *frame, uint16_t len) __attribute__((weak));
void usb_send_frame(const uint8_t *frame, uint16_t len) { (void)frame; (void)len; }

/* Checksum utilities */
static uint16_t ip_checksum(const void *data, int len) {
    uint32_t sum = 0;
    const uint16_t *p = (const uint16_t *)data;
    while (len > 1) {
        sum += *p++;
        len -= 2;
    }
    if (len) sum += *(const uint8_t *)p;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return ~sum;
}

static uint16_t __attribute__((unused)) tcp_checksum(const void *ip_hdr, const void *tcp_hdr, int tcp_len) {
    uint32_t sum = 0;
    
    /* Pseudo-header */
    const uint8_t *ip = (const uint8_t *)ip_hdr;
    sum += (ip[12] << 8) | ip[13];
    sum += (ip[14] << 8) | ip[15];
    sum += (ip[16] << 8) | ip[17];
    sum += (ip[18] << 8) | ip[19];
    sum += 6;  /* TCP protocol */
    sum += tcp_len + 20;  /* TCP length */
    
    /* TCP header + data */
    const uint16_t *p = (const uint16_t *)tcp_hdr;
    int len = tcp_len + 20;
    while (len > 1) {
        sum += *p++;
        len -= 2;
    }
    if (len) sum += *(const uint8_t *)p;
    
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return ~sum;
}

/* ARP cache management */
static void arp_cache_add(uint32_t ip, const uint8_t *mac) {
    for (int i = 0; i < arp_cache_count; i++) {
        if (arp_cache[i].ip == ip) {
            memcpy(arp_cache[i].mac, mac, 6);
            return;
        }
    }
    if (arp_cache_count < 8) {
        arp_cache[arp_cache_count].ip = ip;
        memcpy(arp_cache[arp_cache_count].mac, mac, 6);
        arp_cache_count++;
    }
}

static const uint8_t __attribute__((unused)) *arp_cache_lookup(uint32_t ip) {
    for (int i = 0; i < arp_cache_count; i++) {
        if (arp_cache[i].ip == ip) return arp_cache[i].mac;
    }
    return NULL;
}

/* Ethernet frame processing */
void tcp_stack_process_ethernet(const uint8_t *frame, uint16_t len) {
    if (len < 14) return;
    
    eth_hdr_t *eth = (eth_hdr_t *)frame;
    uint16_t ethertype = (eth->ethertype >> 8) | (eth->ethertype << 8);
    
    if (ethertype == 0x0806) { /* ARP */
        handle_arp(&frame[14], len - 14);
    } else if (ethertype == 0x0800) { /* IPv4 */
        handle_ipv4(&frame[14], len - 14);
    }
}

static void handle_arp(const uint8_t *payload, int len) {
    if (len < (int)sizeof(arp_pkt_t)) return;
    arp_pkt_t *arp = (arp_pkt_t *)payload;
    
    uint16_t oper = (arp->oper >> 8) | (arp->oper << 8);
    uint32_t spa = *(uint32_t *)arp->spa;
    uint32_t tpa = *(uint32_t *)arp->tpa;
    
    arp_cache_add(spa, arp->sha);
    
    if (oper == 1 && tpa == *(uint32_t *)tcp_ctx.our_ip) {
        send_arp_reply(arp->sha, spa);
    }
}

static void send_arp_reply(const uint8_t *target_mac, uint32_t target_ip) {
    uint8_t frame[42];
    eth_hdr_t *eth = (eth_hdr_t *)frame;
    arp_pkt_t *arp = (arp_pkt_t *)&frame[14];
    
    memcpy(eth->dst, target_mac, 6);
    memcpy(eth->src, tcp_ctx.our_mac, 6);
    eth->ethertype = 0x0608; /* ARP */
    
    arp->htype = 0x0100;
    arp->ptype = 0x0008;
    arp->hlen = 6;
    arp->plen = 4;
    arp->oper = 0x0200; /* Reply */
    memcpy(arp->sha, tcp_ctx.our_mac, 6);
    memcpy(arp->spa, tcp_ctx.our_ip, 4);
    memcpy(arp->tha, target_mac, 6);
    *(uint32_t *)arp->tpa = target_ip;
    
    usb_send_frame(frame, sizeof(frame));
}

/* IPv4 processing */
static void handle_ipv4(const uint8_t *payload, int len) {
    if (len < 20) return;
    ip_hdr_t *ip = (ip_hdr_t *)payload;
    
    uint8_t ihl = (ip->ver_ihl & 0xF) * 4;
    if (len < ihl) return;
    
    if (ip_checksum(ip, ihl) != 0) return;
    
    uint32_t dst_ip = *(uint32_t *)ip->dst;
    if (dst_ip != *(uint32_t *)tcp_ctx.our_ip && dst_ip != 0xFFFFFFFF) return;
    
    arp_cache_add(*(uint32_t *)ip->src, 0); /* Will be updated by ARP */
    
    int proto = ip->proto;
    int payload_len = ((ip->tot_len >> 8) | (ip->tot_len << 8)) - ihl;
    
    switch (proto) {
        case 1: handle_icmp(ip->src, &payload[ihl], payload_len); break;
        case 6: handle_tcp(*(uint32_t *)ip->src, &payload[ihl], payload_len); break;
        default: break;
    }
}

static void handle_icmp(const uint8_t *src_ip, const uint8_t *payload, int len) {
    if (len < 8) return;
    if (payload[0] == 8 && payload[1] == 0) { /* Echo request */
        uint8_t reply[64];
        memcpy(reply, payload, len);
        reply[0] = 0; /* Echo reply */
        reply[2] = 0; reply[3] = 0;
        uint16_t csum = ip_checksum(reply, len);
        reply[2] = csum >> 8;
        reply[3] = csum & 0xFF;
        send_ip_packet(*(uint32_t *)src_ip, 1, reply, len);
    }
}

static void send_ip_packet(uint32_t dst_ip, uint8_t proto, const uint8_t *payload, int len) {
    (void)dst_ip;
    (void)proto;
    (void)payload;
    (void)len;
    /* Build and send IP packet */
    /* Simplified - would need full implementation */
}

/* TCP processing */
static void handle_tcp(uint32_t src_ip, const uint8_t *payload, int len) {
    if (len < 20) return;
    tcp_hdr_t *tcp = (tcp_hdr_t *)payload;
    
    uint16_t src_port = (tcp->src_port >> 8) | (tcp->src_port << 8);
    uint32_t seq = (tcp->seq >> 24) | ((tcp->seq >> 8) & 0xFF00) | 
                   ((tcp->seq << 8) & 0xFF0000) | (tcp->seq << 24);
    uint32_t ack = (tcp->ack >> 24) | ((tcp->ack >> 8) & 0xFF00) | 
                   ((tcp->ack << 8) & 0xFF0000) | (tcp->ack << 24);
    uint8_t flags = tcp->off_flags & 0x3F;
    uint16_t window = (tcp->window >> 8) | (tcp->window << 8);
    
    /* Find or create socket */
    int sock_idx = -1;
    for (int i = 0; i < 4; i++) {
        if (tcp_ctx.sockets[i].local_port == ((tcp->dst_port >> 8) | (tcp->dst_port << 8)) &&
            tcp_ctx.sockets[i].remote_ip == src_ip &&
            tcp_ctx.sockets[i].remote_port == src_port) {
            sock_idx = i;
            break;
        }
    }
    
    if (sock_idx == -1) {
        for (int i = 0; i < 4; i++) {
            if (tcp_ctx.sockets[i].state == TCP_LISTEN &&
                tcp_ctx.sockets[i].local_port == ((tcp->dst_port >> 8) | (tcp->dst_port << 8))) {
                sock_idx = i;
                tcp_ctx.sockets[i].remote_ip = src_ip;
                tcp_ctx.sockets[i].remote_port = src_port;
                tcp_ctx.sockets[i].state = TCP_SYN_RCVD;
                break;
            }
        }
    }
    
    if (sock_idx == -1) return;
    
    tcp_socket_t *s = &tcp_ctx.sockets[sock_idx];
    
    if (flags & 0x02) { /* SYN */
        handle_syn(s, src_ip, src_port, seq, window);
    }
    if (flags & 0x10) { /* ACK */
        handle_ack(s, ack);
    }
    if (flags & 0x01) { /* FIN */
        handle_fin(s, seq);
    }
    if (flags & 0x04) { /* RST */
        s->state = TCP_CLOSED;
    }
    
    /* Handle data */
    int data_offset = ((tcp->off_flags >> 12) & 0xF) * 4;
    if (len > data_offset) {
        handle_tcp_data(s, &payload[data_offset], len - data_offset);
    }
}

static void handle_syn(tcp_socket_t *s, uint32_t remote_ip, uint16_t remote_port, uint32_t seq, uint16_t window) {
    (void)window;
    s->remote_ip = remote_ip;
    s->remote_port = remote_port;
    s->remote_seq = seq + 1;
    s->local_seq = 0x12345678;
    s->state = TCP_SYN_RCVD;
    
    send_tcp_packet(s, 0x12, 0, s->local_seq, s->remote_seq, 4096); /* SYN+ACK */
}

static void handle_ack(tcp_socket_t *s, uint32_t ack) {
    if (ack == s->local_seq + 1 && s->state == TCP_SYN_RCVD) {
        s->state = TCP_ESTABLISHED;
        s->local_seq++;
    } else if (ack > s->last_ack) {
        s->last_ack = ack;
        s->retransmit_count = 0;
    }
}

static void handle_fin(tcp_socket_t *s, uint32_t seq) {
    s->remote_seq = seq + 1;
    if (s->state == TCP_ESTABLISHED) {
        s->state = TCP_CLOSE_WAIT;
        send_tcp_packet(s, 0x10, 0, s->local_seq, s->remote_seq, 4096);
    }
}

static void handle_tcp_data(tcp_socket_t *s, const uint8_t *data, int len) {
    int space = sizeof(s->rx_buf) - s->rx_len;
    int copy_len = len < space ? len : space;
    memcpy(s->rx_buf + s->rx_len, data, copy_len);
    s->rx_len += copy_len;
    
    s->remote_seq += copy_len;
    send_tcp_ack(s);
}

static void send_tcp_ack(tcp_socket_t *s) {
    send_tcp_packet(s, 0x10, 0, s->local_seq, s->remote_seq, 4096);
}

static void send_tcp_packet(tcp_socket_t *s, uint8_t flags, int data_len, uint32_t seq, uint32_t ack, uint16_t window) {
    (void)s;
    (void)flags;
    (void)data_len;
    (void)seq;
    (void)ack;
    (void)window;
    /* Build and send TCP packet */
    /* Simplified - would need full implementation */
}

static void tcp_stack_process_timers(void) {
    uint64_t now = timer_now_ms();
    for (int i = 0; i < 4; i++) {
        tcp_socket_t *s = &tcp_ctx.sockets[i];
        switch (s->state) {
            case TCP_SYN_SENT:
            case TCP_SYN_RCVD:
                if (now > s->last_send + 1000 * (1 << s->retransmit_count)) {
                    if (s->retransmit_count < 5) {
                        s->retransmit_count++;
                        s->last_send = now;
                    } else {
                        s->state = TCP_CLOSED;
                    }
                }
                break;
            case TCP_ESTABLISHED:
                if (now > s->last_send + 30000) {
                    /* Keepalive */
                }
                break;
            default: break;
        }
    }
}

void tcp_stack_init(void) {
    tcp_ctx.our_ip[0] = 192; tcp_ctx.our_ip[1] = 168; tcp_ctx.our_ip[2] = 42; tcp_ctx.our_ip[3] = 1;
    tcp_ctx.our_mac[0] = 0x02; tcp_ctx.our_mac[1] = 0x00; tcp_ctx.our_mac[2] = 0x00;
    tcp_ctx.our_mac[3] = 0x00; tcp_ctx.our_mac[4] = 0x00; tcp_ctx.our_mac[5] = 0x01;
    tcp_ctx.next_port = 1024;
    
    /* Listen on port 23 (telnet) */
    tcp_ctx.sockets[0].local_port = 23;
    tcp_ctx.sockets[0].state = TCP_LISTEN;
    tcp_ctx.sockets[0].local_seq = 0x12345678;
}

void tcp_stack_poll(void) {
    tcp_stack_process_timers();
}

