#include <drizzle/net.h>
#include <drizzle/tcp.h>
#include <drizzle/udp.h>
#include <string.h>

enum { ETH_ARP = 0x0806u, ETH_IPV4 = 0x0800u };
enum { ARP_REQUEST = 1u, ARP_REPLY = 2u };
enum { IPV4_MIN = 20u, ICMP_ECHO_REQUEST = 8u, ICMP_ECHO_REPLY = 0u };

static const drizzle_link_t *active_link;
static drizzle_net_state_t state;
static uint8_t mac[DR1ZZLE_MAC_LEN];
static uint8_t v4[4], v4_mask[4], v4_gateway[4];
static uint8_t v6[16], v6_gateway[16];
static unsigned v6_prefix;
static int have_v4, have_v6;
static uint64_t frames_rx, frames_tx, bytes_rx, bytes_tx, drops;
static uint8_t arp_ip[4], arp_mac[DR1ZZLE_MAC_LEN];
static int have_arp;

static uint16_t load16(const uint8_t *p) { return (uint16_t)(((uint16_t)p[0] << 8) | p[1]); }
static void store16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static int is_broadcast(const uint8_t *m) { for (size_t i = 0; i < DR1ZZLE_MAC_LEN; i++) if (m[i] != 0xffu) return 0; return 1; }
static int same4(const uint8_t *a, const uint8_t *b) { return memcmp(a, b, 4u) == 0; }

static uint16_t checksum(const uint8_t *data, size_t length, uint32_t sum) {
    while (length > 1u) { sum += load16(data); data += 2; length -= 2u; }
    if (length) sum += (uint16_t)((uint16_t)data[0] << 8);
    while (sum >> 16) sum = (sum & 0xffffu) + (sum >> 16);
    return (uint16_t)~sum;
}

static void transmit(const uint8_t *frame, size_t length) {
    if (!active_link || !active_link->transmit) { drops++; return; }
    active_link->transmit(frame, length);
    frames_tx++;
    bytes_tx += length;
}

static void remember_arp(const uint8_t ip[4], const uint8_t hardware[DR1ZZLE_MAC_LEN]) {
    memcpy(arp_ip, ip, 4u);
    memcpy(arp_mac, hardware, DR1ZZLE_MAC_LEN);
    have_arp = 1;
}

static void send_arp_reply(const uint8_t *request) {
    uint8_t frame[42];
    memcpy(frame, request + 22u, DR1ZZLE_MAC_LEN);
    memcpy(frame + 6u, mac, DR1ZZLE_MAC_LEN);
    store16(frame + 12u, ETH_ARP);
    store16(frame + 14u, 1u);
    store16(frame + 16u, ETH_IPV4);
    frame[18] = DR1ZZLE_MAC_LEN; frame[19] = 4u;
    store16(frame + 20u, ARP_REPLY);
    memcpy(frame + 22u, mac, DR1ZZLE_MAC_LEN);
    memcpy(frame + 28u, v4, 4u);
    memcpy(frame + 32u, request + 22u, DR1ZZLE_MAC_LEN);
    memcpy(frame + 38u, request + 28u, 4u);
    transmit(frame, sizeof frame);
}

static void handle_arp(const uint8_t *frame, size_t length) {
    if (length < 42u || load16(frame + 14u) != 1u || load16(frame + 16u) != ETH_IPV4 || frame[18] != DR1ZZLE_MAC_LEN || frame[19] != 4u) { drops++; return; }
    remember_arp(frame + 28u, frame + 22u);
    if (load16(frame + 20u) == ARP_REQUEST && have_v4 && same4(frame + 38u, v4)) send_arp_reply(frame);
}

static void send_icmp_echo_reply(const uint8_t *frame, size_t length, size_t ihl, uint16_t total) {
    uint8_t reply[DR1ZZLE_ETH_HEADER + DR1ZZLE_ETH_MTU];
    if ((size_t)total > DR1ZZLE_ETH_MTU || length < DR1ZZLE_ETH_HEADER + (size_t)total) { drops++; return; }
    memcpy(reply, frame + 6u, DR1ZZLE_MAC_LEN);
    memcpy(reply + 6u, mac, DR1ZZLE_MAC_LEN);
    store16(reply + 12u, ETH_IPV4);
    memcpy(reply + 14u, frame + 14u, total);
    memcpy(reply + 26u, frame + 30u, 4u);
    memcpy(reply + 30u, v4, 4u);
    reply[22] = 64u;
    reply[14u + ihl] = ICMP_ECHO_REPLY;
    reply[14u + ihl + 2u] = 0u;
    reply[14u + ihl + 3u] = 0u;
    store16(reply + 24u, 0u);
    store16(reply + 24u, checksum(reply + 14u, ihl, 0u));
    store16(reply + 14u + ihl + 2u, checksum(reply + 14u + ihl, (size_t)total - ihl, 0u));
    transmit(reply, DR1ZZLE_ETH_HEADER + (size_t)total);
}

static void handle_ipv4(const uint8_t *frame, size_t length) {
    if (length < 34u || (frame[14] >> 4) != 4u) { drops++; return; }
    size_t ihl = (size_t)(frame[14] & 0x0fu) * 4u;
    uint16_t total = load16(frame + 16u);
    if (ihl < IPV4_MIN || total < ihl || length < DR1ZZLE_ETH_HEADER + (size_t)total) { drops++; return; }
    if (checksum(frame + 14u, ihl, 0u) != 0u) { drops++; return; }
    if (!have_v4 || !same4(frame + 30u, v4)) return;
    remember_arp(frame + 26u, frame + 6u);
    drizzle_endpoint_t source, destination;
    drizzle_endpoint_v4(&source, 0u, frame + 26u);
    drizzle_endpoint_v4(&destination, 0u, frame + 30u);
    const uint8_t *payload = frame + 14u + ihl;
    size_t payload_length = (size_t)total - ihl;
    if (frame[23] == DR1ZZLE_IPPROTO_ICMP && payload_length >= 8u && payload[0] == ICMP_ECHO_REQUEST) send_icmp_echo_reply(frame, length, ihl, total);
    else if (frame[23] == DR1ZZLE_IPPROTO_UDP) drizzle_udp_input(&source, &destination, payload, payload_length);
    else if (frame[23] == DR1ZZLE_IPPROTO_TCP) drizzle_tcp_input(&source, &destination, payload, payload_length);
}

void drizzle_net_set_link(const drizzle_link_t *link) { active_link = link; state = link ? DR1ZZLE_NET_CONFIGURING : DR1ZZLE_NET_DOWN; }
const drizzle_link_t *drizzle_net_link(void) { return active_link; }
int drizzle_net_link_up(void) { return active_link != 0 && active_link->transmit != 0; }
uint64_t drizzle_net_frames_rx(void) { return frames_rx; }
uint64_t drizzle_net_frames_tx(void) { return frames_tx; }
uint64_t drizzle_net_bytes_rx(void) { return bytes_rx; }
uint64_t drizzle_net_bytes_tx(void) { return bytes_tx; }
uint64_t drizzle_net_drops(void) { return drops; }
void drizzle_net_set_mac(const uint8_t hardware[DR1ZZLE_MAC_LEN]) { memcpy(mac, hardware, DR1ZZLE_MAC_LEN); }
const uint8_t *drizzle_net_mac(void) { return mac; }

void drizzle_net_init(void) {
    memset(mac, 0, sizeof mac);
    memset(v4, 0, sizeof v4);
    memset(v6, 0, sizeof v6);
    have_v4 = 0; have_v6 = 0; have_arp = 0;
    frames_rx = frames_tx = bytes_rx = bytes_tx = drops = 0u;
    drizzle_udp_reset();
    state = active_link ? DR1ZZLE_NET_CONFIGURING : DR1ZZLE_NET_DOWN;
}

void drizzle_net_poll(void) { if (active_link && active_link->receive) active_link->receive(); drizzle_tcp_poll(); }
drizzle_net_state_t drizzle_net_state(void) { return have_v4 || have_v6 ? DR1ZZLE_NET_UP : state; }

void drizzle_net_configure_v4(const uint8_t address[4], const uint8_t netmask[4], const uint8_t gateway[4]) { memcpy(v4, address, 4u); memcpy(v4_mask, netmask, 4u); memcpy(v4_gateway, gateway, 4u); have_v4 = 1; state = DR1ZZLE_NET_UP; }
void drizzle_net_configure_v6(const uint8_t address[16], unsigned prefix_length, const uint8_t gateway[16]) { memcpy(v6, address, 16u); memcpy(v6_gateway, gateway, 16u); v6_prefix = prefix_length > 128u ? 128u : prefix_length; have_v6 = 1; state = DR1ZZLE_NET_UP; }
int drizzle_net_has_v4(void) { return have_v4; }
int drizzle_net_has_v6(void) { return have_v6; }
const uint8_t *drizzle_net_v4(void) { return v4; }
const uint8_t *drizzle_net_v6(void) { return v6; }
const uint8_t *drizzle_net_v4_netmask(void) { return v4_mask; }
const uint8_t *drizzle_net_v4_gateway(void) { return v4_gateway; }
const uint8_t *drizzle_net_v6_gateway(void) { return v6_gateway; }
unsigned drizzle_net_v6_prefix_length(void) { return v6_prefix; }

void drizzle_net_receive(const uint8_t *frame, size_t length) {
    if (!frame || length < DR1ZZLE_ETH_HEADER) { drops++; return; }
    if (memcmp(frame, mac, DR1ZZLE_MAC_LEN) != 0 && !is_broadcast(frame)) return;
    frames_rx++;
    bytes_rx += length;
    uint16_t type = load16(frame + 12u);
    if (type == ETH_ARP) handle_arp(frame, length);
    else if (type == ETH_IPV4) handle_ipv4(frame, length);
    else drops++;
}

int drizzle_net_send_udp_v4(const uint8_t destination[4], uint16_t source_port, uint16_t destination_port, const uint8_t *payload, size_t length) {
    uint8_t frame[DR1ZZLE_ETH_HEADER + DR1ZZLE_IPV4_HEADER + DR1ZZLE_UDP_HEADER + DR1ZZLE_ETH_MTU];
    size_t udp_length = DR1ZZLE_UDP_HEADER + length;
    size_t ip_length = DR1ZZLE_IPV4_HEADER + udp_length;
    if (!have_v4 || !destination || (!payload && length) || length > DR1ZZLE_ETH_MTU - DR1ZZLE_IPV4_HEADER - DR1ZZLE_UDP_HEADER) return -1;
    if (have_arp && same4(destination, arp_ip)) memcpy(frame, arp_mac, DR1ZZLE_MAC_LEN); else memset(frame, 0xff, DR1ZZLE_MAC_LEN);
    memcpy(frame + 6u, mac, DR1ZZLE_MAC_LEN);
    store16(frame + 12u, ETH_IPV4);
    frame[14] = 0x45u; frame[15] = 0u; store16(frame + 16u, (uint16_t)ip_length);
    store16(frame + 18u, 0u); store16(frame + 20u, 0x4000u);
    frame[22] = 64u; frame[23] = DR1ZZLE_IPPROTO_UDP; store16(frame + 24u, 0u);
    memcpy(frame + 26u, v4, 4u); memcpy(frame + 30u, destination, 4u);
    store16(frame + 24u, checksum(frame + 14u, DR1ZZLE_IPV4_HEADER, 0u));
    size_t udp = DR1ZZLE_ETH_HEADER + DR1ZZLE_IPV4_HEADER;
    store16(frame + udp, source_port); store16(frame + udp + 2u, destination_port); store16(frame + udp + 4u, (uint16_t)udp_length); store16(frame + udp + 6u, 0u);
    if (length) memcpy(frame + udp + DR1ZZLE_UDP_HEADER, payload, length);
    uint32_t pseudo = ((uint32_t)v4[0] << 8) + v4[1] + ((uint32_t)v4[2] << 8) + v4[3] + ((uint32_t)destination[0] << 8) + destination[1] + ((uint32_t)destination[2] << 8) + destination[3] + DR1ZZLE_IPPROTO_UDP + (uint32_t)udp_length;
    store16(frame + udp + 6u, checksum(frame + udp, udp_length, pseudo));
    transmit(frame, DR1ZZLE_ETH_HEADER + ip_length);
    return (int)length;
}

void drizzle_endpoint_v4(drizzle_endpoint_t *endpoint, uint16_t port, const uint8_t address[4]) { memset(endpoint, 0, sizeof *endpoint); endpoint->family = DR1ZZLE_AF_INET; endpoint->port = port; memcpy(endpoint->address, address, 4u); }
void drizzle_endpoint_v6(drizzle_endpoint_t *endpoint, uint16_t port, const uint8_t address[16]) { memset(endpoint, 0, sizeof *endpoint); endpoint->family = DR1ZZLE_AF_INET6; endpoint->port = port; memcpy(endpoint->address, address, 16u); }
int drizzle_endpoint_equal(const drizzle_endpoint_t *left, const drizzle_endpoint_t *right) { if (!left || !right || left->family == DR1ZZLE_AF_UNSPEC || right->family == DR1ZZLE_AF_UNSPEC) return 0; size_t n = left->family == DR1ZZLE_AF_INET ? 4u : 16u; return left->family == right->family && left->port == right->port && memcmp(left->address, right->address, n) == 0; }
int drizzle_endpoint_is_unspecified(const drizzle_endpoint_t *endpoint) { if (!endpoint || endpoint->family == DR1ZZLE_AF_UNSPEC) return 1; size_t n = endpoint->family == DR1ZZLE_AF_INET ? 4u : 16u; for (size_t i = 0; i < n; i++) if (endpoint->address[i]) return 0; return 1; }
int drizzle_endpoint_is_loopback(const drizzle_endpoint_t *endpoint) { if (!endpoint) return 0; return endpoint->family == DR1ZZLE_AF_INET ? endpoint->address[0] == 127u : endpoint->family == DR1ZZLE_AF_INET6 && endpoint->address[15] == 1u && memcmp(endpoint->address, (uint8_t[15]){0}, 15u) == 0; }
int drizzle_endpoint_is_multicast(const drizzle_endpoint_t *endpoint) { if (!endpoint) return 0; return endpoint->family == DR1ZZLE_AF_INET ? (endpoint->address[0] & 0xf0u) == 0xe0u : endpoint->family == DR1ZZLE_AF_INET6 && endpoint->address[0] == 0xffu; }
int drizzle_endpoint_is_link_local(const drizzle_endpoint_t *endpoint) { if (!endpoint) return 0; return endpoint->family == DR1ZZLE_AF_INET ? endpoint->address[0] == 169u && endpoint->address[1] == 254u : endpoint->family == DR1ZZLE_AF_INET6 && endpoint->address[0] == 0xfeu && (endpoint->address[1] & 0xc0u) == 0x80u; }
static int append_char(char *buffer, size_t capacity, size_t *used, char c) { if (*used + 1u >= capacity) return 0; buffer[(*used)++] = c; buffer[*used] = 0; return 1; }
static int append_byte(char *buffer, size_t capacity, size_t *used, uint8_t value) {
    char digits[3];
    size_t count = 0;
    do { digits[count++] = (char)('0' + (value % 10u)); value = (uint8_t)(value / 10u); } while (value);
    while (count) if (!append_char(buffer, capacity, used, digits[--count])) return 0;
    return 1;
}
int drizzle_endpoint_text(const drizzle_endpoint_t *endpoint, char *buffer, size_t capacity) {
    size_t used = 0;
    if (!endpoint || !buffer || !capacity) return 0;
    buffer[0] = 0;
    if (endpoint->family != DR1ZZLE_AF_INET) return 0;
    for (size_t i = 0; i < 4u; i++) {
        if (i && !append_char(buffer, capacity, &used, '.')) return 0;
        if (!append_byte(buffer, capacity, &used, endpoint->address[i])) return 0;
    }
    return (int)used;
}
int drizzle_endpoint_parse(const char *text, drizzle_endpoint_t *endpoint) { unsigned parts[4] = {0, 0, 0, 0}; int digits[4] = {0, 0, 0, 0}; size_t part = 0; if (!text || !endpoint || !*text) return 0; for (; *text; text++) { if (*text == '.') { if (!digits[part] || ++part >= 4u) return 0; } else if (*text >= '0' && *text <= '9') { digits[part] = 1; parts[part] = parts[part] * 10u + (unsigned)(*text - '0'); if (parts[part] > 255u) return 0; } else return 0; } if (part != 3u || !digits[part]) return 0; uint8_t a[4] = {(uint8_t)parts[0], (uint8_t)parts[1], (uint8_t)parts[2], (uint8_t)parts[3]}; drizzle_endpoint_v4(endpoint, 0u, a); return 1; }
