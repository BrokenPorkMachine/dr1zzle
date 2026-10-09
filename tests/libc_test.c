#include <ctype.h>
#include <drizzle/net.h>
#include <drizzle/udp.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static int failures;
#ifdef HOST_TEST
long write(int descriptor, const void *buffer, unsigned long count);
static void note_failure(const char *text) { (void)write(2, text, strlen(text)); (void)write(2, "\n", 1u); }
#else
static void note_failure(const char *text) { puts(text); }
#endif
#define CHECK(x) do { if (!(x)) { note_failure("FAIL " #x); failures++; } } while (0)
static int ascending(const void *a, const void *b) { int x = *(const int *)a, y = *(const int *)b; return (x > y) - (x < y); }
static uint8_t tx_frame[1600];
static size_t tx_length;
static void capture_tx(const uint8_t *frame, size_t length) { tx_length = length; memcpy(tx_frame, frame, length); }
static uint16_t be16(const uint8_t *p) { return (uint16_t)(((uint16_t)p[0] << 8) | p[1]); }
static void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static uint16_t test_checksum(const uint8_t *data, size_t length, uint32_t sum) {
    while (length > 1u) { sum += be16(data); data += 2; length -= 2u; }
    if (length) sum += (uint16_t)((uint16_t)data[0] << 8);
    while (sum >> 16) sum = (sum & 0xffffu) + (sum >> 16);
    return (uint16_t)~sum;
}
static void build_ipv4(uint8_t *frame, const uint8_t dst_mac[6], const uint8_t src_mac[6], const uint8_t src_ip[4], const uint8_t dst_ip[4], uint8_t protocol, uint16_t payload_length) {
    memcpy(frame, dst_mac, 6u);
    memcpy(frame + 6u, src_mac, 6u);
    put16(frame + 12u, 0x0800u);
    frame[14] = 0x45u;
    put16(frame + 16u, (uint16_t)(20u + payload_length));
    frame[22] = 64u;
    frame[23] = protocol;
    memcpy(frame + 26u, src_ip, 4u);
    memcpy(frame + 30u, dst_ip, 4u);
    put16(frame + 24u, 0u);
    put16(frame + 24u, test_checksum(frame + 14u, 20u, 0u));
}
int main(void) {
    char b[32];
    CHECK(strlen("drizzle") == 7u);
    CHECK(strcmp("abc", "abd") < 0);
    CHECK(strstr("abcdrizzle", "driz") != 0);
    CHECK(memcmp(memmove(b, "abcdef", 7u), "abcdef", 7u) == 0);
    CHECK(memcmp(memmove(b + 2, b, 5u), "abcde", 5u) == 0);
    CHECK(memcmp(memmove(b, b + 2, 5u), "abcde", 5u) == 0);

    CHECK(snprintf(b, sizeof b, "%04x", 0x2a) == 4 && !strcmp(b, "002a"));
    CHECK(snprintf(b, sizeof b, "%-6s", "hi") == 6 && !strcmp(b, "hi    "));
    CHECK(snprintf(b, sizeof b, "%.3s", "drizzle") == 3 && !strcmp(b, "dri"));
    CHECK(snprintf(b, sizeof b, "%+d", 7) == 2 && !strcmp(b, "+7"));
    CHECK(snprintf(b, sizeof b, "%#x", 42u) == 4 && !strcmp(b, "0x2a"));
    CHECK(snprintf(b, sizeof b, "%hhd", 255) == 2 && !strcmp(b, "-1"));
    CHECK(snprintf(b, 4u, "hello") == 5 && !strcmp(b, "hel"));

    char *tail;
    errno = 0; CHECK(strtoul("0", &tail, 0) == 0 && *tail == 0 && errno == 0);
    errno = 0; CHECK(strtoul("0x2a!", &tail, 0) == 42 && *tail == '!' && errno == 0);
    errno = 0; CHECK(strtoul("z", &tail, 35) == 0 && *tail == 'z' && errno == 0);
    errno = 0; CHECK(strtoul("1", &tail, 1) == 0 && *tail == '1' && errno == EINVAL);
    errno = 0; CHECK(strtoul("999999999999999999999999999999", &tail, 10) == ULONG_MAX && errno == ERANGE);
    errno = 0; CHECK(strtol("-42x", &tail, 10) == -42 && *tail == 'x' && errno == 0);

    CHECK(isalpha('D') && isdigit('7') && tolower('Z') == 'z');

    unsigned char heap[384];
    drizzle_heap_set(heap, sizeof heap);
    char *p = calloc(4u, 4u);
    CHECK(p && p[0] == 0 && p[15] == 0);
    memset(p, 'a', 16u);
    char *grown = realloc(p, 24u);
    CHECK(grown && grown[0] == 'a' && grown[15] == 'a');
    free(grown);
    CHECK(malloc(128u) != 0);
    CHECK(malloc(128u) == 0);

    int values[] = {4, 1, 3, 2};
    int needle = 3;
    qsort(values, 4u, sizeof values[0], ascending);
    CHECK(values[0] == 1 && values[3] == 4);
    CHECK(*(int *)bsearch(&needle, values, 4u, sizeof values[0], ascending) == 3);

    drizzle_endpoint_t ep;
    char text[16];
    CHECK(drizzle_endpoint_parse("192.168.4.2", &ep));
    CHECK(drizzle_endpoint_text(&ep, text, sizeof text) == 11 && !strcmp(text, "192.168.4.2"));
    CHECK(!drizzle_endpoint_parse("192..4.2", &ep));
    CHECK(!drizzle_endpoint_parse("192.168.4.", &ep));
    CHECK(!drizzle_endpoint_parse("300.168.4.2", &ep));

    static const drizzle_link_t link = { capture_tx, 0, "test-link" };
    uint8_t hw[6] = {0x02u, 0xd1u, 0x7au, 0, 0, 1u};
    uint8_t ip[4] = {10u, 0u, 0u, 2u};
    uint8_t mask[4] = {255u, 255u, 255u, 0u};
    uint8_t gw[4] = {10u, 0u, 0u, 1u};
    uint8_t peer[4] = {10u, 0u, 0u, 3u};
    uint8_t payload[3] = {'d', 'r', '1'};
    drizzle_net_init();
    drizzle_net_set_link(&link);
    drizzle_net_set_mac(hw);
    drizzle_net_configure_v4(ip, mask, gw);
    CHECK(drizzle_net_link_up() && drizzle_net_state() == DR1ZZLE_NET_UP);
    drizzle_udp_set_local_port(40000u);
    CHECK(drizzle_udp_local_port() == 40000u);
    CHECK(drizzle_udp_send_v4(peer, 9999u, payload, sizeof payload) == 3);
    CHECK(tx_length == 14u + 20u + 8u + 3u);
    CHECK(be16(tx_frame + 12u) == 0x0800u && tx_frame[23] == DR1ZZLE_IPPROTO_UDP);
    CHECK(be16(tx_frame + 34u) == 40000u);
    CHECK(drizzle_net_frames_tx() == 1u && drizzle_net_bytes_tx() == tx_length);
    CHECK(drizzle_udp_send_v4(peer, 9999u, 0, 0u) == 0);
    CHECK(tx_length == 14u + 20u + 8u);
    CHECK(drizzle_net_frames_tx() == 2u);

    uint8_t rx[14u + 20u + 8u + 3u];
    memset(rx, 0, sizeof rx);
    uint8_t peer_mac[6] = {0x02u, 0xaau, 0xbbu, 0xccu, 0xddu, 0xeeu};
    build_ipv4(rx, hw, peer_mac, peer, ip, DR1ZZLE_IPPROTO_UDP, (uint16_t)(8u + 3u));
    put16(rx + 34u, 7777u); put16(rx + 36u, 9999u); put16(rx + 38u, 11u);
    memcpy(rx + 42u, payload, sizeof payload);
    CHECK(drizzle_udp_bind(9999u));
    drizzle_net_receive(rx, sizeof rx);
    uint8_t out[8];
    drizzle_endpoint_t src;
    CHECK(drizzle_udp_receive(9999u, out, sizeof out, &src) == 3);
    CHECK(!memcmp(out, payload, sizeof payload) && src.port == 7777u);
    drizzle_net_init();
    CHECK(drizzle_udp_bound_count() == 0u);
    CHECK(drizzle_udp_local_port() == DR1ZZLE_UDP_LOCAL_PORT_DEFAULT);

    drizzle_net_set_link(&link);
    drizzle_net_set_mac(hw);
    drizzle_net_configure_v4(ip, mask, gw);
    uint8_t ping[14u + 20u + 8u];
    memset(ping, 0, sizeof ping);
    build_ipv4(ping, hw, peer_mac, peer, ip, DR1ZZLE_IPPROTO_ICMP, 8u);
    ping[34] = 8u;
    ping[35] = 0u;
    put16(ping + 36u, 0u);
    put16(ping + 36u, test_checksum(ping + 34u, 8u, 0u));
    tx_length = 0u;
    drizzle_net_receive(ping, sizeof ping);
    CHECK(tx_length == sizeof ping);
    CHECK(be16(tx_frame + 12u) == 0x0800u && tx_frame[22] == 64u && tx_frame[23] == DR1ZZLE_IPPROTO_ICMP);
    CHECK(tx_frame[34] == 0u && test_checksum(tx_frame + 14u, 20u, 0u) == 0u && test_checksum(tx_frame + 34u, 8u, 0u) == 0u);
    return failures;
}
