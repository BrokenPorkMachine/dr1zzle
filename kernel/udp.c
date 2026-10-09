#include <drizzle/udp.h>
#include <string.h>

#define UDP_BINDINGS 8u
#define UDP_QUEUE 8u
#define UDP_PAYLOAD 512u

typedef struct {
    int used;
    uint16_t port;
    drizzle_endpoint_t source;
    size_t length;
    uint8_t data[UDP_PAYLOAD];
} packet_t;

static uint16_t bindings[UDP_BINDINGS];
static packet_t queue[UDP_QUEUE];
static uint16_t local_port = DR1ZZLE_UDP_LOCAL_PORT_DEFAULT;

static uint16_t load16(const uint8_t *p) { return (uint16_t)(((uint16_t)p[0] << 8) | p[1]); }
static int bound(uint16_t port) { for (size_t i = 0; i < UDP_BINDINGS; i++) if (bindings[i] == port) return 1; return 0; }

int drizzle_udp_bind(uint16_t port) {
    if (!port || bound(port)) return 0;
    for (size_t i = 0; i < UDP_BINDINGS; i++) if (!bindings[i]) { bindings[i] = port; return 1; }
    return 0;
}

void drizzle_udp_set_local_port(uint16_t port) { local_port = port ? port : DR1ZZLE_UDP_LOCAL_PORT_DEFAULT; }
uint16_t drizzle_udp_local_port(void) { return local_port; }

void drizzle_udp_unbind(uint16_t port) {
    for (size_t i = 0; i < UDP_BINDINGS; i++) if (bindings[i] == port) bindings[i] = 0;
    for (size_t i = 0; i < UDP_QUEUE; i++) if (queue[i].used && queue[i].port == port) queue[i].used = 0;
}

int drizzle_udp_send_to(const drizzle_endpoint_t *destination, const uint8_t *data, size_t length) {
    if (!destination || destination->family != DR1ZZLE_AF_INET || (!data && length)) return -1;
    return drizzle_net_send_udp_v4(destination->address, local_port, destination->port, data, length);
}

int drizzle_udp_send_v4(const uint8_t address[4], uint16_t port, const uint8_t *data, size_t length) { if (!data && length) return -1; return drizzle_net_send_udp_v4(address, local_port, port, data, length); }

int drizzle_udp_receive(uint16_t port, uint8_t *buffer, size_t capacity, drizzle_endpoint_t *source) {
    for (size_t i = 0; i < UDP_QUEUE; i++) {
        if (queue[i].used && queue[i].port == port) {
            size_t count = queue[i].length < capacity ? queue[i].length : capacity;
            if (buffer && count) memcpy(buffer, queue[i].data, count);
            if (source) *source = queue[i].source;
            queue[i].used = 0;
            return (int)count;
        }
    }
    return -1;
}

void drizzle_udp_input(const drizzle_endpoint_t *source, const drizzle_endpoint_t *destination, const uint8_t *payload, size_t length) {
    if (!source || !destination || !payload || length < DR1ZZLE_UDP_HEADER || destination->family != DR1ZZLE_AF_INET) return;
    uint16_t src_port = load16(payload);
    uint16_t dst_port = load16(payload + 2u);
    size_t udp_length = load16(payload + 4u);
    if (udp_length < DR1ZZLE_UDP_HEADER || udp_length > length || !bound(dst_port)) return;
    for (size_t i = 0; i < UDP_QUEUE; i++) {
        if (!queue[i].used) {
            queue[i].used = 1;
            queue[i].port = dst_port;
            queue[i].source = *source;
            queue[i].source.port = src_port;
            queue[i].length = udp_length - DR1ZZLE_UDP_HEADER;
            if (queue[i].length > UDP_PAYLOAD) queue[i].length = UDP_PAYLOAD;
            memcpy(queue[i].data, payload + DR1ZZLE_UDP_HEADER, queue[i].length);
            return;
        }
    }
}

void drizzle_udp_discard(uint16_t port, const drizzle_endpoint_t *source) { (void)source; drizzle_udp_unbind(port); }
uint16_t drizzle_udp_bound_count(void) { uint16_t count = 0; for (size_t i = 0; i < UDP_BINDINGS; i++) if (bindings[i]) count++; return count; }
void drizzle_udp_reset(void) { memset(bindings, 0, sizeof bindings); memset(queue, 0, sizeof queue); local_port = DR1ZZLE_UDP_LOCAL_PORT_DEFAULT; }
