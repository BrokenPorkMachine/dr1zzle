#include "internal.h"
#include <string.h>
#include "drizzle/dns.h"

/* A deliberately small DNS: enough to resolve a name, cache the answer, and
 * answer queries for our own hostname. Compression pointers are parsed on the
 * way in but never emitted, which keeps the encoder trivial.
 *
 * The resolver binds a client port of its own; the server, when enabled, binds
 * the well-known port. The two never contend for a slot.
 */

#define DR1ZZLE_DNS_PORT 53u
#define DR1ZZLE_DNS_CLIENT_PORT 49153u
#define DR1ZZLE_DNS_CACHE_MAX 8u
#define DR1ZZLE_DNS_NAME_MAX 64u
#define DR1ZZLE_DNS_UDP_MAX 512u
#define DR1ZZLE_DNS_TIMEOUT_MS 250u
#define DR1ZZLE_DNS_ATTEMPTS 4u

#define DNS_CLASS_IN 1u
#define DNS_TYPE_A 1u
#define DNS_TYPE_AAAA 28u

typedef struct {
    int valid;
    char name[DR1ZZLE_DNS_NAME_MAX];
    uint8_t address[16];
    drizzle_family_t family;
    uint32_t expires_ms;
} dns_entry_t;

static uint8_t servers[4][4];
static unsigned server_count;
static dns_entry_t cache[DR1ZZLE_DNS_CACHE_MAX];

static uint16_t next_transaction = 1u;
static uint16_t pending_transaction;
static unsigned pending_attempts;
static uint8_t pending_name[DR1ZZLE_DNS_NAME_MAX];
static uint8_t pending_address[16];
static int pending_ipv4;
static int pending_ipv6;
static uint32_t last_dispatch_ms;

static int server_enabled;
static uint16_t server_port = DR1ZZLE_DNS_PORT;
static char local_name[DR1ZZLE_DNS_NAME_MAX];

void drizzle_dns_init(const uint8_t configured[4][4], unsigned count) {
    memset(cache, 0, sizeof cache);
    memset(servers, 0, sizeof servers);
    if (count > 4u) count = 4u;
    if (count && configured) memcpy(servers, configured, count * 4u);
    server_count = count;
    next_transaction = 1u;
    pending_transaction = 0u;
    pending_attempts = 0u;
    drizzle_udp_bind(DR1ZZLE_DNS_CLIENT_PORT);
}

void drizzle_dns_set_hostname(const char *name) {
    size_t index = 0u;
    if (!name) {
        local_name[0] = 0;
        return;
    }
    while (name[index] && index + 1u < sizeof local_name) {
        local_name[index] = name[index];
        index++;
    }
    local_name[index] = 0;
}

unsigned drizzle_dns_cache_count(void) {
    unsigned count = 0u;
    size_t index;
    for (index = 0u; index < DR1ZZLE_DNS_CACHE_MAX; index++) {
        if (cache[index].valid) count++;
    }
    return count;
}

/* ---- name encoding and decoding ---- */

static size_t encode_name(char *buffer, size_t capacity, const char *name) {
    size_t written = 0u;
    const char *segment = name;

    for (;;) {
        const char *dot = segment;
        size_t length;
        while (*dot && *dot != '.') dot++;
        length = (size_t)(dot - segment);
        if (length == 0u || length > 63u) return 0u;
        if (written + length + 2u > capacity) return 0u;
        buffer[written] = (char)(uint8_t)length;
        memcpy(buffer + written + 1u, segment, length);
        written += length + 1u;
        if (!*dot) break;
        segment = dot + 1;
    }
    if (written + 1u > capacity) return 0u;
    buffer[written] = 0;
    return written + 1u;
}

/* Returns the offset just past the name in the message, or 0 when malformed. */
static size_t skip_name(const uint8_t *message, size_t length, size_t offset) {
    unsigned jumps = 0u;
    while (offset < length) {
        uint8_t marker = message[offset];
        if ((marker & 0xc0u) == 0xc0u) {
            if (offset + 2u > length) return 0u;
            return offset + 2u; /* a pointer always ends the name */
        }
        if (marker == 0u) return offset + 1u;
        if (marker > 63u) return 0u;
        offset += 1u + marker;
        if (++jumps > 16u) return 0u; /* refuse pointer loops */
    }
    return 0u;
}

static size_t decode_name(const uint8_t *message, size_t length, size_t offset,
                          char *buffer, size_t capacity) {
    size_t written = 0u;
    unsigned jumps = 0u;
    int followed_pointer = 0;
    size_t end = 0u;

    for (;;) {
        uint8_t marker;
        if (offset >= length) return 0u;
        marker = message[offset];
        if ((marker & 0xc0u) == 0xc0u) {
            size_t pointer;
            if (offset + 2u > length) return 0u;
            pointer = (size_t)(((uint32_t)(marker & 0x3fu) << 8) | message[offset + 1u]);
            if (!followed_pointer) {
                end = offset + 2u;
                followed_pointer = 1;
            }
            offset = pointer;
            if (++jumps > 16u) return 0u;
            continue;
        }
        if (marker == 0u) {
            offset += 1u;
            if (!followed_pointer) end = offset;
            break;
        }
        if (marker > 63u || offset + 1u + marker > length) return 0u;
        if (written + marker + 2u > capacity) return 0u;
        if (written) buffer[written] = '.';
        memcpy(buffer + written + 1u, message + offset + 1u, marker);
        written += marker;
        offset += 1u + marker;
    }
    buffer[written] = 0;
    return end;
}

/* ---- cache ---- */

static dns_entry_t *cache_find(const char *name) {
    size_t index;
    for (index = 0u; index < DR1ZZLE_DNS_CACHE_MAX; index++) {
        if (cache[index].valid && strcmp(cache[index].name, name) == 0) return &cache[index];
    }
    return NULL;
}

static void cache_store(const char *name, const uint8_t *address, drizzle_family_t family,
                        uint32_t ttl) {
    dns_entry_t *entry = cache_find(name);
    size_t index;

    if (!entry) {
        for (index = 0u; index < DR1ZZLE_DNS_CACHE_MAX; index++) {
            if (!cache[index].valid) {
                entry = &cache[index];
                break;
            }
        }
    }
    if (!entry) entry = &cache[0]; /* table full: replace the first slot */
    if (!entry) return;

    memset(entry, 0, sizeof *entry);
    strncpy(entry->name, name, sizeof entry->name - 1u);
    entry->family = family;
    memcpy(entry->address, address, family == DR1ZZLE_AF_INET6 ? 16u : 4u);
    entry->expires_ms = (uint32_t)(drizzle_time_ms() + ttl * 1000u);
    entry->valid = 1;
}

/* ---- query encoding ---- */

static int build_query(uint8_t *packet, size_t capacity, uint16_t transaction,
                       const char *name, uint16_t type) {
    char encoded[DR1ZZLE_DNS_NAME_MAX * 2u];
    size_t name_length = encode_name(encoded, sizeof encoded, name);
    size_t offset;

    if (name_length == 0u) return 0;
    if (name_length + 16u > capacity) return 0;

    memset(packet, 0, 12u);
    net_write16(packet, transaction);
    net_write16(packet + 2, 0x0100u); /* recursion desired */
    net_write16(packet + 4, 1u);      /* exactly one question */
    memcpy(packet + 12, encoded, name_length);
    offset = 12u + name_length;
    net_write16(packet + offset, type);
    net_write16(packet + offset + 2, (uint16_t)DNS_CLASS_IN);
    return (int)(offset + 4u);
}

static void dispatch_query(void) {
    uint8_t packet[DR1ZZLE_DNS_UDP_MAX];
    size_t index;

    for (index = 0u; index < server_count; index++) {
        int length = build_query(packet, sizeof packet, pending_transaction,
                                 (const char *)pending_name, (uint16_t)DNS_TYPE_A);
        if (length > 0) {
            (void)drizzle_udp_send_v4(servers[index], DR1ZZLE_DNS_PORT, packet,
                                      (size_t)length);
        }
        length = build_query(packet, sizeof packet, pending_transaction,
                             (const char *)pending_name, (uint16_t)DNS_TYPE_AAAA);
        if (length > 0) {
            (void)drizzle_udp_send_v4(servers[index], DR1ZZLE_DNS_PORT, packet,
                                      (size_t)length);
        }
    }
}

static void note_answer(uint32_t ttl, const uint8_t *address, drizzle_family_t family) {
    if (ttl == 0u) ttl = 60u;
    cache_store((const char *)pending_name, address, family, ttl);
    if (family == DR1ZZLE_AF_INET6) {
        memcpy(pending_address, address, 16u);
        pending_ipv6 = 1;
    } else {
        memcpy(pending_address, address, 4u);
        pending_ipv4 = 1;
    }
}

static void parse_response(const uint8_t *message, size_t length) {
    uint16_t transaction;
    uint16_t answer_count;
    size_t offset;
    char question[DR1ZZLE_DNS_NAME_MAX];

    if (length < 12u) return;
    transaction = net_read16(message);
    if (pending_transaction == 0u || transaction != pending_transaction) return;
    if (net_read16(message + 2) & 0x8000u) return; /* server reported an error */
    if (net_read16(message + 4) == 0u) return;    /* no question echoed */

    offset = decode_name(message, length, 12u, question, sizeof question);
    if (offset == 0u) return;
    offset += 4u; /* qtype and qclass */
    if (offset > length) return;

    answer_count = net_read16(message + 6);
    while (answer_count > 0u && offset < length) {
        char name[DR1ZZLE_DNS_NAME_MAX];
        uint16_t type;
        uint16_t class_field;
        uint32_t ttl;
        uint16_t data_length;
        size_t data_offset;

        data_offset = skip_name(message, length, offset);
        if (data_offset == 0u) return;
        offset = data_offset;
        if (offset + 10u > length) return;
        type = net_read16(message + offset);
        class_field = net_read16(message + offset + 2);
        ttl = net_read32(message + offset + 4);
        data_length = net_read16(message + offset + 8);
        offset += 10u;
        if (offset + data_length > length) return;

        /* Answers for a different name (a CNAME chain, say) are cached under
         * their own name so a later lookup of that name hits the cache. */
        if (class_field == DNS_CLASS_IN && data_length > 0u) {
            decode_name(message, length, offset - 10u, name, sizeof name);
            if (type == DNS_TYPE_A && data_length == 4u) {
                cache_store(name, message + offset, DR1ZZLE_AF_INET, ttl);
            } else if (type == DNS_TYPE_AAAA && data_length == 16u) {
                cache_store(name, message + offset, DR1ZZLE_AF_INET6, ttl);
            }
            if (strcmp(name, question) == 0 || strcmp(name, (const char *)pending_name) == 0) {
                if (type == DNS_TYPE_A && data_length == 4u) {
                    note_answer(ttl, message + offset, DR1ZZLE_AF_INET);
                } else if (type == DNS_TYPE_AAAA && data_length == 16u) {
                    note_answer(ttl, message + offset, DR1ZZLE_AF_INET6);
                }
            }
        }
        offset += data_length;
        answer_count--;
    }
}

/* Reads and parses whatever the resolver has been sent. */
static void dns_drain_client(void) {
    uint8_t buffer[DR1ZZLE_DNS_UDP_MAX];
    drizzle_endpoint_t source;
    int got;
    while ((got = drizzle_udp_receive(DR1ZZLE_DNS_CLIENT_PORT, buffer, sizeof buffer,
                                     &source)) >= 0) {
        parse_response(buffer, (size_t)got);
    }
}

static void dns_start_query(const char *name) {
    memset(pending_name, 0, sizeof pending_name);
    strncpy((char *)pending_name, name, sizeof pending_name - 1u);
    pending_transaction = next_transaction;
    next_transaction++;
    if (next_transaction == 0u) next_transaction = 1u;
    pending_attempts = 0u;
    pending_ipv4 = 0;
    pending_ipv6 = 0;
    last_dispatch_ms = (uint32_t)drizzle_time_ms();
    dispatch_query();
    pending_attempts++;
}

/* Retries a query that has been outstanding too long. */
static void dns_retry_if_stale(void) {
    uint32_t now;
    if (pending_transaction == 0u) return;
    now = (uint32_t)drizzle_time_ms();
    if ((now - last_dispatch_ms) < DR1ZZLE_DNS_TIMEOUT_MS) return;
    if (pending_attempts >= DR1ZZLE_DNS_ATTEMPTS) {
        pending_transaction = 0u; /* give up */
        return;
    }
    last_dispatch_ms = now;
    dispatch_query();
    pending_attempts++;
}

int drizzle_dns_resolve(const char *name, drizzle_family_t *family, uint8_t *address) {
    dns_entry_t *entry;

    if (!name || !family || !address) return 0;

    entry = cache_find(name);
    if (entry) {
        if ((int32_t)(entry->expires_ms - (uint32_t)drizzle_time_ms()) > 0) {
            *family = entry->family;
            memcpy(address, entry->address, entry->family == DR1ZZLE_AF_INET6 ? 16u : 4u);
            return 1;
        }
        memset(entry, 0, sizeof *entry);
    }
    if (server_count == 0u) return 0;

    /* Exactly one query is kept in flight; a repeat call for the same name
     * continues it rather than restarting. */
    if (pending_transaction == 0u || strcmp((const char *)pending_name, name) != 0) {
        dns_start_query(name);
    }
    dns_drain_client();
    dns_retry_if_stale();

    if (pending_ipv6) {
        *family = DR1ZZLE_AF_INET6;
        memcpy(address, pending_address, 16u);
        pending_transaction = 0u;
        return 1;
    }
    if (pending_ipv4) {
        *family = DR1ZZLE_AF_INET;
        memcpy(address, pending_address, 4u);
        pending_transaction = 0u;
        return 1;
    }
    return 0;
}

/* Builds a reply for our own hostname. Answers A and AAAA with the addresses
 * currently configured, and refuses anything else. The answer's owner name is
 * a compression pointer back to the question, which is what every real server
 * does and costs two bytes. */
static int server_answer(const uint8_t *query, size_t query_length,
                         const drizzle_endpoint_t *source, uint8_t *reply,
                         size_t capacity) {
    char question[DR1ZZLE_DNS_NAME_MAX];
    size_t question_end;
    uint16_t type;
    uint16_t class_field;
    uint16_t reply_flags;
    uint8_t rcode = 0u;
    size_t question_bytes;
    size_t reply_length;
    int have_answer = 0;
    const uint8_t *address = NULL;
    drizzle_family_t answer_family = DR1ZZLE_AF_INET;

    question_end = decode_name(query, query_length, 12u, question, sizeof question);
    if (question_end == 0u) return 0;
    if (question_end + 4u > query_length) return 0;
    type = net_read16(query + question_end);
    class_field = net_read16(query + question_end + 2);
    question_bytes = question_end + 4u - 12u;

    if (class_field == DNS_CLASS_IN && local_name[0] && strcmp(question, local_name) == 0) {
        if (type == (uint16_t)DNS_TYPE_A && drizzle_net_has_v4()) {
            address = drizzle_net_v4();
            answer_family = DR1ZZLE_AF_INET;
            have_answer = 1;
        } else if (type == (uint16_t)DNS_TYPE_AAAA && drizzle_net_has_v6()) {
            address = drizzle_net_v6();
            answer_family = DR1ZZLE_AF_INET6;
            have_answer = 1;
        }
    } else {
        rcode = 3u; /* name error */
    }

    reply_length = 12u + question_bytes + (have_answer ? (16u + (answer_family ==
                                                               DR1ZZLE_AF_INET6
                                                                   ? 16u
                                                                   : 4u))
                                                        : 0u);
    if (reply_length > capacity) return 0;

    reply_flags = (uint16_t)(0x8400u | (net_read16(query + 2) & 0x0100u) | rcode);

    memset(reply, 0, 12u);
    net_write16(reply, net_read16(query));
    net_write16(reply + 2, reply_flags);
    net_write16(reply + 4, 1u);
    net_write16(reply + 6, (uint16_t)(have_answer ? 1u : 0u));
    net_write16(reply + 8, 0u);
    net_write16(reply + 10, 0u);
    memcpy(reply + 12, query + 12, question_bytes);

    if (have_answer) {
        size_t offset = 12u + question_bytes;
        size_t address_length = (answer_family == DR1ZZLE_AF_INET6) ? 16u : 4u;
        reply[offset] = 0xc0u; /* pointer to offset 12 */
        reply[offset + 1u] = 0x0cu;
        net_write16(reply + offset + 2u, type);
        net_write16(reply + offset + 4u, (uint16_t)DNS_CLASS_IN);
        net_write32(reply + offset + 6u, 60u);
        net_write16(reply + offset + 10u, (uint16_t)address_length);
        memcpy(reply + offset + 12u, address, address_length);
    }

    (void)drizzle_udp_send_to(source, reply, reply_length);
    return 1;
}

void drizzle_dns_poll(void) {
    uint8_t buffer[DR1ZZLE_DNS_UDP_MAX];
    uint8_t reply[DR1ZZLE_DNS_UDP_MAX];
    drizzle_endpoint_t source;
    int got;

    dns_retry_if_stale();
    if (pending_transaction != 0u) dns_drain_client();

    if (!server_enabled) return;
    while ((got = drizzle_udp_receive(server_port, buffer, sizeof buffer, &source)) >= 0) {
        if (got < 12u) continue;
        if ((buffer[2] & 0x80u) != 0u) continue; /* a response, not a query */
        if (buffer[3] != 0u) continue;            /* opcode must be query */
        (void)server_answer(buffer, (size_t)got, &source, reply, sizeof reply);
    }
}

void drizzle_dns_server_enable(uint16_t port) {
    server_port = port ? port : DR1ZZLE_DNS_PORT;
    server_enabled = 1;
    drizzle_udp_bind(server_port);
}

void drizzle_dns_server_disable(void) {
    if (server_enabled) drizzle_udp_unbind(server_port);
    server_enabled = 0;
}