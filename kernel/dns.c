#include <drizzle/dns.h>
#include <string.h>

#define DNS_MAX_SERVERS 4u
static uint8_t dns_servers[DNS_MAX_SERVERS][4];
static unsigned dns_server_count;
static char hostname[32];
static int dns_server_enabled;

void drizzle_dns_init(const uint8_t servers[4][4], unsigned server_count) {
    dns_server_count = server_count > DNS_MAX_SERVERS ? DNS_MAX_SERVERS : server_count;
    for (unsigned i = 0; i < dns_server_count; i++) memcpy(dns_servers[i], servers[i], 4u);
}

void drizzle_dns_set_hostname(const char *name) {
    size_t length = strnlen(name, sizeof hostname - 1u);
    memcpy(hostname, name, length);
    hostname[length] = 0;
}

int drizzle_dns_resolve(const char *name, drizzle_family_t *family, uint8_t *address) {
    if (!name || !family || !address) return 0;
    if (hostname[0] && strcmp(name, hostname) == 0 && drizzle_net_has_v4()) {
        *family = DR1ZZLE_AF_INET;
        memcpy(address, drizzle_net_v4(), 4u);
        return 1;
    }
    return 0;
}

void drizzle_dns_poll(void) {}
unsigned drizzle_dns_cache_count(void) { return dns_server_count; }
void drizzle_dns_server_enable(uint16_t port) { (void)port; dns_server_enabled = 1; }
void drizzle_dns_server_disable(void) { dns_server_enabled = 0; }
