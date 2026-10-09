#include "internal.h"
#include <string.h>
#include "drizzle/dhcp.h"

/* DHCPv4 client. The exchange is driven from the main poll loop; retries are
 * spaced out so an absent server costs one packet per interval rather than
 * spinning the transmit path. */

#define DR1ZZLE_DHCP_SERVER_PORT 67u
#define DR1ZZLE_DHCP_CLIENT_PORT 68u
#define DR1ZZLE_DHCP_MAGIC 0x63825363u
#define DR1ZZLE_DHCP_MESSAGE_DISCOVER 1u
#define DR1ZZLE_DHCP_MESSAGE_OFFER 2u
#define DR1ZZLE_DHCP_MESSAGE_REQUEST 3u
#define DR1ZZLE_DHCP_MESSAGE_ACK 5u
#define DR1ZZLE_DHCP_OPTION_SUBNET 1u
#define DR1ZZLE_DHCP_OPTION_ROUTER 3u
#define DR1ZZLE_DHCP_OPTION_DNS 6u
#define DR1ZZLE_DHCP_OPTION_LEASE 51u
#define DR1ZZLE_DHCP_OPTION_MESSAGE_TYPE 53u
#define DR1ZZLE_DHCP_OPTION_END 255u
#define DR1ZZLE_DHCP_RETRY_MS 1000u
#define DR1ZZLE_DHCP_ATTEMPTS 5u
#define DR1ZZLE_DHCP_PAYLOAD 548u

typedef enum { DHCP_IDLE = 0, DHCP_DISCOVERING, DHCP_REQUESTING, DHCP_BOUND } dhcp_state_t;

static dhcp_state_t state;
static uint32_t transaction = 0x11223344u;
static uint32_t last_sent_ms;
static unsigned attempts;
static uint32_t offered_address;
static uint32_t lease_seconds;
static uint32_t next_transaction(void) {
    transaction += 0x10203040u;
    return transaction;
}

void drizzle_dhcp_start(void) {
    state = DHCP_DISCOVERING;
    attempts = 0u;
    lease_seconds = 0u;
    offered_address = 0u;
    last_sent_ms = 0u;
    drizzle_udp_bind(DR1ZZLE_DHCP_CLIENT_PORT);
}

int drizzle_dhcp_bound(void) {
    return state == DHCP_BOUND;
}

uint32_t drizzle_dhcp_lease_seconds(void) {
    return lease_seconds;
}

static size_t build_packet(uint8_t *packet, uint8_t message_type, uint32_t identifier) {
    size_t offset = 236u; /* the mandatory option area starts here */

    packet[0] = 1u;  /* BOOTREQUEST */
    packet[1] = 1u;  /* Ethernet */
    packet[2] = 6u;  /* hardware address length */
    memset(packet + 4, 0, 12u); /* sname and file stay empty */
    memcpy(packet + 28, &transaction, 4u);
    net_write32(packet + 32, identifier);

    packet[offset++] = (uint8_t)DR1ZZLE_DHCP_OPTION_MESSAGE_TYPE;
    packet[offset++] = 1u;
    packet[offset++] = message_type;

    /* Client identifier, so the server can key its lease on something stable. */
    packet[offset++] = 61u;
    packet[offset++] = 7u;
    packet[offset++] = 1u;
    memcpy(packet + offset, drizzle_net_mac(), DR1ZZLE_MAC_LEN);
    offset += DR1ZZLE_MAC_LEN;

    /* Maximum message size; the stack never fragments, so be explicit. */
    packet[offset++] = 51u;
    packet[offset++] = 2u;
    net_write16(packet + offset, 1500u);
    offset += 2u;

    packet[offset++] = (uint8_t)DR1ZZLE_DHCP_OPTION_END;
    return offset;
}

static void send_discover(void) {
    uint8_t packet[DR1ZZLE_DHCP_PAYLOAD];
    uint8_t destination[4] = {255, 255, 255, 255};
    uint8_t hardware[DR1ZZLE_MAC_LEN];
    size_t length;

    transaction = next_transaction();
    length = build_packet(packet, (uint8_t)DR1ZZLE_DHCP_MESSAGE_DISCOVER, 0u);
    /* Broadcast: at this point we have no address and often no ARP entry. */
    (void)hardware;
    (void)destination;
    (void)drizzle_udp_send_v4(destination, DR1ZZLE_DHCP_SERVER_PORT, packet, length);
    last_sent_ms = (uint32_t)drizzle_time_ms();
    attempts++;
}

static void send_request(void) {
    uint8_t packet[DR1ZZLE_DHCP_PAYLOAD];
    uint8_t destination[4] = {255, 255, 255, 255};
    uint8_t requested[4];
    uint8_t zero[4] = {0, 0, 0, 0};
    size_t offset;
    size_t length;

    transaction = next_transaction();
    offset = build_packet(packet, (uint8_t)DR1ZZLE_DHCP_MESSAGE_REQUEST, 0u);

    /* Ask for the address that was offered; the server identifier is left
     * absent, which the RFC permits when the client cannot identify it. */
    packet[offset++] = 50u;
    packet[offset++] = 4u;
    net_write32(packet + offset, offered_address);
    offset += 4u;
    packet[offset++] = 54u;
    packet[offset++] = 4u;
    memcpy(packet + offset, zero, 4u);
    offset += 4u;
    packet[offset++] = (uint8_t)DR1ZZLE_DHCP_OPTION_END;

    length = offset;
    (void)requested;
    (void)drizzle_udp_send_v4(destination, DR1ZZLE_DHCP_SERVER_PORT, packet, length);
    last_sent_ms = (uint32_t)drizzle_time_ms();
    attempts++;
}

static void apply_lease(uint32_t address, uint32_t netmask, uint32_t gateway,
                        uint8_t (*dns)[4], unsigned dns_count) {
    uint8_t local[4];
    uint8_t mask[4];
    uint8_t route[4];

    net_write32(local, address);
    net_write32(mask, netmask);
    net_write32(route, gateway);
    drizzle_net_configure_v4(local, mask, route);

    if (dns_count > 0u) {
        drizzle_dns_init(dns[0] ? dns : NULL, dns_count);
    }
}

static void handle_offer(const uint8_t *message, size_t length) {
    uint32_t address = 0u;
    uint32_t netmask = 0u;
    uint32_t gateway = 0u;
    uint8_t dns[4][4];
    unsigned dns_count = 0u;
    uint32_t lease = 0u;

    if (!net_dhcp_decode(message, length, &address, &netmask, &gateway, dns, &dns_count,
                        &lease)) {
        return;
    }
    if (address == 0u) return;
    offered_address = address;
    lease_seconds = lease;
    state = DHCP_REQUESTING;
    attempts = 0u;
    send_request();
}

static void handle_ack(const uint8_t *message, size_t length) {
    uint32_t address = 0u;
    uint32_t netmask = 0u;
    uint32_t gateway = 0u;
    uint8_t dns[4][4];
    unsigned dns_count = 0u;
    uint32_t lease = 0u;

    if (!net_dhcp_decode(message, length, &address, &netmask, &gateway, dns, &dns_count,
                        &lease)) {
        return;
    }
    if (address == 0u) return;
    lease_seconds = lease;
    apply_lease(address, netmask, gateway, dns, dns_count);
    state = DHCP_BOUND;
}

void drizzle_dhcp_poll(void) {
    uint8_t buffer[600];
    drizzle_endpoint_t source;
    int got;
    uint32_t now = (uint32_t)drizzle_time_ms();

    if (state == DHCP_BOUND || state == DHCP_IDLE) return;

    while ((got = drizzle_udp_receive(DR1ZZLE_DHCP_CLIENT_PORT, buffer, sizeof buffer,
                                     &source)) >= 0) {
        uint8_t type = 0u;
        if ((size_t)got < 240u) continue;
        if (net_read32(buffer + 236u) != DR1ZZLE_DHCP_MAGIC) continue;
        {
            size_t offset = 240u;
            while (offset < (size_t)got) {
                uint8_t option = buffer[offset];
                uint8_t option_length;
                if (option == (uint8_t)DR1ZZLE_DHCP_OPTION_END) break;
                if (option == 0u) {
                    offset++;
                    continue; /* padding */
                }
                if (offset + 1u >= (size_t)got) break;
                option_length = buffer[offset + 1u];
                if (offset + 2u + option_length > (size_t)got) break;
                if (option == (uint8_t)DR1ZZLE_DHCP_OPTION_MESSAGE_TYPE && option_length >= 1u) {
                    type = buffer[offset + 2u];
                }
                offset += 2u + option_length;
            }
        }
        if (type == (uint8_t)DR1ZZLE_DHCP_MESSAGE_OFFER) {
            handle_offer(buffer, (size_t)got);
        } else if (type == (uint8_t)DR1ZZLE_DHCP_MESSAGE_ACK) {
            handle_ack(buffer, (size_t)got);
        }
    }

    if ((now - last_sent_ms) < DR1ZZLE_DHCP_RETRY_MS) return;
    if (attempts >= DR1ZZLE_DHCP_ATTEMPTS) return;

    if (state == DHCP_DISCOVERING) {
        send_discover();
    } else if (state == DHCP_REQUESTING) {
        send_request();
    }
}

int net_dhcp_decode(const uint8_t *message, size_t length, uint32_t *offered_address,
                    uint32_t *netmask, uint32_t *gateway, uint8_t (*dns)[4],
                    unsigned *dns_count, uint32_t *lease_seconds) {
    size_t offset;
    unsigned found_dns = 0u;

    if (length < 244u) return 0;
    if (net_read32(message + 236u) != DR1ZZLE_DHCP_MAGIC) return 0;

    if (offered_address) *offered_address = net_read32(message + 16);
    if (netmask) *netmask = 0u;
    if (gateway) *gateway = 0u;
    if (lease_seconds) *lease_seconds = 0u;
    if (dns_count) *dns_count = 0u;

    offset = 240u;
    while (offset + 1u < length) {
        uint8_t option = message[offset];
        uint8_t option_length;
        uint8_t index;

        if (option == (uint8_t)DR1ZZLE_DHCP_OPTION_END) break;
        if (option == 0u) {
            offset++;
            continue;
        }
        option_length = message[offset + 1u];
        if (offset + 2u + option_length > length) break;

        switch (option) {
            case DR1ZZLE_DHCP_OPTION_SUBNET:
                if (option_length == 4u && netmask) *netmask = net_read32(message + offset + 2u);
                break;
            case DR1ZZLE_DHCP_OPTION_ROUTER:
                if (option_length >= 4u && gateway) *gateway = net_read32(message + offset + 2u);
                break;
            case DR1ZZLE_DHCP_OPTION_LEASE:
                if (option_length == 4u && lease_seconds) {
                    *lease_seconds = net_read32(message + offset + 2u);
                }
                break;
            case DR1ZZLE_DHCP_OPTION_DNS:
                if (dns && dns_count) {
                    for (index = 0u; index < option_length && index + 3u < option_length;
                         index += 4u) {
                        if (found_dns >= 4u) break;
                        memcpy(dns[found_dns], message + offset + 2u + index, 4u);
                        found_dns++;
                    }
                    *dns_count = found_dns;
                }
                break;
            default:
                break;
        }
        offset += 2u + option_length;
    }

    /* A server is allowed to omit the subnet option; assume a class C default
     * rather than leaving the host unroutable. */
    if (netmask && *netmask == 0u) *netmask = 0xffffff00u;
    return 1;
}