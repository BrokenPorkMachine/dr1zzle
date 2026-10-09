#include "internal.h"
#include <string.h>

/* ARP (RFC 826) for IPv4 next-hop resolution. */

#define DR1ZZLE_HTYPE_ETHER 1u
#define DR1ZZLE_PTYPE_IPV4 0x0800u

#define DR1ZZLE_ARP_OP_REQUEST 1u
#define DR1ZZLE_ARP_OP_REPLY 2u

#define DR1ZZLE_ARP_HEADER 28u

static int is_broadcast_mac(const uint8_t hardware[DR1ZZLE_MAC_LEN]) {
    size_t index;
    for (index = 0u; index < DR1ZZLE_MAC_LEN; index++) {
        if (hardware[index] != 0xffu) return 0;
    }
    return 1;
}

void net_arp_request(const uint8_t *target) {
    static const uint8_t broadcast_mac[DR1ZZLE_MAC_LEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    const uint8_t zero_mac[DR1ZZLE_MAC_LEN] = {0, 0, 0, 0, 0, 0};
    uint8_t packet[DR1ZZLE_ARP_HEADER];
    const uint8_t *local = drizzle_net_mac();

    net_write16(packet, (uint16_t)DR1ZZLE_HTYPE_ETHER);
    net_write16(packet + 2, (uint16_t)DR1ZZLE_PTYPE_IPV4);
    packet[4] = DR1ZZLE_MAC_LEN;
    packet[5] = 4u;
    net_write16(packet + 6, (uint16_t)DR1ZZLE_ARP_OP_REQUEST);
    memcpy(packet + 8, local, DR1ZZLE_MAC_LEN);
    memcpy(packet + 14, drizzle_net_v4(), 4u);
    memcpy(packet + 18, zero_mac, DR1ZZLE_MAC_LEN);
    memcpy(packet + 24, target, 4u);

    net_link_send(broadcast_mac, local, (uint16_t)DR1ZZLE_ETHERTYPE_ARP, packet,
                  sizeof packet);
}

void net_arp_input(const uint8_t *payload, size_t length) {
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint16_t operation;
    const uint8_t *sender_hardware;
    const uint8_t *sender_protocol;

    if (length < DR1ZZLE_ARP_HEADER) {
        drizzle_net_count_drop();
        return;
    }
    hardware_type = net_read16(payload);
    protocol_type = net_read16(payload + 2);
    operation = net_read16(payload + 6);
    sender_hardware = payload + 8;
    sender_protocol = payload + 14;

    if (hardware_type != DR1ZZLE_HTYPE_ETHER || protocol_type != DR1ZZLE_PTYPE_IPV4) {
        drizzle_net_count_drop();
        return;
    }
    if (is_broadcast_mac(sender_hardware)) {
        /* Broadcast senders are only meaningful inside a request. */
        if (operation != DR1ZZLE_ARP_OP_REQUEST) return;
    }

    net_neighbor_learn(DR1ZZLE_AF_INET, sender_protocol, sender_hardware);

    if (operation == DR1ZZLE_ARP_OP_REQUEST) {
        const uint8_t *target_protocol = payload + 24;
        const uint8_t *target_hardware = payload + 18;
        const uint8_t *local = drizzle_net_mac();
        uint8_t reply[DR1ZZLE_ARP_HEADER];

        if (!drizzle_net_has_v4()) return;
        if (memcmp(target_protocol, drizzle_net_v4(), 4u) != 0) return;

        net_write16(reply, (uint16_t)DR1ZZLE_HTYPE_ETHER);
        net_write16(reply + 2, (uint16_t)DR1ZZLE_PTYPE_IPV4);
        reply[4] = DR1ZZLE_MAC_LEN;
        reply[5] = 4u;
        net_write16(reply + 6, (uint16_t)DR1ZZLE_ARP_OP_REPLY);
        memcpy(reply + 8, local, DR1ZZLE_MAC_LEN);
        memcpy(reply + 14, drizzle_net_v4(), 4u);
        memcpy(reply + 18, target_hardware, DR1ZZLE_MAC_LEN);
        memcpy(reply + 24, sender_protocol, 4u);

        net_link_send(target_hardware, local, (uint16_t)DR1ZZLE_ETHERTYPE_ARP, reply,
                      sizeof reply);
    }
}