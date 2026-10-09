#include "internal.h"
#include <string.h>
#include "drizzle/tcp.h"

/* TCP (RFC 9293).
 *
 * Single-threaded and non-blocking: every socket is advanced from
 * drizzle_tcp_poll(). The transmit buffer deliberately retains data until it is
 * acknowledged, which makes retransmission a matter of replaying from the front
 * of the buffer rather than keeping a separate segment log.
 *
 * Receive is strictly in order. An out-of-order segment is dropped and answered
 * with a cumulative ACK, which the peer's own retransmission recovers. That is
 * the right trade for a console workload and keeps the state machine small.
 */

#define DR1ZZLE_TCP_MAX_SOCKETS 6u
#define DR1ZZLE_TCP_BUFFER 1024u /* power of two */
#define DR1ZZLE_TCP_BUFFER_MASK (DR1ZZLE_TCP_BUFFER - 1u)
#define DR1ZZLE_TCP_MAX_DATA (DR1ZZLE_TCP_BUFFER - DR1ZZLE_TCP_HEADER)
#define DR1ZZLE_TCP_DEFAULT_MSS 1460u
#define DR1ZZLE_TCP_RTO_MIN_MS 200u
#define DR1ZZLE_TCP_RTO_MAX_MS 4000u
#define DR1ZZLE_TCP_TIME_WAIT_MS 1000u
#define DR1ZZLE_TCP_EPHEMERAL_FIRST 49152u

#define DR1ZZLE_TCP_FIN 0x01u
#define DR1ZZLE_TCP_SYN 0x02u
#define DR1ZZLE_TCP_RST 0x04u
#define DR1ZZLE_TCP_PSH 0x08u
#define DR1ZZLE_TCP_ACK 0x10u

typedef enum {
    TCP_CLOSED = 0,
    TCP_LISTEN,
    TCP_SYN_RCVD,
    TCP_ESTABLISHED,
    TCP_FIN_WAIT_1,
    TCP_FIN_WAIT_2,
    TCP_CLOSE_WAIT,
    TCP_LAST_ACK,
    TCP_TIME_WAIT
} tcp_state_t;

struct drizzle_socket {
    int in_use;
    int is_listener;
    unsigned backlog;
    struct drizzle_socket *parent;

    drizzle_endpoint_t local;
    drizzle_endpoint_t peer;
    tcp_state_t state;

    /* Transmit ring. Offsets are relative to tx_start: [0, tx_unacked) has been
     * sent and is waiting for an ACK, [tx_unacked, tx_count) has not been sent. */
    uint8_t tx[DR1ZZLE_TCP_BUFFER];
    uint16_t tx_start;
    uint16_t tx_count;
    uint16_t tx_unacked;

    uint8_t rx[DR1ZZLE_TCP_BUFFER];
    uint16_t rx_count;

    uint32_t snd_una;
    uint32_t snd_nxt;
    uint32_t rcv_nxt;
    uint16_t snd_wnd;
    uint16_t peer_mss;

    int fin_sent;
    int fin_acked;
    int peer_fin;
    int peer_eof_notified;

    uint32_t last_send_ms;
    uint32_t last_progress_ms;
    unsigned retransmit_count;
    uint32_t rto_ms;
};

static struct drizzle_socket sockets[DR1ZZLE_TCP_MAX_SOCKETS];
static uint16_t next_ephemeral = DR1ZZLE_TCP_EPHEMERAL_FIRST;
static uint32_t random_state = 0x2545f491u;

static uint32_t random_next(void) {
    /* xorshift32: enough to keep initial sequence numbers from repeating
     * across reboots of the same link. */
    random_state ^= random_state << 13;
    random_state ^= random_state >> 17;
    random_state ^= random_state << 5;
    return random_state;
}

static uint32_t new_sequence(void) {
    uint32_t sequence;
    uint32_t now = (uint32_t)drizzle_time_ms();
    if (random_state == 0x2545f491u) {
        random_state ^= now * 2654435761u;
        if (random_state == 0u) random_state = 1u;
    }
    sequence = random_next() + now;
    if (sequence == 0u) sequence = 1u;
    return sequence;
}

static uint16_t allocate_ephemeral_port(void) {
    uint16_t candidate = next_ephemeral;
    next_ephemeral++;
    if (next_ephemeral < DR1ZZLE_TCP_EPHEMERAL_FIRST ||
        next_ephemeral == (uint16_t)(DR1ZZLE_TCP_EPHEMERAL_FIRST + DR1ZZLE_TCP_MAX_SOCKETS)) {
        next_ephemeral = DR1ZZLE_TCP_EPHEMERAL_FIRST;
    }
    return candidate;
}

static struct drizzle_socket *socket_allocate(void) {
    size_t index;
    for (index = 0u; index < DR1ZZLE_TCP_MAX_SOCKETS; index++) {
        if (!sockets[index].in_use) {
            memset(&sockets[index], 0, sizeof sockets[index]);
            sockets[index].in_use = 1;
            sockets[index].state = TCP_CLOSED;
            sockets[index].peer_mss = DR1ZZLE_TCP_DEFAULT_MSS;
            sockets[index].snd_wnd = DR1ZZLE_TCP_DEFAULT_MSS;
            sockets[index].rto_ms = DR1ZZLE_TCP_RTO_MIN_MS;
            return &sockets[index];
        }
    }
    return NULL;
}

static void socket_release(struct drizzle_socket *socket) {
    memset(socket, 0, sizeof *socket);
}

static uint16_t tx_byte(const struct drizzle_socket *socket, uint16_t offset) {
    return socket->tx[(socket->tx_start + offset) & DR1ZZLE_TCP_BUFFER_MASK];
}

static uint8_t rx_byte(const struct drizzle_socket *socket, uint16_t offset) {
    return socket->rx[offset];
}

static size_t tx_push(struct drizzle_socket *socket, const uint8_t *data, size_t length) {
    size_t index;
    size_t space = DR1ZZLE_TCP_BUFFER - socket->tx_count;
    if (length > space) length = space;
    for (index = 0u; index < length; index++) {
        uint16_t position = (uint16_t)((socket->tx_start + socket->tx_count) &
                                       DR1ZZLE_TCP_BUFFER_MASK);
        socket->tx[position] = data[index];
        socket->tx_count++;
    }
    return length;
}

static size_t tx_consume(struct drizzle_socket *socket, uint32_t acknowledged) {
    /* Move the acknowledged prefix out of the ring. */
    uint32_t ahead = acknowledged - socket->snd_una;
    if ((int32_t)(ahead - socket->tx_unacked) > 0 || ahead > (uint32_t)socket->tx_count) {
        ahead = socket->tx_count;
    }
    socket->tx_start = (uint16_t)((socket->tx_start + ahead) & DR1ZZLE_TCP_BUFFER_MASK);
    socket->tx_count = (uint16_t)(socket->tx_count - ahead);
    if ((uint32_t)socket->tx_unacked > ahead) {
        socket->tx_unacked = (uint16_t)(socket->tx_unacked - ahead);
    } else {
        socket->tx_unacked = 0u;
    }
    socket->snd_una = (uint32_t)(socket->snd_una + ahead);
    return ahead;
}

static size_t rx_push(struct drizzle_socket *socket, const uint8_t *data, size_t length) {
    size_t index;
    size_t space = DR1ZZLE_TCP_BUFFER - socket->rx_count;
    if (length > space) length = space;
    for (index = 0u; index < length; index++) {
        socket->rx[socket->rx_count + index] = data[index];
    }
    socket->rx_count = (uint16_t)(socket->rx_count + length);
    return length;
}

static uint16_t advertise_window(const struct drizzle_socket *socket) {
    return (uint16_t)(DR1ZZLE_TCP_BUFFER - socket->rx_count);
}

static void transmit_segment(struct drizzle_socket *socket, uint8_t flags, uint32_t sequence,
                             uint32_t acknowledgement, const uint8_t *data, size_t length) {
    uint8_t segment[DR1ZZLE_TCP_HEADER + DR1ZZLE_TCP_MAX_DATA];
    const uint8_t *local_address;
    uint16_t checksum;

    if (length > DR1ZZLE_TCP_MAX_DATA) length = DR1ZZLE_TCP_MAX_DATA;

    net_write16(segment, socket->local.port);
    net_write16(segment + 2, socket->peer.port);
    net_write32(segment + 4, sequence);
    net_write32(segment + 8, acknowledgement);
    segment[12] = (uint8_t)((DR1ZZLE_TCP_HEADER / 4u) << 4);
    segment[13] = flags;
    net_write16(segment + 14, advertise_window(socket));
    net_write16(segment + 16, 0u);
    net_write16(segment + 18, 0u);
    if (length) memcpy(segment + DR1ZZLE_TCP_HEADER, data, length);

    local_address = (socket->local.family == DR1ZZLE_AF_INET6) ? drizzle_net_v6()
                                                                : drizzle_net_v4();
    checksum = net_transport_checksum(socket->local.family, local_address,
                                      socket->peer.address, (uint8_t)DR1ZZLE_IPPROTO_TCP,
                                      segment, DR1ZZLE_TCP_HEADER + length);
    if (checksum == 0u) checksum = 0xffffu;
    net_write16(segment + 16, checksum);

    socket->last_send_ms = (uint32_t)drizzle_time_ms();
    (void)net_ip_send(socket->local.family, &socket->peer, (uint8_t)DR1ZZLE_IPPROTO_TCP,
                      segment, DR1ZZLE_TCP_HEADER + length, 64u);
}

static void send_reset(const drizzle_endpoint_t *local, const drizzle_endpoint_t *peer,
                       uint32_t sequence, uint32_t acknowledgement, uint8_t flags) {
    uint8_t segment[DR1ZZLE_TCP_HEADER];
    const uint8_t *local_address;
    uint16_t checksum;
    uint8_t response_flags = (uint8_t)(DR1ZZLE_TCP_RST);

    /* A reset answering a reset stays silent, which is what keeps a refused
     * connection from turning into a reset storm. */
    if (flags & DR1ZZLE_TCP_RST) return;
    if (flags & DR1ZZLE_TCP_ACK) {
        response_flags |= DR1ZZLE_TCP_ACK;
    }

    net_write16(segment, local->port);
    net_write16(segment + 2, peer->port);
    net_write32(segment + 4, sequence);
    net_write32(segment + 8, acknowledgement);
    segment[12] = (uint8_t)((DR1ZZLE_TCP_HEADER / 4u) << 4);
    segment[13] = response_flags;
    net_write16(segment + 14, 0u);
    net_write16(segment + 16, 0u);
    net_write16(segment + 18, 0u);

    local_address = (local->family == DR1ZZLE_AF_INET6) ? drizzle_net_v6() : drizzle_net_v4();
    checksum = net_transport_checksum(local->family, local_address, peer->address,
                                      (uint8_t)DR1ZZLE_IPPROTO_TCP, segment,
                                      DR1ZZLE_TCP_HEADER);
    if (checksum == 0u) checksum = 0xffffu;
    net_write16(segment + 16, checksum);

    (void)net_ip_send(local->family, peer, (uint8_t)DR1ZZLE_IPPROTO_TCP, segment,
                      DR1ZZLE_TCP_HEADER, 64u);
}

/* Sends whatever the peer is willing to take, oldest first. */
static void pump_transmit(struct drizzle_socket *socket) {
    while (socket->tx_unacked < socket->tx_count && !socket->fin_sent) {
        size_t pending = (size_t)(socket->tx_count - socket->tx_unacked);
        size_t chunk = pending;
        size_t index;
        uint8_t block[DR1ZZLE_TCP_MAX_DATA];

        if ((uint32_t)chunk > socket->snd_wnd) chunk = socket->snd_wnd;
        if ((uint32_t)chunk > socket->peer_mss) chunk = socket->peer_mss;
        if (chunk == 0u) break;

        for (index = 0u; index < chunk; index++) {
            block[index] = (uint8_t)tx_byte(socket, (uint16_t)(socket->tx_unacked + index));
        }
        transmit_segment(socket, (uint8_t)(DR1ZZLE_TCP_ACK | DR1ZZLE_TCP_PSH),
                         (uint32_t)(socket->snd_una + socket->tx_unacked), socket->rcv_nxt,
                         block, chunk);
        socket->snd_nxt = (uint32_t)(socket->snd_nxt + chunk);
        socket->tx_unacked = (uint16_t)(socket->tx_unacked + chunk);
        socket->retransmit_count = 0u;
        socket->rto_ms = DR1ZZLE_TCP_RTO_MIN_MS;
    }

    /* Close only after everything written has been acknowledged, so a FIN never
     * overtakes data still in flight. */
    if (!socket->fin_sent && socket->tx_unacked == socket->tx_count &&
        (socket->state == TCP_ESTABLISHED || socket->state == TCP_CLOSE_WAIT)) {
        transmit_segment(socket, (uint8_t)(DR1ZZLE_TCP_ACK | DR1ZZLE_TCP_FIN),
                         socket->snd_nxt, socket->rcv_nxt, NULL, 0u);
        socket->snd_nxt = (uint32_t)(socket->snd_nxt + 1u);
        socket->fin_sent = 1;
        socket->retransmit_count = 0u;
        socket->rto_ms = DR1ZZLE_TCP_RTO_MIN_MS;
        socket->state = (socket->state == TCP_ESTABLISHED) ? TCP_FIN_WAIT_1
                                                           : TCP_LAST_ACK;
    }
}

/* Retransmits the oldest unacknowledged segment. */
static void retransmit_oldest(struct drizzle_socket *socket) {
    uint8_t block[DR1ZZLE_TCP_MAX_DATA];
    size_t outstanding = (size_t)(socket->tx_count - socket->tx_unacked);
    size_t index;

    if (outstanding > 0u) {
        size_t chunk = outstanding;
        if ((uint32_t)chunk > socket->peer_mss) chunk = socket->peer_mss;
        for (index = 0u; index < chunk; index++) {
            block[index] = (uint8_t)tx_byte(socket, (uint16_t)index);
        }
        transmit_segment(socket, (uint8_t)(DR1ZZLE_TCP_ACK | DR1ZZLE_TCP_PSH), socket->snd_una,
                         socket->rcv_nxt, block, chunk);
    } else if (socket->fin_sent && !socket->fin_acked) {
        transmit_segment(socket, (uint8_t)(DR1ZZLE_TCP_ACK | DR1ZZLE_TCP_FIN),
                         socket->snd_nxt - 1u, socket->rcv_nxt, NULL, 0u);
    }
}

static struct drizzle_socket *find_listening(const drizzle_endpoint_t *destination,
                                             drizzle_family_t family) {
    size_t index;
    for (index = 0u; index < DR1ZZLE_TCP_MAX_SOCKETS; index++) {
        struct drizzle_socket *socket = &sockets[index];
        if (!socket->in_use || !socket->is_listener) continue;
        if (socket->local.port != destination->port) continue;
        if (socket->local.family != family && socket->local.family != DR1ZZLE_AF_UNSPEC) {
            continue;
        }
        return socket;
    }
    return NULL;
}

static struct drizzle_socket *find_connected(const drizzle_endpoint_t *source,
                                             const drizzle_endpoint_t *destination,
                                             drizzle_family_t family, int include_syn) {
    size_t index;
    for (index = 0u; index < DR1ZZLE_TCP_MAX_SOCKETS; index++) {
        struct drizzle_socket *socket = &sockets[index];
        if (!socket->in_use || socket->is_listener) continue;
        if (socket->state == TCP_CLOSED) continue;
        if (!include_syn && socket->state != TCP_ESTABLISHED &&
            socket->state != TCP_CLOSE_WAIT && socket->state != TCP_FIN_WAIT_1 &&
            socket->state != TCP_FIN_WAIT_2 && socket->state != TCP_LAST_ACK) {
            continue;
        }
        if (socket->local.port != destination->port) continue;
        if (!drizzle_endpoint_equal(&socket->peer, source)) continue;
        if (family == DR1ZZLE_AF_INET6 && socket->local.family != DR1ZZLE_AF_INET6) continue;
        return socket;
    }
    return NULL;
}

static unsigned pending_backlog(const struct drizzle_socket *listener) {
    unsigned count = 0u;
    size_t index;
    for (index = 0u; index < DR1ZZLE_TCP_MAX_SOCKETS; index++) {
        if (sockets[index].in_use && sockets[index].parent == listener &&
            sockets[index].state != TCP_CLOSED) {
            count++;
        }
    }
    return count;
}

void drizzle_tcp_input(const drizzle_endpoint_t *source, const drizzle_endpoint_t *destination,
                       const uint8_t *payload, size_t length) {
    uint16_t destination_port;
    uint16_t source_port;
    uint32_t sequence;
    uint32_t acknowledgement;
    uint8_t flags;
    size_t header_length;
    size_t body_length;
    uint8_t flags_out;
    uint32_t now = (uint32_t)drizzle_time_ms();
    struct drizzle_socket *socket;
    struct drizzle_socket *listener;
    const uint8_t *local_address;

    if (length < DR1ZZLE_TCP_HEADER) {
        drizzle_net_count_drop();
        return;
    }
    destination_port = net_read16(payload);
    source_port = net_read16(payload + 2);
    sequence = net_read32(payload + 4);
    acknowledgement = net_read32(payload + 8);
    header_length = (size_t)(payload[12] >> 4) * 4u;
    flags = (uint8_t)(payload[13] & 0x3fu);

    if (header_length < DR1ZZLE_TCP_HEADER || header_length > length) {
        drizzle_net_count_drop();
        return;
    }
    if (net_read16(payload + 16) != 0u) {
        local_address = (destination->family == DR1ZZLE_AF_INET6) ? drizzle_net_v6()
                                                                  : drizzle_net_v4();
        if (net_transport_checksum(destination->family, source->address, local_address,
                                   (uint8_t)DR1ZZLE_IPPROTO_TCP, payload, length) != 0u) {
            drizzle_net_count_drop();
            return;
        }
    }

    socket = find_connected(source, destination, destination->family, 1);

    if (!socket) {
        if (!(flags & DR1ZZLE_TCP_SYN)) {
            /* Nothing is listening on that port sequence: answer with a reset
             * so the peer fails fast instead of retransmitting a SYN. */
            send_reset(destination, source, 0u, (uint32_t)(sequence + 1u), flags);
            return;
        }
        listener = find_listening(destination, destination->family);
        if (!listener) {
            send_reset(destination, source, 0u, (uint32_t)(sequence + 1u), flags);
            return;
        }
        if (pending_backlog(listener) >= listener->backlog) {
            send_reset(destination, source, 0u, (uint32_t)(sequence + 1u), flags);
            return;
        }
        socket = socket_allocate();
        if (!socket) {
            send_reset(destination, source, 0u, (uint32_t)(sequence + 1u), flags);
            return;
        }
        socket->parent = listener;
        socket->local = *destination;
        socket->peer = *source;
        socket->state = TCP_SYN_RCVD;
        socket->snd_una = new_sequence();
        socket->snd_nxt = socket->snd_una;
        socket->rcv_nxt = (uint32_t)(sequence + 1u);
        socket->last_progress_ms = now;

        /* Honour the peer's advertised window from the SYN. */
        socket->snd_wnd = net_read16(payload + 14);
        if (socket->snd_wnd == 0u) socket->snd_wnd = DR1ZZLE_TCP_DEFAULT_MSS;
        if (header_length > DR1ZZLE_TCP_HEADER) {
            size_t option = DR1ZZLE_TCP_HEADER;
            while (option + 1u < header_length) {
                uint8_t kind = payload[option];
                uint8_t option_length = payload[option + 1u];
                if (option_length < 2u || option + option_length > header_length) break;
                if (kind == 2u && option_length == 4u) {
                    uint16_t mss = net_read16(payload + option + 2u);
                    socket->peer_mss = mss < 32u ? 32u : mss;
                }
                option += option_length;
            }
        }

        transmit_segment(socket, (uint8_t)(DR1ZZLE_TCP_SYN | DR1ZZLE_TCP_ACK), socket->snd_nxt,
                         socket->rcv_nxt, NULL, 0u);
        socket->snd_nxt = (uint32_t)(socket->snd_nxt + 1u);
        socket->snd_una = (uint32_t)(socket->snd_una + 1u);
        return;
    }

    /* ---- established-ish socket ---- */
    if (flags & DR1ZZLE_TCP_RST) {
        socket_release(socket);
        return;
    }

    if (flags & DR1ZZLE_TCP_ACK) {
        if ((int32_t)(acknowledgement - socket->snd_nxt) > 0) {
            /* Acknowledges something we never sent. */
            send_reset(destination, source, socket->snd_nxt, acknowledgement, flags);
            socket_release(socket);
            return;
        }
        tx_consume(socket, acknowledgement);
        if (socket->fin_sent && (uint32_t)(acknowledgement - socket->snd_nxt) >= 1u) {
            socket->fin_acked = 1;
        }
        socket->retransmit_count = 0u;
        socket->rto_ms = DR1ZZLE_TCP_RTO_MIN_MS;
        socket->last_progress_ms = now;
    }

    if (socket->state == TCP_SYN_RCVD && (flags & DR1ZZLE_TCP_ACK) &&
        acknowledgement == socket->snd_nxt) {
        socket->state = TCP_ESTABLISHED;
    }

    /* Track the peer's window. */
    {
        uint16_t window = net_read16(payload + 14);
        if ((flags & DR1ZZLE_TCP_SYN) == 0u) socket->snd_wnd = window;
    }

    /* Payload, in order only. */
    body_length = length - header_length;
    if (body_length > 0u) {
        if (sequence == socket->rcv_nxt) {
            size_t accepted = rx_push(socket, payload + header_length, body_length);
            socket->rcv_nxt = (uint32_t)(socket->rcv_nxt + accepted);
            socket->last_progress_ms = now;
        }
        /* Out-of-order or duplicate: fall through and acknowledge, letting the
         * peer's retransmission fill the gap. */
    }

    if (flags & DR1ZZLE_TCP_FIN) {
        if (sequence + body_length == socket->rcv_nxt) {
            socket->rcv_nxt = (uint32_t)(socket->rcv_nxt + 1u);
        }
        socket->peer_fin = 1;
        socket->last_progress_ms = now;
        if (socket->state == TCP_ESTABLISHED) socket->state = TCP_CLOSE_WAIT;
        else if (socket->state == TCP_FIN_WAIT_1 && socket->fin_acked) {
            socket->state = TCP_TIME_WAIT;
            socket->last_progress_ms = now;
        } else if (socket->state == TCP_FIN_WAIT_2) {
            socket->state = TCP_TIME_WAIT;
            socket->last_progress_ms = now;
        }
    }

    /* Always acknowledge what we have accepted. */
    flags_out = (uint8_t)DR1ZZLE_TCP_ACK;
    if (socket->state == TCP_SYN_RCVD) flags_out = (uint8_t)(DR1ZZLE_TCP_SYN | DR1ZZLE_TCP_ACK);
    if (body_length > 0u && sequence == socket->rcv_nxt) {
        flags_out = (uint8_t)(DR1ZZLE_TCP_ACK | DR1ZZLE_TCP_PSH);
    }
    if (flags_out & DR1ZZLE_TCP_SYN) {
        transmit_segment(socket, flags_out, socket->snd_nxt, socket->rcv_nxt, NULL, 0u);
    } else {
        transmit_segment(socket, flags_out, socket->snd_nxt, socket->rcv_nxt, NULL, 0u);
    }

    pump_transmit(socket);
}

void drizzle_tcp_poll(void) {
    size_t index;
    uint32_t now = (uint32_t)drizzle_time_ms();

    for (index = 0u; index < DR1ZZLE_TCP_MAX_SOCKETS; index++) {
        struct drizzle_socket *socket = &sockets[index];
        if (!socket->in_use) continue;

        switch (socket->state) {
            case TCP_CLOSED:
                socket_release(socket);
                continue;
            case TCP_LISTEN:
                continue;
            case TCP_TIME_WAIT:
                if ((now - socket->last_progress_ms) >= DR1ZZLE_TCP_TIME_WAIT_MS) {
                    socket_release(socket);
                }
                continue;
            default:
                break;
        }

        if (socket->state == TCP_SYN_RCVD && socket->parent) {
            /* A half-open handshake that the peer never finished. */
            if ((now - socket->last_progress_ms) >= (DR1ZZLE_TCP_RTO_MIN_MS * 8u)) {
                socket_release(socket);
            }
            continue;
        }

        pump_transmit(socket);

        if (socket->tx_unacked > 0u || (socket->fin_sent && !socket->fin_acked)) {
            if ((now - socket->last_send_ms) >= socket->rto_ms) {
                socket->retransmit_count++;
                if (socket->retransmit_count > 6u) {
                    /* The peer is gone. */
                    socket_release(socket);
                    continue;
                }
                socket->rto_ms *= 2u;
                if (socket->rto_ms > DR1ZZLE_TCP_RTO_MAX_MS) {
                    socket->rto_ms = DR1ZZLE_TCP_RTO_MAX_MS;
                }
                socket->last_send_ms = now;
                retransmit_oldest(socket);
            }
        }
    }
}

drizzle_socket_t *drizzle_tcp_listen(uint16_t port, unsigned backlog) {
    struct drizzle_socket *socket = socket_allocate();
    if (!socket) return NULL;
    socket->is_listener = 1;
    socket->backlog = backlog ? backlog : DR1ZZLE_TCP_DEFAULT_BACKLOG;
    socket->local.family = DR1ZZLE_AF_UNSPEC; /* accepts both families */
    socket->local.port = port;
    socket->peer.port = 0u;
    socket->state = TCP_LISTEN;
    return socket;
}

drizzle_socket_t *drizzle_tcp_accept(drizzle_socket_t *listener) {
    size_t index;
    for (index = 0u; index < DR1ZZLE_TCP_MAX_SOCKETS; index++) {
        struct drizzle_socket *candidate = &sockets[index];
        if (!candidate->in_use || candidate->parent != listener) continue;
        if (candidate->state == TCP_SYN_RCVD || candidate->state == TCP_ESTABLISHED) {
            candidate->parent = NULL;
            return candidate;
        }
    }
    return NULL;
}

int drizzle_tcp_send(drizzle_socket_t *socket, const uint8_t *data, size_t length) {
    if (!socket || !socket->in_use || socket->is_listener) return -1;
    if (socket->state != TCP_ESTABLISHED && socket->state != TCP_CLOSE_WAIT) return -1;
    if (socket->peer_fin) return -1;
    {
        size_t accepted = tx_push(socket, data, length);
        pump_transmit(socket);
        return (int)accepted;
    }
}

int drizzle_tcp_receive(drizzle_socket_t *socket, uint8_t *buffer, size_t capacity) {
    size_t index;
    size_t count;
    if (!socket || !socket->in_use || socket->is_listener) return -1;
    if (socket->rx_count == 0u) return -1;
    count = socket->rx_count;
    if (count > capacity) count = capacity;
    for (index = 0u; index < count; index++) {
        buffer[index] = rx_byte(socket, (uint16_t)index);
    }
    if (count == socket->rx_count) {
        socket->rx_count = 0u;
    } else {
        memmove(socket->rx, socket->rx + count, (size_t)socket->rx_count - count);
        socket->rx_count = (uint16_t)(socket->rx_count - count);
    }
    /* Draining the receive buffer frees window for the peer. */
    transmit_segment(socket, (uint8_t)DR1ZZLE_TCP_ACK, socket->snd_nxt, socket->rcv_nxt, NULL,
                     0u);
    return (int)count;
}

int drizzle_tcp_eof(drizzle_socket_t *socket) {
    if (!socket || !socket->in_use) return 0;
    return socket->peer_fin ? 1 : 0;
}

int drizzle_tcp_close(drizzle_socket_t *socket) {
    if (!socket || !socket->in_use) return -1;
    if (socket->is_listener) {
        socket_release(socket);
        return 0;
    }
    if (socket->state == TCP_ESTABLISHED || socket->state == TCP_SYN_RCVD ||
        socket->state == TCP_CLOSE_WAIT) {
        socket->last_progress_ms = (uint32_t)drizzle_time_ms();
        if (socket->state == TCP_ESTABLISHED) {
            pump_transmit(socket);
            socket->state = TCP_FIN_WAIT_1;
        } else {
            transmit_segment(socket, (uint8_t)(DR1ZZLE_TCP_RST | DR1ZZLE_TCP_ACK),
                             socket->snd_nxt, socket->rcv_nxt, NULL, 0u);
            socket_release(socket);
        }
        return 0;
    }
    socket_release(socket);
    return 0;
}

const drizzle_endpoint_t *drizzle_tcp_local(const drizzle_socket_t *socket) {
    return socket ? &socket->local : NULL;
}

const drizzle_endpoint_t *drizzle_tcp_peer(const drizzle_socket_t *socket) {
    return socket ? &socket->peer : NULL;
}

drizzle_family_t drizzle_tcp_family(const drizzle_socket_t *socket) {
    return socket ? socket->local.family : DR1ZZLE_AF_UNSPEC;
}

size_t drizzle_tcp_pending(const drizzle_socket_t *socket) {
    if (!socket) return 0u;
    return (size_t)(socket->tx_count - socket->tx_unacked);
}

void drizzle_tcp_discard(const drizzle_endpoint_t *source) {
    size_t index;
    for (index = 0u; index < DR1ZZLE_TCP_MAX_SOCKETS; index++) {
        struct drizzle_socket *socket = &sockets[index];
        if (!socket->in_use || socket->is_listener) continue;
        if (drizzle_endpoint_equal(&socket->peer, source)) socket_release(socket);
    }
}

void drizzle_tcp_reset(void) {
    memset(sockets, 0, sizeof sockets);
}