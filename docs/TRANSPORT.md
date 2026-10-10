# Transport: links, TCP, and the dump stream scheduler

This document specifies how bytes leave the device. It is the layer that
"stream all dumps over TCP/IP, either Wi-Fi or over USB" actually means in
code, and it is deliberately separate from what is being streamed
([DUMP_WIRE_FORMAT.md](DUMP_WIRE_FORMAT.md)) and from the remote-access
protocol layered on top of it ([SSH_SCP_443.md](SSH_SCP_443.md)).

## 1. Link abstraction

Two links exist on this platform and neither of them is guaranteed to be up.
USB CDC-ECM is the one that can be verified without A11 silicon work; the
Wi-Fi radio is a BCM4357 behind an Apple PCIe/UART transport that this tree
does not yet have a validated backend for
([WIFI.md](WIFI.md)).

Everything above the link speaks Ethernet frames and knows nothing about
which link is carrying them.

```c
typedef struct drizzle_link {
    const char *name;        /* "usb-cdc-ecm", "wifi-bcm4357", "qemu-virtio" */
    int      (*up)(void);
    int      (*send_frame)(const uint8_t *frame, uint16_t len);
    uint16_t (*mtu)(void);   /* payload bytes per frame, excluding headers */
    void     (*poll)(void);  /* RX drain and TX completion, cooperative */
    uint32_t flags;
} drizzle_link_t;

#define LINK_FLAG_POINT_TO_POINT 0x1  /* no ARP needed, peer MAC fixed   */
#define LINK_FLAG_SECRET_OK      0x2  /* allowed to carry secret sources  */
```

Rules:

- `link_send_frame()` dispatches to the active link. There is exactly one
  active link at a time unless the operator has opened a second session on a
  different link, in which case each session is pinned to the link it arrived
  on (see §4).
- `net_send_frame()` in `src/net/tcp.c` becomes a thin call into
  `link_send_frame()`. Nothing else in the stack changes.
- RX is always `link->poll()` driven: the link pushes frames up through
  `net_recv_frame()`. Today `src/drivers/cdc_ecm.c` receives frames and
  `net/tcp.c` never sees them; that wiring is the first item of work here,
  not a new design.
- A link that reports `up() == 0` is not selected. Link selection never
  guesses: `auto` picks the first registered link that is up, in registration
  order, and says which one it picked.

### 1.1 USB CDC-ECM

| Property | Value | Status |
|---|---|---|
| Interface | DWC2 device, CDC-ECM, bulk IN/OUT 512 B | implemented, unverified |
| Endpoints | EP0 control, EP1 interrupt IN, EP2 bulk IN/OUT | implemented |
| Address | 192.168.42.1/24, peer 192.168.42.2 | implemented (static) |
| Link flags | point-to-point | spec |
| Throughput | ~492 B per segment, see §3 | measured only on QEMU |

### 1.2 Wi-Fi (BCM4357)

The radio identity is established from public device-tree evidence; the
transport is not. The spec for this link is therefore a contract, not an
implementation: a backend that satisfies `drizzle_link_t` and drives
`wifi_state()` in `include/wifi.h` through `READY` → `ASSOCIATED` is all the
stack needs. Until such a backend exists, `transport link wifi` fails with a
named reason and `auto` stays on USB.

## 2. Interface addressing

Both links are static-addressed. There is no DHCP client and no router: the
peer is the host on the other end of the cable or the access point's
infrastructure.

| Link | Device | Peer | Notes |
|---|---|---|---|
| USB CDC-ECM | 192.168.42.1/24 | 192.168.42.2 | as today |
| Wi-Fi | 192.168.43.1/24 | 192.168.43.254 (AP) | distinct subnet, see below |

`transport address <link> <ip> <prefix>` overrides either. The subnets must
not overlap: the ARP cache in `src/net/tcp.c` is keyed by IPv4 address and
shared by all links, so a second link reusing 192.168.42.0/24 would resolve
the peer's MAC from the wrong link's cache and send frames into the wrong
radio.

## 3. TCP requirements for bulk transfer

`src/net/tcp.c` today is stop-and-wait: one unacknowledged window per socket,
resent on a 500 ms timer, `MAX_PACKET 512`, `TX_BUF 2048`, `RX_BUF 2048`,
`MAX_SOCKETS 4`, fixed `INITIAL_SEQ 0x1000`.

That is adequate for a shell and inadequate for a 128 MB NAND dump. The
arithmetic, which the spec treats as an acceptance criterion rather than a
hope:

- one segment is 492 payload bytes (`MAX_PACKET 512` minus headers);
- stop-and-wait means one segment per round trip;
- on the USB link a round trip is far below 1 ms, so the link, not the
  protocol, is the limit — but on Wi-Fi with a 5-20 ms RTT the protocol
  becomes the limit, and 20 ms per 492 bytes is 24 KB/s, which is 90 minutes
  for 128 MB.

Required changes, in the order they are worth doing:

1. **Windowed sender.** `snd_una`/`snd_nxt` already exist; add a window of at
   least 8 segments and send up to the peer's advertised window instead of
   waiting for `unacked == 0`. Retransmission stays RTO-based and per-segment,
   so a single lost segment does not restart the window.
2. **Larger segments.** CDC-ECM bulk MPS is 512, so an Ethernet frame is at
   most ~512 bytes including headers; the segment size is bounded by the
   link, not by `MAX_PACKET`. Wi-Fi allows 1500-byte MTU and should use it.
3. **Nagle off, delayed ACK off.** The stack currently piggybacks ACKs on
   data and sends pure ACKs on receive; a bulk stream wants one ACK per two
   segments at most. Anything else halves throughput against a delayed-ACK
   peer.
4. **Per-socket buffers sized for streaming, not for typing.** A dump stream
   needs at least one 16 KiB read-ahead; four sockets at 16 KiB is 64 KiB of
   SRAM, which is affordable against a 1.9 MB SRAM but must be accounted for
   explicitly (see SPEC.md §10).

The alternative — leaving the stack alone and pushing everything over SCP
with a byte-counted transfer — is not an alternative: SCP *is* TCP here.

## 4. Which link carries a dump

Three cases, and the spec picks one behaviour for each rather than exposing
a preference matrix:

| Case | Behaviour |
|---|---|
| One link up | That link. |
| Control session over SSH on link A, dump issued in that session | Link A. The session is pinned; a dump that silently jumped links would appear on a firewall the operator is not looking at. |
| Dump issued from the UART console with both links up | `auto`: the link with the higher measured goodput over the last 30 s, defaulting to USB on a tie. |

`transport link <name>` forces a link and overrides all of the above until
cleared with `transport link auto`. `dump stream <target> --link <name>`
forces it for one transfer only.

Goodput is measured, not assumed: the TCP layer counts payload bytes and
segments retransmitted per link, and `transport status` prints both. A link
that is up but retransmitting everything is not the "faster" link.

## 5. The stream scheduler

A dump is a long operation inside a cooperative single-threaded monitor. The
rules that keep it from breaking everything else:

- **Never block.** `dump stream` starts a job and returns to the shell. The
  job is a state machine advanced from `net_poll()`, which the main loop
  already calls between commands.
- **Chunk at a time.** One chunk (default 4096 B, max 16384 B) is copied out
  of the source and handed to `tcp_send()` per poll. If `tcp_send()` accepts
  fewer bytes than offered, the job records the shortfall and does not
  advance; TCP backpressure is the only flow control this needs.
- **Respect the peer.** A stream aborts if the socket goes away
  (`on_close`), if the retry counter is exhausted, or on an explicit abort
  record from the control channel. Partial state is reported, not hidden:
  the trailer's completion code names which of those happened.
- **The console stays live.** Sink selection means the same chunk is printed
  as hex to the invoking console and/or written to the socket. The hex path
  is capped at `DUMP_MAX_LENGTH` per command as today; the binary path is not
  capped the same way, because it never lands in a terminal.
- **One stream per link.** Concurrent streams on a single point-to-point link
  interleave and both slow down; a second request is refused with a reason
  rather than silently queued.

## 6. Ports

| Port | Service | Default |
|---|---|---|
| 443 | SSH-2 (transport, connection, sftp/scp) | on, when a link is up |
| 23 | legacy plaintext TCP console | off |

Port 23 is not "also on". A plaintext line protocol that dumps memory and
takes `memwrite` must not be reachable from a network that has a router in
it. It stays available for the case where SSH bring-up has failed and the
operator has already got physical access — which is also the case where they
have the UART. `transport legacy-console on` exists for that debugging
scenario, prints a warning naming the exposure, and is not sticky across
reboot.

`transport ports` prints the listeners, their ports, and the link each is
bound to. `ssh port <n>` moves the SSH listener, and refuses a port below
1024 other than 443 with a reason.

## 7. Interfaces, in build order

```
src/net/tcp.c       windowed sender, larger segments, per-link counters
src/net/link.c      link registry, selection, dispatch
src/net/stream.c    the dump-stream job state machine
include/net.h       extended API (below)
```

```c
int          link_register(const drizzle_link_t *link);
int          link_select(const char *name);        /* "auto" or a link name */
const char  *link_active_name(void);
void         link_send_frame(const uint8_t *frame, uint16_t len);

/* Dump-stream jobs. A job id is returned; 0 means refused. */
unsigned     stream_start(unsigned source_id, unsigned chunk);
int          stream_abort(unsigned job_id);
void         stream_poll(void);                    /* called from net_poll() */
void         stream_report(void);                  /* shell: stream status */

/* Per-link counters, for goodput and for `transport status`. */
uint64_t     link_bytes_sent(const char *name);
uint64_t     link_bytes_recv(const char *name);
uint32_t     link_retransmits(const char *name);
```

## 8. Status of this document

Everything in §1, §2, §5, §6 and §7 is specification: the interfaces named do
not all exist yet. §1.1 describes code that exists and is unverified on
silicon. §1.2 and §3 name work that is not started. The honest summary is in
[SPEC.md](../SPEC.md) §12 and [TASK_STATUS.md](TASK_STATUS.md).
