# The goatloader server

`dr1zzle` runs one TCP service, and it is on before the shell starts.

```
  device 192.168.123.10 : 1234     (goatloader, always on)
```

The address and the port are both pre-configured constants
(`include/net.h`, `include/goat/loader.h`), and `goat/cli.py` defaults to the
same two numbers. Nothing is negotiated: there is no DHCP client on this link,
so the two sides agree by construction and a remote side does not need to be
told anything.

```
  goat push payload.img4 --key-hex ...     stages a sealed container
  goat push payload.img4 --key-hex ... --run
  goat shell                                drives the monitor console
  ssh/scp: not offered by this build        see docs/REMOTE_ACCESS.md
```

## Why it cannot be turned off

The listener is the transport the rest of the features hang off:

| Feature | What it needs from the server |
|---|---|
| `goat push` | `KEY`, `PUSH` |
| `goat shell` | the shell passthrough |
| `goat run` / a launched payload | `RUN`, and the staged container |

So it is bound during bring-up, before `shell_run()` is reached, and there is
no interface that stops it:

- `goatloader_stop()` returns `-1` and prints why. It is a refusal, not a switch.
- `goatloader_poll()` re-creates the listener on every pass. This stack turns
  the listening socket itself into the first connection, so adopting a session
  would otherwise leave the payload unbound; the re-arm is the same code path
  as the initial bind.
- The `server` shell command reports state. `server off` (and `stop`,
  `disable`, `down`, `kill`) is answered with the reason, not with a stop.
- Disabling the listener is a build change, not a runtime one.

Rationale: a service that other features depend on must not be switchable from
a console whose operator may not know that. The cost of that is real — see
Exposure below — and it is called out rather than hidden behind a flag nobody
would look at.

## The address

`NET_DEFAULT_IPV4` is `192.168.123.10` with a `/24` and gateway `192.168.123.1`. The connected host acts as the gateway for TCP/IP over USB. `net_configure_static()` installs it during bring-up, so the
stack answers ARP for the address from the first frame rather than after
something asks.

`tests/test_goatloader.py` reads the constant and `goat/cli.py`'s default and
fails when they drift, because nothing else in the build would notice.

## The protocol

One ASCII line per request; a reply is one line. Requests are `GOAT/1 <verb>
[args]`; replies start `GOAT/1 OK` / `GOAT/1 RUN` / `GOAT/1 ERR`, so the host
tool can branch on a prefix check. Anything that does not start with the tag is
run as a shell command, so a human on a socket can type `help`.

| Request | Reply | Notes |
|---|---|---|
| `GOAT/1 HELLO client=...` | `OK hello device=dr1zzle-goatloader/1 ip=... port=...` | names the address it was reached on |
| `GOAT/1 KEY <64 hex>` | `OK key=32` / `ERR key=...` | the AES key the container is sealed with |
| `GOAT/1 PUSH <n>` then *n* raw bytes | `OK stage len=... loadBase=... subject=... verify=ok` / `ERR stage=parse|verify` | the only binary in the protocol |
| `GOAT/1 RUN` | `RUN loadBase=... entry=...` then enters | every refusal names itself: `no-key`, `no-stage`, `verify`, `decrypt` |
| `GOAT/1 ABORT` | `OK aborted` | drops the staged container |
| `GOAT/1 STATUS` | `OK active=1 sessions=... staged=... key=... pushed=... entered=...` | `active` is `1` because that is the contract |
| `GOAT/1 BYE` | `OK bye` | closes the session |
| anything else | command output | the monitor console, same commands as UART |

Order matters and is enforced in that order: parse, then verify, then — only
with both passing and a key in hand — decrypt. `goat_verify()` checks the
container certificate's own signature and then the container signature against
the key the certificate vouches for, so an unsigned container is never staged
and never decryptable. `RUN` verifies again rather than trusting the staged
record, because the record is RAM and a fault between the two commands is
exactly the case where re-checking costs one signature and saves an image.

The reply to `RUN` is queued before `goat_enter()` is called. Once the payload
is entered there is no loop left to service the transmit queue, so the host
tool would otherwise wait on a line that never came.

## What it does not do

No authentication. This is a plaintext line protocol on a point-to-point link
(one host, one device, no router), which is why it is acceptable here and would
not be on a routable subnet. `SPEC.md` §7.4 keeps the legacy port-23 console off
for the same reason, and §8.7 names the exposure when a routable link is
attached: when Wi-Fi is up, this is a network service with a shell on it.

No file service. `docs/REMOTE_ACCESS.md` records what an OpenSSH-compatible
server would need; it is not in this tree, and this server does not pretend to
be one.

## Where it runs

Nothing in the loader blocks, and nothing in it runs in an interrupt. The
bulk-OUT path assembles Ethernet frames and buffers them (`cdc_ecm.c`); the
shell's idle loop calls `net_poll()` and `goatloader_poll()`, and *that* is
where frames become network events. Keeping the stack single-threaded is what
lets it use static segment buffers.

```c
    while (1) {
        net_poll();          /* buffers -> stack -> transmit queue */
        goatloader_poll();   /* accept, service, reply */
        int c = uart_getc();
        ...
    }
```

## Testing

- `make loader-test` — the protocol state machine on the host, driven through
  `goatloader_poll()` against a fake socket, plus the device/host agreement
  checks.
- `python3 tests/test_hw.py` — bring-up ordering: the address is configured,
  the listener is bound before the shell, and the port still matches the host
  tool.

Neither runs the protocol over a real link: the payload has not been run on
silicon, and `docs/TASK_STATUS.md` says so.

## Files

| Path | What |
|---|---|
| `include/goat/loader.h` | the interface, the port, the reply contract |
| `src/goat/loader.c` | the state machine and the protocol |
| `include/net.h`, `src/net/tcp.c` | the pre-configured static address |
| `src/drivers/cdc_ecm.c` | frame assembly and the transmit queue |
| `src/shell/shell.c` | `shell_exec()`, the `server` command, the idle loop |
| `goat/cli.py` | the host side: `goat push`, `goat shell` |
