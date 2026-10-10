# Remote access: SSH-2, SFTP and SCP on TCP 443

This document specifies dr1zzle's remote-access server. It supersedes the
boundary description in [REMOTE_ACCESS.md](REMOTE_ACCESS.md), which recorded
what SSH would *require* without specifying it; this is the specification.

Nothing here is implemented yet. §9 lists the work in dependency order.

---

## 1. What is being built

An OpenSSH-compatible SSH-2 server, small enough to run on this payload, that
exposes:

1. a **session channel** wired to the existing monitor command loop, so an
   SSH shell and the UART shell are the same shell with a different sink;
2. an **SFTP v3 subsystem** and a **legacy SCP path**, both backed by the
   dump registry, so a firmware or memory image is `scp`'d off like a file;
3. an **audit line** recording who pulled what and when, because a shell that
   can read all of DRAM is worth logging.

It listens on TCP 443, on any link that is up ([TRANSPORT.md](TRANSPORT.md)).

---

## 2. Port 443

One TCP listener per up link, bound to 0.0.0.0 on that link's address. Port
443 is chosen for two reasons and the second one is not cosmetic:

- **It survives egress filtering.** A host network that passes HTTPS passes
  TCP 443. The operator reads a register without negotiating firewall policy.
- **It makes the legacy console unnecessary.** With SSH on 443, the plaintext
  console on port 23 has no reason to be enabled by default, and is not
  ([TRANSPORT.md](TRANSPORT.md) §6).

Port 443 carries SSH directly. There is no TLS record layer underneath, and
there is no HTTP/HTTPS multiplexing: a probe of port 443 gets an SSH banner,
not a TLS ClientHello. That is the honest behaviour — TLS under SSH here would
add a certificate store and a second trust anchor to solve a problem SSH
already solves.

Client invocations:

```bash
ssh -p 443 operator@192.168.42.1
sftp -P 443 operator@192.168.42.1
scp -P 443 operator@192.168.42.1:/securerom.bin .
scp -P 443 -O operator@192.168.42.1:/securerom.bin .   # legacy protocol
```

---

## 3. Algorithm sets

Negotiation follows RFC 4253 §7.1: each side sends name-lists in its
preference order, and the first client entry the server also supports is
selected. An empty intersection is fatal, with
`SSH_MSG_DISCONNECT_KEY_EXCHANGE_FAILED`. There is no downgrade path and no
`-o` fallback list on the device; a client that cannot negotiate gets
disconnected and told why.

| Message | Server offers, in order |
|---|---|
| `kex_algorithms` | `curve25519-sha256`, `curve25519-sha256@libssh.org` |
| `server_host_key_algorithms` | `ssh-ed25519`, `rsa-sha2-512` |
| `encryption_algorithms` (c2s) | `chacha20-poly1305@openssh.com`, `aes128-ctr` |
| `encryption_algorithms` (s2c) | `chacha20-poly1305@openssh.com`, `aes128-ctr` |
| `mac_algorithms` | (implicit under AEAD), `hmac-sha2-256` |
| `compression_algorithms` | `none` |

Only `curve25519-sha256` is required of the client in practice: OpenSSH has
had it since 6.5 and it is the default. `aes128-ctr` + `hmac-sha2-256` is the
fallback for older and embedded clients and costs an AES encrypt key
schedule that `goat` does not currently have (§6).

`rsa-sha2-512` is listed but is **not** part of the first cut. Signing with
RSA needs a private-key modexp and `goat_rsa` is verify-only by design; the
host key is Ed25519 unless and until that changes.

---

## 4. Wire protocol

This section is the part that has to be exactly right, so the requirements
are stated as rules rather than prose.

### 4.1 Binary packet protocol (RFC 4253 §6)

```
uint32    packet_length          (length of padding_length + payload + padding)
byte      padding_length
byte[packet_length]  payload
byte[pad]  random padding
```

- `packet_length` excludes itself and includes `padding_length`.
- Total packet on the wire is `packet_length + 4` bytes.
- Padding is at least 4 bytes, and the total (excluding the MAC) must be a
  multiple of the cipher block size, or 8 for a stream cipher.
- `packet_length` is capped. This payload has 74 KiB of new SRAM budget
  ([SPEC.md](../SPEC.md) §10), so the receive bound is **32 KiB** — larger
  packets are a fatal `SSH_MSG_DISCONNECT_PROTOCOL_ERROR` rather than a
  slow allocation. OpenSSH's default maximum is 32 KiB anyway.
- Sequence numbers are per direction, start at 0, and increment by exactly
  1 per packet. They are folded into the MAC input, so a reordered or
  replayed packet fails the MAC on the next packet, not on this one.

### 4.2 State machine

```
BANNER EXCHANGE → KEXINIT → KEY EXCHANGE → NEWKEYS → EXT INFO?
                                                        ↓
                                        SERVICE REQUEST (ssh-userauth)
                                                        ↓
                                        USERAUTH REQUEST → SUCCESS / FAIL
                                                        ↓
                                        CONNECTION OPEN → channels
```

- The version banner is `SSH-2.0-dr1zzle_2.0`, sent immediately on
  connect, with the trailing `\r\n` optional on both sides.
- `SSH_MSG_KEXINIT` carries the algorithm lists of §3 and a cookie. The
  cookie is 16 random bytes and must differ per connection: a constant
  cookie makes the exchange trivially replayable.
- `SSH_MSG_NEWKEYS` marks the point where subsequent packets use the new
  keys. Keys are derived per RFC 4253 §7.2 from the shared secret `K`, the
  exchange hash `H`, and the session identifier, with IVs A and B and the
  six keys `K1..K6`. Deriving fewer than the negotiated algorithms need is a
  decryption failure, not a warning.
- Before `NEWKEYS`, packets are plaintext with no MAC. After it, every
  packet must carry a MAC or be an AEAD-protected packet.

### 4.3 Key exchange: `curve25519-sha256`

1. Client sends `SSH_MSG_KEX_ECDH_INIT` with a 32-byte ephemeral public key.
2. Server sends `SSH_MSG_KEX_ECDH_REPLY` with: the host key blob, the
   server's 32-byte ephemeral public key, and the signature over `H`.
3. `H` is SHA-256 over, in order: `V_C`, `V_S`, `I_C`, `I_S`, `K_S` (host key
   blob), `e` (client ephemeral, as an SSH string), `f` (server ephemeral),
   and `K` (the shared secret as an SSH **mpint**, which means it may carry a
   leading zero byte when the top bit is set — this is the single most common
   source of KEX interop bugs and it is called out here for that reason).

X25519 is implemented per RFC 7748 with the clamped scalar and the basepoint
`u = 9`. All-zero output is rejected as a small-subgroup result.

### 4.4 Signature: `ssh-ed25519`

Host key blob is `string "ssh-ed25519"` followed by `string pk`. The
signature field is `string "ssh-ed25519"` followed by `string sig`, over the
raw 64-byte Ed25519 signature, verified per RFC 8032 with SHA-512.

SHA-512 is **not** in this tree — `goat` provides SHA-256 only. It is the
first dependency to write (§9).

### 4.5 Ciphers

- **`chacha20-poly1305@openssh.com`** — AEAD. Key 32 bytes, two ChaCha20
  keys derived from the SSH key material (one per direction), each with its
  own Poly1305 key. The packet is
  `encrypt(payload || padding_length_byte || padding)` where the length field
  itself stays in the clear. Nonce is a 64-bit big-endian sequence number
  with an 8-byte zero prefix, and the AAD is the 4-byte length field. This is
  a different construction from RFC 8439 and must not be copied from it
  wholesale.
- **`aes128-ctr` + `hmac-sha2-256`** — separate cipher and MAC, MAC computed
  over the sequence number and the *ciphertext*. Requires an AES encrypt
  schedule, which `goat_aes` does not provide.

---

## 5. User authentication

`SSH_MSG_USERAUTH_REQUEST` with service `ssh-connection`:

| Method | Behaviour |
|---|---|
| `none` | always `FAIL`. Never a success, even with no auth configured — a method that succeeds before the client proves anything is a hole, not a convenience. |
| `publickey` | accepted. Ed25519 always; RSA-SHA2-512 when `goat_rsa` gains signing. `publickey` queries (signature flag false) are answered without demanding a signature, so a client can probe the key list. |
| `password` | off by default. `ssh allow-password on` enables it for the single `operator` account. |

Rules:

- Max 6 failed attempts per connection, then `DISCONNECT` with reason
  `too many authentication failures`. No backoff sleep — the payload has one
  thread and sleeping on a failed login is a denial of service on itself.
- Account list is exactly one entry, `operator`, with no password unless set.
  There is no root account and no way to add one.
- `authorized_keys` is baked at build time, or provisioned over the **UART
  console only** with `ssh authorized-add <key>`. Provisioning over the
  network means whoever is on the network can add themselves.
- Every successful authentication is written to the audit line: key
  fingerprint, link, peer address, timestamp.

---

## 6. Crypto primitives

What this tree has, what it needs, and what it costs.

| Primitive | In `goat` today | Required work |
|---|---|---|
| SHA-256 | yes | — |
| HMAC-SHA-256 | derived from SHA-256 | ~40 lines (inner/outer pad, `goat_sha256_update`) |
| SHA-512 | **no** | ~150 lines, same structure as SHA-256 with different constants and 80 rounds |
| X25519 | **no** | ~350 lines: 255-bit field arithmetic plus the Montgomery ladder, constant-time-ish |
| Ed25519 | **no** | ~600 lines: point arithmetic, encode/decode, sign, verify |
| ChaCha20 | **no** | ~120 lines: quarter round, 20 rounds, counter block |
| Poly1305 | **no** | ~150 lines: 130-bit accumulate, `r`/`s` clamping |
| AES-128 encrypt + CTR | decrypt-only, CBC-only | ~100 lines: forward key schedule plus the counter mode |

Total: roughly 1,500 lines of freestanding C, all of it host-testable against
published vectors, none of it dependent on A11 silicon. RFC vectors to test
against:

| Primitive | Reference vectors |
|---|---|
| X25519 | RFC 7748 §6.1 |
| Ed25519 | RFC 8032 §7.1 (test 1..3 plus the edge cases) |
| ChaCha20 | RFC 8439 §2.4.2 |
| Poly1305 | RFC 8439 §2.5.2 |
| HMAC-SHA-256 | RFC 4231 test case 1..2 |

Two properties the implementations must have and that are easy to skip:

- **No secret-dependent branches in the scalar arithmetic.** X25519 and
  Ed25519 both do table lookups and conditional swaps; a timing leak in the
  host key is a host key that can be extracted by a client that can measure
  the link. Constant-time conditional swap is the whole point of the ladder
  formulation.
- **No heap allocation during KEX.** All state is statically sized, because a
  failed allocation halfway through an exchange is a disconnect that looks
  like a network problem.

---

## 7. Connection protocol, channels, and the file service

### 7.1 Channels

`SSH_MSG_CHANNEL_OPEN` of type `session` is the only type offered. A
`direct-tcpip` or `forwarded-tcpip` request is refused with
`SSH_MSG_CHANNEL_FAILURE` — forwarding a port into the device would turn a
diagnostic instrument into a router.

Two concurrent channels maximum, bounded by the four-socket TCP table. Channel
requests:

| Request | Behaviour |
|---|---|
| `pty-req` | Accepted and ignored: there is no terminal emulator here. The reply is success so OpenSSH clients do not refuse to continue. |
| `shell` | Binds the channel to `execute()` via a console sink. Same command loop as UART. |
| `exec <command>` | Runs one command, then channel EOF and close. Used by `scp` and by `dr1zzle-host pull`. |
| `subsystem <name>` | `sftp` enters the file service; anything else fails. |
| `env` | Ignored. |
| `window-change`, `signal` | Ignored. |

Window management is real and must be implemented: `SSH_MSG_CHANNEL_WINDOW_ADJUST`
credits are what pace a 128 MB transfer, and an implementation that ignores
them will be killed by the peer's window going to zero.

### 7.2 SFTP v3

`subsystem sftp`, packet types per draft-ietf-secsh-filexfer-02. Supported:
`INIT`/`VERSION`, `REALPATH`, `STAT`/`LSTAT`, `OPEN`, `READ`, `CLOSE`,
`OPENDIR`/`READDIR`/`CLOSE_DIR`. Unsupported: `WRITE`, `SETSTAT`, `REMOVE`,
`RENAME`, `MKDIR`, `SYMLINK`, `LINK` — the registry is read-only, and the
answer is `SSH_FX_OP_UNSUPPORTED` with a message, not a silent no-op.

Registry layout exposed to SFTP:

```
/securerom.bin        1048576
/sram.bin              1972224
/dram.bin           2147483648
/nand.bin             geometry-dependent
/nand/<block>.bin
/apfs/<path>          when APFS extraction is available
/regs.bin                  832        the DZREGS1 record
/audit.log                 text
```

`READ` is served by the same chunker as the raw stream path, so a pull is
resumable by reopening and reading from the offset reached.

### 7.3 Legacy SCP

Driven from `exec` channels with the reference implementation's protocol:

- `scp -f <path>` — device sends size, then the bytes, then a single `\0`
  status byte.
- `scp -t <path>` — device receives. **Refused.** There is no upload path:
  a device that accepts files is a device that can be reflashed over the
  network, and that is not a capability this spec grants.

Newer OpenSSH defaults to SFTP for `scp`, so this path exists for `scp -O`
and for scripts that shell out to the old protocol.

### 7.4 Audit

One append-only text line per significant event: authentication, command,
stream start, stream completion, refused secret access, link change. Bounded
to the last 4 KiB so it can be read with `ssh audit` and pulled over SFTP as
`/audit.log`, and it does not grow without limit.

---

## 8. Integration with the payload

```
link up
   └── listener :443 (tcp_listen)
          └── ssh_connection  (banner, KEX, NEWKEYS, userauth)
                 └── session channel
                        ├── shell    → console sink → execute()
                        ├── exec     → execute() once, EOF
                        └── sftp     → dump registry (read-only)
```

Three integration points, and each one is small because the architecture
already supports it:

1. **The console sink.** `include/console.h` already has
   `console_bind_net(console_sink_t)`. The SSH shell channel installs a sink
   that writes SSH channel data. No command code changes.
2. **The source registry.** `dump_source_t` already has a read callback. The
   SFTP `READ` path calls it with an offset and a length, which is the same
   signature the chunker uses.
3. **The TCP stack.** `tcp_listen()` exists. The listener, the accept path
   and the poll scheduler are the only new transport code.

The one place that is *not* already supported is the shell's input path:
`shell_run()` reads from `uart_getc()` directly. A session channel needs the
same loop fed from a socket, so `execute()` is separated from the read loop
and the read loop becomes a per-console input source. This is the only
refactor of existing code this document requires, and it is a small one.

---

## 9. Implementation order

Blocks are ordered by dependency, not by size.

| # | Block | Depends on | Testable on host |
|---:|-------|-----------|------------------|
| 1 | SHA-512, HMAC-SHA-256 | — | yes, vectors |
| 2 | ChaCha20, Poly1305 | — | yes, vectors |
| 3 | X25519 | — | yes, RFC 7748 |
| 4 | Ed25519 (needs SHA-512) | 1 | yes, RFC 8032 |
| 5 | AES-128 encrypt + CTR | — | yes, NIST vectors |
| 6 | Binary packet framing + state machine | — | yes, captured traces |
| 7 | KEX + NEWKEYS + key derivation | 1,2,3,4 | yes, against OpenSSH on the host |
| 8 | Userauth (publickey) | 4, 6 | yes |
| 9 | Connection protocol + session channel | 6 | needs the console refactor |
| 10 | SFTP v3 over the registry | 9 | yes, against `sftp` on the host |
| 11 | Legacy SCP | 9 | yes, against `scp -O` |
| 12 | Audit | 9 | — |
| 13 | Listener wiring, link selection | TRANSPORT.md | needs a link |

Blocks 1-8 and 10-11 are host-testable with no A11 silicon and no QEMU
network device, which is why they come first. Block 13 is the only one that
needs a link, and it needs one anyway for `dump stream`.

The largest single risk is block 7: key derivation and the `mpint` encoding of
the shared secret are where interop failures happen, and they fail in a way
that looks like "the connection dropped" rather than "my KEX is wrong". The
mitigation is to test against OpenSSH on the host with full `-vvv` logging
before any of it runs on the device.

---

## 10. Status

**Specified, not implemented.** The repository contains no SSH code today;
[REMOTE_ACCESS.md](REMOTE_ACCESS.md) recorded that accurately before this
document existed and is retained for the history. The honest claim is that
the protocol is specified here in enough detail to implement and to test, and
that the primitives in §6 are not written yet.
