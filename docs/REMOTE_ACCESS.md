# Remote access boundary

> **Superseded by [SSH_SCP_443.md](SSH_SCP_443.md).** This file is retained as
> the record of the boundary as it stood when it was written, and because every
> gap it names is now specified. Read the new document for the actual design.

The portable TCP stack is ready for a server to bind a listening socket, but
this tree does **not** contain an SSH/SCP implementation. SSH-2 is an encrypted
protocol, not a line-oriented shell: it needs a host-key store, key exchange,
cipher and MAC/AEAD implementations, user authentication, channel flow
control, and an SCP/SFTP file service. Sending a password or shell text over a
plain TCP socket would expose credentials and would not be compatible with
OpenSSH, so dr1zzle deliberately does not ship such a substitute.

To finish SSH/SCP on a real target, the next integration point is a server
around `drizzle_tcp.h` with these explicit callbacks:

- persistent host-key loading and signature;
- entropy/randomness and the selected KEX/cipher/HMAC algorithms;
- an authenticated account policy;
- a bounded session channel connected to the monitor console; and
- a file provider with path, size, and write limits for SCP/SFTP.

The QEMU profile currently exposes only a PL011 console and no virtio-net
device, so end-to-end SSH/SCP verification requires either a network-capable
QEMU board profile or an A11 transport backend. Until those exist, claiming
that `ssh` or `scp` works would be false.

That statement is still true. What changed is that the design it was waiting
on now exists: [SSH_SCP_443.md](SSH_SCP_443.md) specifies the transport, the
algorithm sets, the primitives required, the file service and the
implementation order, and [SPEC.md](../SPEC.md) §8 places it in the whole. The
boundary is now a schedule rather than a mystery.
