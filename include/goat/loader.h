#ifndef GOAT_LOADER_H
#define GOAT_LOADER_H

#include <stddef.h>
#include <stdint.h>

/* dr1zzle goatloader: the payload's TCP server.
 *
 * ---------------------------------------------------------------------------
 * Why this is always on
 * ---------------------------------------------------------------------------
 *
 * The goatloader is not a convenience service, it is the transport the rest
 * of the features hang off:
 *
 *   goat push   seals an image on the host and stages it on the device
 *   goat shell  drives the monitor console from a normal terminal
 *   goat run    hands the device to the image that was just staged
 *
 * All three are a TCP conversation with this listener. If it is not bound,
 * the host tool has nothing to talk to and the sealed-container flow -- the
 * one path a plain `goat push` takes end to end -- is unreachable. So the
 * listener is created during bring-up, before the shell starts, and there is
 * deliberately no interface that stops it: `goatloader_stop()` is a refusal,
 * not a switch, and `goatloader_poll()` re-arms the listener if it ever goes
 * away. Turning it off would be a build change, not a runtime one.
 *
 * The pre-configured static address is what makes the remote side easy: the
 * host tool defaults to 192.168.42.1:1234 (goat/cli.py), the device defaults
 * to the same address, and neither needs DHCP, a route, or a configuration
 * step. See net.h for the address itself and docs/GOATLOADER.md for the
 * whole contract.
 *
 * Wire format: one ASCII line per request, '\n' terminated. A PUSH announces
 * a length and then sends exactly that many raw bytes; the reply still comes
 * back as a line. Replies start with "GOAT/1 OK" or "GOAT/1 ERR" so the host
 * tool can branch on a prefix check.
 */

/* Listener port. Must stay equal to GOATLOADER_PORT in goat/cli.py; there is
 * a host test that reads both and fails when they drift. */
#define GOATLOADER_PORT 1234u

/* One listening socket plus this many concurrent sessions. The stack has four
 * sockets altogether (src/net/tcp.c, MAX_SOCKETS), so one listener and three
 * sessions is the whole budget. */
#define GOATLOADER_MAX_SESSIONS 3u

/* Line buffer for one request. A shell command typed by a human is the
 * longest thing that arrives here; anything longer is refused rather than
 * silently truncated. */
#define GOATLOADER_LINE_MAX 96u

/* Reply ceiling, including the bytes captured from a shell command's output.
 * Shell output past this point is truncated and the reply still terminates. */
#define GOATLOADER_REPLY_MAX 512u

/* Protocol tag. Requests are "GOAT/1 <verb> [args]". */
#define GOATLOADER_PROTO "GOAT/1"

/* Bind the listener. Safe to call once; returns 0 when bound and -1 when the
 * stack could not allocate a socket, which poll() retries on its own. */
int goatloader_init(void);

/* Accept pending connections, service live ones, queue replies. Call this
 * from the main loop; it never blocks and never waits on the network. */
void goatloader_poll(void);

/* True after init(). Always: this is the "cannot be turned off" contract in
 * one call, so the shell can report it honestly instead of lying. */
int goatloader_active(void);

/* Live sessions, for status output. */
unsigned goatloader_sessions(void);

/* Shell status output. */
void goatloader_report(void);

/* Refuses. Returns -1 always, and prints why: there is no code path that
 * closes the listener, so a caller asking for "off" is a bug or a
 * misunderstanding, not a preference to honour. */
int goatloader_stop(void);

/* Where pushed containers are staged. The payload points this at the SRAM
 * tail (GOAT_STAGE_BASE); a host test points it at a plain buffer. Call
 * before the first PUSH, or use the default. */
void goatloader_set_stage(uint8_t *base, uint32_t capacity);

#endif /* GOAT_LOADER_H */
