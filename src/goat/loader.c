/* The goatloader server: one listener, a handful of sessions, a line protocol.
 *
 * ---------------------------------------------------------------------------
 * Shape of the thing
 * ---------------------------------------------------------------------------
 *
 * Everything arrives as bytes on a TCP socket and everything leaves the same
 * way, so the only interesting parts are (a) turning a byte stream back into
 * requests and (b) keeping the state a request needs between requests. Those
 * are the two things below.
 *
 * A request is one ASCII line. The exception is PUSH, which is the only
 * binary in the protocol: it announces a length and the container bytes
 * follow, and the reply is still a line. Reassembling that is what the blob
 * state in `session_t` is for -- without it, a container that happens to
 * contain '\n' would be parsed as a dozen commands.
 *
 * Per-session state is deliberately thin: the AES key and the staged
 * container are payload-wide, not per-session. One operator, one key, one
 * image in flight. That is the documented model in goat.h, not an accident.
 *
 * ---------------------------------------------------------------------------
 * Where it runs
 * ---------------------------------------------------------------------------
 *
 * Nothing here blocks and nothing here is called from an interrupt. The
 * bulk-OUT path buffers whole frames and the main loop hands them to the
 * stack (see cdc_ecm.c), which is what keeps the stack's static segment
 * buffers single-owner. This function is the main loop's half of that deal.
 */

#include "goat/loader.h"
#include "goat/goat.h"
#include "goat/aes.h"
#include "memory_map.h"
#include "firmware.h"
#include "net.h"
#include "usb.h"
#include "uart.h"
#include "shell.h"
#include "string.h"
#include "util.h"

/* --- per-session --------------------------------------------------------- */

typedef struct {
    tcp_socket_t *socket;
    int           in_use;
    char          line[GOATLOADER_LINE_MAX];
    size_t        line_len;
    int           line_dropped;   /* over-long line in progress */
    size_t        blob_left;      /* container bytes still owed after PUSH */
    size_t        blob_got;
} session_t;

typedef struct {
    char   text[GOATLOADER_REPLY_MAX];
    size_t len;
} reply_t;

static session_t sessions[GOATLOADER_MAX_SESSIONS];
static tcp_socket_t *listener;

/* Staging window. Defaults to the SRAM tail; a host test points it at a plain
 * buffer so the same code runs on a machine with no A11 in it. */
static uint8_t *stage;
static uint32_t stage_capacity;

static goat_container_t staged;
static int have_staged;
static uint8_t pending_key[GOAT_AES_KEY_SIZE];
static int have_key;

static uint64_t stat_pushed;
static uint64_t stat_entered;
static uint64_t stat_installed;
static uint64_t stat_refused;
static uint64_t stat_commands;

/* --- reply helpers ------------------------------------------------------- */

static void reply_reset(reply_t *reply) {
    reply->text[0] = 0;
    reply->len = 0;
}

static void reply_add(reply_t *reply, const char *text) {
    while (*text && reply->len + 1u < sizeof reply->text) {
        reply->text[reply->len++] = *text++;
    }
    reply->text[reply->len] = 0;
}

static void reply_add_uint(reply_t *reply, uint64_t value) {
    reply_add(reply, utoa(value));
}

static void reply_add_hex(reply_t *reply, uint64_t value) {
    reply_add(reply, "0x");
    reply_add(reply, utoa_hex(value));
}

static void reply_add_address(reply_t *reply, uint32_t address) {
    reply_add_uint(reply, (address >> 24) & 0xffu); reply_add(reply, ".");
    reply_add_uint(reply, (address >> 16) & 0xffu); reply_add(reply, ".");
    reply_add_uint(reply, (address >> 8) & 0xffu);  reply_add(reply, ".");
    reply_add_uint(reply, address & 0xffu);
}

static void reply_send(session_t *session, reply_t *reply) {
    if (!session->socket || !reply->len) return;
    (void)tcp_send(session->socket, (const uint8_t *)reply->text,
                   (uint16_t)reply->len);
}

/* --- text helpers -------------------------------------------------------- */

static int is_space(char c) { return c == ' ' || c == '\t'; }

/* strncmp is not declared by this tree's string.h, and what it would do here
 * is three lines long. Keeping it local also keeps the loader's dependency
 * list short, which is part of what lets it be tested on the host. */
static int starts_with(const char *text, const char *prefix) {
    while (*prefix) {
        if (*text++ != *prefix++) return 0;
    }
    return 1;
}

/* Splits off the next blank-delimited token, NUL-terminating in place. */
static char *token(char **cursor) {
    char *at = *cursor;
    char *start;
    while (is_space(*at)) at++;
    if (!*at) { *cursor = at; return 0; }
    start = at;
    while (*at && !is_space(*at)) at++;
    if (*at) *at++ = 0;
    *cursor = at;
    return start;
}

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int parse_hex_bytes(const char *text, uint8_t *out, size_t expect) {
    size_t length = strlen(text);
    size_t index;
    if (length != expect * 2u) return -1;
    for (index = 0; index < expect; index++) {
        int hi = hex_nibble(text[index * 2u]);
        int lo = hex_nibble(text[index * 2u + 1u]);
        if (hi < 0 || lo < 0) return -1;
        out[index] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

static int parse_count(const char *text, uint64_t *out) {
    uint64_t value = 0;
    int digits = 0;
    const char *at;
    for (at = text; *at; at++) {
        if (*at < '0' || *at > '9') return -1;
        value = value * 10u + (uint64_t)(*at - '0');
        digits = 1;
        if (value > 0xffffffffULL) return -1;
    }
    if (!digits) return -1;
    *out = value;
    return 0;
}

static void trim_tail(char *text) {
    size_t length = strlen(text);
    while (length && is_space(text[length - 1u])) text[--length] = 0;
}

/* --- shell passthrough --------------------------------------------------- */

static reply_t *capture_target;

static void capture_line(const uint8_t *data, size_t len) {
    reply_t *reply = capture_target;
    size_t room;
    size_t index;
    if (!reply) return;
    room = sizeof reply->text - 1u - reply->len;
    if (len > room) len = room;
    for (index = 0; index < len; index++) {
        reply->text[reply->len++] = (char)data[index];
    }
    reply->text[reply->len] = 0;
}

static void run_shell(reply_t *reply, const char *line) {
    capture_target = reply;
    uart_capture_begin(capture_line);
    shell_exec(line);
    uart_capture_end();
    capture_target = 0;
    stat_commands++;
    /* A command that prints nothing still has to answer, or the client is
     * left waiting on a reply that never comes. */
    if (reply->len == 0) reply_add(reply, "ok\n");
}

/* --- container staging --------------------------------------------------- */

/* --- container staging --------------------------------------------------- */

/* The container names where its plaintext should be decrypted to, and that
 * destination has to land inside the staging window. goat_decrypt() bounds the
 * far end of SRAM but not this end, and the region below the window is the
 * payload's own heap and stack: a container that asked for it would be
 * overwriting the code that is decrypting it. Stated here because this is the
 * one place that knows both numbers. */
static int placement_ok(const goat_container_t *c) {
    uint64_t base = (uint64_t)(uintptr_t)stage;
    uint64_t limit = base + stage_capacity;
    if (c->load_base < base) return 0;
    if (c->load_base + c->cipher_len > limit) return 0;
    return 1;
}

static void finish_push(session_t *session, reply_t *reply) {
    goat_container_t parsed;
    size_t length = session->blob_got;

    session->blob_left = 0;
    session->blob_got = 0;

    /* Placement before anything else: a container that asked to be decrypted
     * on top of the running payload is refused for that reason alone, even if
     * every later check would have passed. */
    if (goat_parse(stage, (uint32_t)length, &parsed) != 0) {
        stat_refused++;
        have_staged = 0;
        goat_staged_container = 0;
        reply_add(reply, GOATLOADER_PROTO " ERR stage=parse\n");
        return;
    }
    if (!placement_ok(&parsed)) {
        stat_refused++;
        have_staged = 0;
        goat_staged_container = 0;
        reply_add(reply, GOATLOADER_PROTO " ERR stage=placement\n");
        return;
    }
    /* Verification is the gate: goat_verify() checks the certificate's own
     * signature and then the container signature against the key the
     * certificate vouches for. An unsigned or wrongly signed container is
     * staged but never decryptable, so refusing here is the same thing as
     * refusing later -- it is just earlier, and with a reason. */
    if (goat_verify(&parsed) != 0) {
        stat_refused++;
        have_staged = 0;
        goat_staged_container = 0;
        reply_add(reply, GOATLOADER_PROTO " ERR stage=verify\n");
        return;
    }

    staged = parsed;
    have_staged = 1;
    goat_staged_container = stage;
    stat_pushed++;

    reply_add(reply, GOATLOADER_PROTO " OK stage len=");
    reply_add_uint(reply, (uint64_t)length);
    reply_add(reply, " loadBase=");
    reply_add_hex(reply, staged.load_base);
    reply_add(reply, " entryOff=");
    reply_add_hex(reply, staged.entry_off);
    reply_add(reply, " subject=");
    {
        char name[GOATLOADER_LINE_MAX];
        uint32_t keep = staged.subject_len;
        if (keep > sizeof name - 1u) keep = (uint32_t)sizeof name - 1u;
        for (uint32_t i = 0; i < keep; i++) name[i] = (char)staged.subject[i];
        name[keep] = 0;
        reply_add(reply, name);
    }
    reply_add(reply, " verify=ok\n");

    /* The serial log is the audit trail for what was staged, and it is
     * written outside the capture window on purpose: this is not part of the
     * reply, it is the operator's record. */
    uart_puts("goatloader: staged ");
    uart_puts(utoa((uint64_t)length));
    uart_puts(" bytes, signature ok\n");
    goat_report(&staged);
}

/* --- request dispatch ---------------------------------------------------- */

/* Rejoins a verb and its arguments into a command line. token() replaced the
 * separator with a NUL, and the shell wants the whole line, so the framing
 * has to be rebuilt here rather than by the caller. */
static void run_shell_command(reply_t *reply, const char *verb, const char *args) {
    char command[GOATLOADER_LINE_MAX];
    size_t used = 0;

    while (*verb && used + 2u < sizeof command) command[used++] = *verb++;
    if (*args && used + 2u < sizeof command) command[used++] = ' ';
    while (*args && used + 1u < sizeof command) command[used++] = *args++;
    command[used] = 0;
    run_shell(reply, command);
}

static void reply_stage(reply_t *reply) {
    reply_add(reply, " stage=");
    reply_add_hex(reply, (uint64_t)(uintptr_t)stage);
    reply_add_hex(reply, (uint64_t)stage_capacity);
}

static void handle_line(session_t *session, char *line) {
    reply_t reply;
    char body[GOATLOADER_LINE_MAX];
    char *cursor;
    char *verb;
    char *args;
    size_t tag = strlen(GOATLOADER_PROTO);
    size_t used = 0;
    const char *source = line;
    int framed;

    reply_reset(&reply);

    framed = strlen(line) >= tag && starts_with(line, GOATLOADER_PROTO) &&
             (line[tag] == 0 || is_space(line[tag]));

    if (!framed) {
        /* A bare line is a shell command, so a human on a socket can type
         * `help` without having to know the framing. The host tool always
         * sends the prefix. */
        run_shell(&reply, line);
        reply_send(session, &reply);
        return;
    }

    source = line + tag;
    while (is_space(*source)) source++;
    while (*source && used + 1u < sizeof body) body[used++] = *source++;
    body[used] = 0;

    cursor = body;
    verb = token(&cursor);
    args = cursor;
    if (!verb) {
        reply_add(&reply, GOATLOADER_PROTO " ERR empty-request\n");
        reply_send(session, &reply);
        return;
    }

    if (strcmp(verb, "HELLO") == 0) {
        reply_add(&reply, GOATLOADER_PROTO " OK hello device=dr1zzle-goatloader/1 ip=");
        reply_add_address(&reply, net_ip());
        reply_add(&reply, " port=");
        reply_add_uint(&reply, GOATLOADER_PORT);
        /* The window is advertised because the host tool cannot know it: it is
         * whatever SRAM the linker left over, so it moves when the image does.
         * A container whose load base falls outside it is refused with
         * stage=placement, and the host can say why before pushing it. */
        reply_stage(&reply);
        reply_add(&reply, "\n");
    }
    else if (strcmp(verb, "KEY") == 0) {
        trim_tail(args);
        if (*args && parse_hex_bytes(args, pending_key, sizeof pending_key) == 0) {
            have_key = 1;
            reply_add(&reply, GOATLOADER_PROTO " OK key=");
            reply_add_uint(&reply, (uint64_t)sizeof pending_key);
            reply_add(&reply, "\n");
        } else {
            stat_refused++;
            reply_add(&reply, GOATLOADER_PROTO " ERR key=expected-64-hex-digits\n");
        }
    }
    else if (strcmp(verb, "PUSH") == 0) {
        uint64_t want = 0;
        trim_tail(args);
        if (*args && parse_count(args, &want) == 0 && want > 0u &&
            want <= (uint64_t)stage_capacity) {
            /* No reply yet: the bytes come first, the answer follows them.
             * Replying here would put text in the middle of a binary. */
            session->blob_left = (size_t)want;
            session->blob_got = 0;
            return;
        }
        stat_refused++;
        reply_add(&reply, GOATLOADER_PROTO " ERR push=expected-length\n");
    }
    else if (strcmp(verb, "RUN") == 0) {
        uint64_t load_base = 0;
        uint64_t entry = 0;
        if (!have_key) {
            stat_refused++;
            reply_add(&reply, GOATLOADER_PROTO " ERR run=no-key\n");
        } else if (!have_staged) {
            stat_refused++;
            reply_add(&reply, GOATLOADER_PROTO " ERR run=no-stage\n");
        } else if (goat_verify(&staged) != 0) {
            /* Checked again here and not just at PUSH: the staged record is
             * RAM, and a fault between the two commands is exactly the case
             * where re-checking costs one signature and saves an image. */
            stat_refused++;
            reply_add(&reply, GOATLOADER_PROTO " ERR run=verify\n");
        } else if (goat_decrypt(&staged, pending_key, &load_base, &entry) != 0) {
            /* goat_decrypt() checks the digest over the plaintext that
             * actually landed at load_base before it reports success. */
            stat_refused++;
            reply_add(&reply, GOATLOADER_PROTO " ERR run=decrypt\n");
        } else {
            stat_entered++;
            reply_add(&reply, GOATLOADER_PROTO " RUN loadBase=");
            reply_add_hex(&reply, load_base);
            reply_add(&reply, " entry=");
            reply_add_hex(&reply, entry);
            reply_add(&reply, "\n");
            reply_send(session, &reply);
            /* The reply has to be on the wire before the jump. Once the
             * payload is entered there is no loop left to service the
             * transmit queue, and the host tool is waiting on this line to
             * know whether it should expect a handoff at all. */
            usb_cdc_tx_pending();
            uart_puts("goatloader: entering 0x");
            uart_puts(utoa_hex(entry));
            uart_puts("\n");
            goat_enter(entry);
        }
    }
    else if (strcmp(verb, "INSTALL") == 0) {
        char *slot_text = token(&args);
        char *name_text = token(&args);
        uint64_t slot = 0;
        uint64_t length = have_staged ? staged.payload_len : 0;
        char label[17];
        const char *label_ptr = name_text;

        if (!slot_text || parse_count(slot_text, &slot) != 0 ||
            slot >= FW_SLOT_COUNT) {
            stat_refused++;
            reply_add(&reply, GOATLOADER_PROTO " ERR install=expected-slot\n");
        } else {
            /* The label is the operator's if one was given, otherwise the
             * certificate subject. Resolved here so the reply can name the
             * slot without the store having to hand it back. */
            if (!label_ptr && have_staged) {
                uint32_t keep = staged.subject_len;
                if (keep > sizeof label - 1u) keep = (uint32_t)sizeof label - 1u;
                for (uint32_t i = 0; i < keep; i++) {
                    label[i] = (char)staged.subject[i];
                }
                label[keep] = 0;
                label_ptr = label;
            }
            int rc = goatloader_install((unsigned)slot, label_ptr);
            if (rc == 0) {
                reply_add(&reply, GOATLOADER_PROTO " OK install slot=");
                reply_add_uint(&reply, slot);
                reply_add(&reply, " len=");
                reply_add_uint(&reply, length);
                reply_add(&reply, " name=");
                reply_add(&reply, label_ptr ? label_ptr : "-");
                reply_add(&reply, "\n");
                uart_puts("goatloader: installed slot ");
                uart_puts(utoa(slot));
                uart_puts(" ");
                uart_puts(label_ptr ? label_ptr : "-");
                uart_puts("\n");
            } else {
                const char *why = "failed";
                stat_refused++;
                if (rc == -1) why = "no-key";
                else if (rc == -2) why = "no-stage";
                else if (rc == -3) why = "verify";
                else if (rc == -4) why = "decrypt";
                reply_add(&reply, GOATLOADER_PROTO " ERR install=");
                reply_add(&reply, why);
                reply_add(&reply, "\n");
            }
        }
    }
    else if (strcmp(verb, "BYE") == 0) {
        reply_add(&reply, GOATLOADER_PROTO " OK bye\n");
        reply_send(session, &reply);
        usb_cdc_tx_pending();
        tcp_close(session->socket);
        session->socket = 0;
        session->in_use = 0;
        session->blob_left = 0;
        session->line_len = 0;
        return;
    }
    else if (strcmp(verb, "STATUS") == 0) {
        reply_add(&reply, GOATLOADER_PROTO " OK active=1 sessions=");
        reply_add_uint(&reply, goatloader_sessions());
        reply_add(&reply, " staged=");
        reply_add(&reply, have_staged ? "1" : "0");
        reply_add(&reply, " key=");
        reply_add(&reply, have_key ? "1" : "0");
        reply_add(&reply, " pushed=");
        reply_add_uint(&reply, stat_pushed);
        reply_add(&reply, " entered=");
        reply_add_uint(&reply, stat_entered);
        reply_add(&reply, " installed=");
        reply_add_uint(&reply, stat_installed);
        reply_add(&reply, " refused=");
        reply_add_uint(&reply, stat_refused);
        reply_add(&reply, " commands=");
        reply_add_uint(&reply, stat_commands);
        reply_stage(&reply);
        reply_add(&reply, "\n");
    }
    else if (strcmp(verb, "ABORT") == 0) {
        have_staged = 0;
        goat_staged_container = 0;
        session->blob_left = 0;
        session->blob_got = 0;
        reply_add(&reply, GOATLOADER_PROTO " OK aborted\n");
    }
    else {
        /* Unknown verb: run it as a shell command. The monitor surface is
         * the same over TCP as it is over UART -- one command loop, one
         * command table -- so there is no second list to keep in sync. */
        run_shell_command(&reply, verb, args);
    }

    reply_send(session, &reply);
}

/* --- byte stream -> requests -------------------------------------------- */

static void session_feed(session_t *session, const uint8_t *data, size_t len) {
    while (len) {
        if (session->blob_left) {
            size_t take = session->blob_left < len ? session->blob_left : len;
            for (size_t i = 0; i < take; i++) {
                stage[session->blob_got + i] = data[i];
            }
            session->blob_got += take;
            session->blob_left -= take;
            data += take;
            len -= take;
            if (!session->blob_left) {
                reply_t reply;
                reply_reset(&reply);
                finish_push(session, &reply);
                reply_send(session, &reply);
            }
            continue;
        }

        {
            char c = (char)*data++;
            size_t keep;
            len--;
            if (c == '\n') {
                keep = session->line_len;
                session->line[session->line_len] = 0;
                session->line_len = 0;
                if (keep && !session->line_dropped) handle_line(session, session->line);
                session->line_dropped = 0;
                continue;
            }
            if (c == '\r') continue;
            if (session->line_len + 1u < sizeof session->line) {
                session->line[session->line_len++] = c;
                continue;
            }
            /* Over-long line. Refusing at the boundary beats truncating:
             * a silently shortened `memdump` argument writes to the wrong
             * place. Answer once, then drop the rest of the line. */
            if (!session->line_dropped) {
                reply_t reply;
                reply_reset(&reply);
                session->line_dropped = 1;
                reply_add(&reply, GOATLOADER_PROTO " ERR line-too-long\n");
                reply_send(session, &reply);
            }
        }
    }
}

/* --- sessions and the listener ------------------------------------------ */

static void session_release(session_t *session) {
    if (session->socket) tcp_close(session->socket);
    session->socket = 0;
    session->in_use = 0;
    session->blob_left = 0;
    session->blob_got = 0;
    session->line_len = 0;
    session->line_dropped = 0;
}

static void session_open(tcp_socket_t *socket) {
    session_t *free_slot = 0;
    reply_t reply;
    unsigned index;

    for (index = 0; index < GOATLOADER_MAX_SESSIONS; index++) {
        if (!sessions[index].in_use) {
            free_slot = &sessions[index];
            break;
        }
    }
    if (!free_slot) {
        /* No free socket, so no way to answer. Refusing the connection is
         * what keeps the listener available for the next one. */
        tcp_close(socket);
        uart_puts("goatloader: session refused, all slots busy\n");
        return;
    }

    free_slot->socket = socket;
    free_slot->in_use = 1;
    free_slot->line_len = 0;
    free_slot->blob_left = 0;
    free_slot->blob_got = 0;
    free_slot->line_dropped = 0;

    reply_reset(&reply);
    reply_add(&reply, GOATLOADER_PROTO " READY device=dr1zzle-goatloader/1 ip=");
    reply_add_address(&reply, net_ip());
    reply_add(&reply, " port=");
    reply_add_uint(&reply, GOATLOADER_PORT);
    reply_add(&reply, "\n");
    reply_send(free_slot, &reply);

    uart_puts("goatloader: session open\n");
}

static void session_service(session_t *session) {
    uint8_t buffer[GOATLOADER_REPLY_MAX];
    tcp_socket_t *socket;

    if (!session->in_use) return;
    socket = session->socket;
    if (!socket || !tcp_established(socket)) {
        session_release(session);
        return;
    }
    for (;;) {
        uint16_t got = tcp_recv(socket, buffer, sizeof buffer);
        if (!got) break;
        session_feed(session, buffer, got);
        /* BYE releases the slot from inside the dispatcher. */
        if (!session->in_use) return;
    }
}

/* --- public surface ------------------------------------------------------ */

/* Weak refusal: on a build that links no NAND writer (the host test), INSTALL
 * reports that it is unsupported instead of failing to link. src/core/fw_store.c
 * overrides this with the strong definition that programs the slot. */
__attribute__((weak))
int goatloader_install_hook(unsigned slot, const uint8_t *image, uint32_t size,
                            uint64_t load_base, uint32_t entry_off,
                            const char *name) {
    (void)slot; (void)image; (void)size; (void)load_base; (void)entry_off;
    (void)name;
    return -1;
}

int goatloader_install(unsigned slot, const char *name) {
    char derived[17];
    const char *label = name;
    uint64_t load_base = 0;
    uint64_t entry = 0;
    int rc;

    if (slot >= FW_SLOT_COUNT) return -5;
    if (!have_key) return -1;
    if (!have_staged) return -2;
    if (goat_verify(&staged) != 0) return -3;

    /* The subject is captured before decrypt: goat_decrypt() writes the
     * plaintext over the staging window, which is where the container's own
     * bytes live, and the header this label feeds is built from those bytes. */
    if (!label) {
        uint32_t keep = staged.subject_len;
        if (keep > sizeof derived - 1u) keep = (uint32_t)sizeof derived - 1u;
        for (uint32_t i = 0; i < keep; i++) derived[i] = (char)staged.subject[i];
        derived[keep] = 0;
        label = derived;
    }

    if (goat_decrypt(&staged, pending_key, &load_base, &entry) != 0) return -4;

    rc = goatloader_install_hook((unsigned)slot,
                                 (const uint8_t *)(uintptr_t)load_base,
                                 (uint32_t)staged.payload_len, load_base,
                                 (uint32_t)staged.entry_off, label);
    if (rc != 0) return -5;
    stat_installed++;
    return 0;
}

int goatloader_init(void) {
    unsigned index;

    if (!stage) {
        stage = (uint8_t *)(uintptr_t)GOAT_STAGE_BASE;
        stage_capacity = (uint32_t)GOAT_STAGE_SIZE;
    }
    for (index = 0; index < GOATLOADER_MAX_SESSIONS; index++) {
        sessions[index].socket = 0;
        sessions[index].in_use = 0;
        sessions[index].line_len = 0;
        sessions[index].blob_left = 0;
        sessions[index].blob_got = 0;
        sessions[index].line_dropped = 0;
    }
    listener = 0;
    memset(pending_key, 0, sizeof pending_key);
    have_key = 0;
    have_staged = 0;
    goat_staged_container = 0;
    stat_pushed = stat_entered = stat_installed = stat_refused = stat_commands = 0;

    listener = tcp_listen(GOATLOADER_PORT);
    /* -1 here is not a failure of the server, only of this attempt: the
     * socket table is four deep and one is taken by the bring-up order. */
    return listener ? 0 : -1;
}

void goatloader_poll(void) {
    unsigned index;

    /* The listener is re-armed every poll. In this stack the listening
     * socket itself becomes the first connection, so adopting one leaves the
     * payload with no listener at all unless a new one is created in the
     * same pass. Creating one when there is none is the same code path,
     * which is what keeps "always listening" true rather than aspirational:
     * there is no state in which a poll leaves the payload unbound. */
    if (listener && tcp_established(listener)) {
        session_open(listener);
        listener = 0;
    }
    if (!listener) listener = tcp_listen(GOATLOADER_PORT);

    for (index = 0; index < GOATLOADER_MAX_SESSIONS; index++) {
        session_service(&sessions[index]);
    }

    /* Replies were queued into the transmit ring; push them now so a reply
     * reaches the client even if the caller between polls is slow. */
    usb_cdc_tx_pending();
}

int goatloader_active(void) {
    return 1;
}

unsigned goatloader_sessions(void) {
    unsigned count = 0;
    unsigned index;
    for (index = 0; index < GOATLOADER_MAX_SESSIONS; index++) {
        if (sessions[index].in_use) count++;
    }
    return count;
}

static void report_address(uint32_t address) {
    uart_puts(utoa((address >> 24) & 0xffu)); uart_putc('.');
    uart_puts(utoa((address >> 16) & 0xffu)); uart_putc('.');
    uart_puts(utoa((address >> 8) & 0xffu));  uart_putc('.');
    uart_puts(utoa(address & 0xffu));
}

void goatloader_report(void) {
    uart_puts("goatloader: state=always-on ip=");
    report_address(net_ip());
    uart_puts(" port=");
    uart_puts(utoa(GOATLOADER_PORT));
    uart_puts(" sessions=");
    uart_puts(utoa(goatloader_sessions()));
    uart_puts(" staged=");
    uart_puts(have_staged ? "yes" : "no");
    uart_puts(" key=");
    uart_puts(have_key ? "yes" : "no");
    uart_puts(" pushed=");
    uart_puts(utoa(stat_pushed));
    uart_puts(" entered=");
    uart_puts(utoa(stat_entered));
    uart_puts(" installed=");
    uart_puts(utoa(stat_installed));
    uart_puts(" refused=");
    uart_puts(utoa(stat_refused));
    uart_puts(" commands=");
    uart_puts(utoa(stat_commands));
    uart_putc('\n');
}

int goatloader_stop(void) {
    /* Refused, and the reason is printed here rather than at the call site
     * so there is exactly one sentence describing the policy. There is no
     * code path that closes the listener; disabling the goatloader is a
     * build change, not a runtime one. */
    uart_puts("goatloader: cannot be stopped\n");
    uart_puts("  `goat push`, `goat shell` and the sealed-container flow all\n");
    uart_puts("  need this listener. See docs/GOATLOADER.md for why it is\n");
    uart_puts("  bound at bring-up and what it exposes.\n");
    return -1;
}

void goatloader_set_stage(uint8_t *base, uint32_t capacity) {
    stage = base;
    stage_capacity = capacity;
}
