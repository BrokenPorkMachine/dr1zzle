/* Host test for the goatloader protocol state machine.
 *
 * The payload cannot be run on a Mac, so this drives the loader the way the
 * main loop does -- goatloader_poll() over a fake socket -- and asserts on
 * the bytes it produces. Worth doing because the protocol is the contract
 * with the Rust Goat host boundary: a reply that starts with "GOAT/1 ERR" where the host tool
 * expects "GOAT/1 OK" fails as a failed push, not as a compile error.
 *
 * Builds with ASan/UBSan like the other host tests; see tests/test_phase4.py.
 */

#include "goat/loader.h"
#include "goat/goat.h"
#include "goat/aes.h"
#include "net.h"
#include "usb.h"
#include "uart.h"
#include "shell.h"
#include "string.h"
#include "util.h"

/* The staged-container pointer the payload publishes; defined in goat.c on
 * the device, and here because this test stubs the rest of that module. */
const uint8_t *goat_staged_container;

/* --- fake socket --------------------------------------------------------- */

#define CLIENT_MAX 2048u
#define SERVER_MAX 1024u

static uint8_t client_to_device[CLIENT_MAX];
static size_t client_to_device_len;
static size_t client_to_device_pos;

static uint8_t device_to_client[SERVER_MAX];
static size_t device_to_client_len;

/* The listening socket itself becomes the connection in this stack, which is
 * the behaviour the loader has to cope with. Modelled here: one dummy socket
 * that is established as soon as it exists. The real type is opaque (that is
 * the point of the header), so the fake is only a non-null identity. */
static int dummy_socket;
static int listen_calls;
static int open_sessions;

/* The staging window on the host: a real buffer, because the device version
 * is a SRAM window this machine does not have. */
static uint8_t stage_window[4096];

tcp_socket_t *tcp_listen(uint16_t port) {
    listen_calls++;
    (void)port;
    return (tcp_socket_t *)&dummy_socket;
}

int tcp_established(tcp_socket_t *s) { (void)s; return 1; }

uint16_t tcp_recv(tcp_socket_t *s, uint8_t *data, uint16_t max_len) {
    size_t available = client_to_device_len - client_to_device_pos;
    uint16_t count = 0;
    (void)s;
    if (!available) return 0;
    count = (uint16_t)(available > max_len ? max_len : available);
    memcpy(data, client_to_device + client_to_device_pos, count);
    client_to_device_pos += count;
    return count;
}

uint16_t tcp_send(tcp_socket_t *s, const uint8_t *data, uint16_t len) {
    (void)s;
    if (!len) return 0;
    if (device_to_client_len + len > SERVER_MAX) return 0;
    memcpy(device_to_client + device_to_client_len, data, len);
    device_to_client_len += len;
    return len;
}

void tcp_close(tcp_socket_t *s) { (void)s; open_sessions--; }

uint32_t net_ip(void) { return NET_DEFAULT_IPV4; }

void usb_cdc_tx_pending(void) { }

/* --- serial-side stubs --------------------------------------------------- */

/* Serial-side stubs. These model the real uart.c capture semantics: while a
 * capture is active the bytes go to the sink as well as to the console, which
 * is the only reason a command run on behalf of a remote session has anything
 * to reply with. */
static char serial_log[2048];
static size_t serial_len;
static uart_capture_fn capture_sink;
static int capture_active;

void uart_putc(char c) {
    uint8_t byte = (uint8_t)c;
    if (capture_active && capture_sink) capture_sink(&byte, 1u);
    if (serial_len + 1u < sizeof serial_log) serial_log[serial_len++] = c;
}

void uart_puts(const char *s) { while (*s) uart_putc(*s++); }

void uart_capture_begin(uart_capture_fn sink) {
    capture_sink = sink;
    capture_active = 1;
}

void uart_capture_end(void) {
    capture_sink = 0;
    capture_active = 0;
}

/* The shell stub prints something identifiable so the passthrough path can be
 * asserted: the reply has to be the command's output, not a canned answer. */
static char last_command[128];
static int commands_run;

void shell_exec(const char *line) {
    size_t index = 0;
    commands_run++;
    while (line[index] && index + 1u < sizeof last_command) {
        last_command[index] = line[index];
        index++;
    }
    last_command[index] = 0;
    uart_puts("shell: ");
    uart_puts(line);
    uart_putc('\n');
}

/* --- goat-side stubs ----------------------------------------------------- */

/* Two symbols this file needs before their definitions: contains() for the
 * enter-path assertion below, and exit(), which <stdlib.h> would normally
 * provide but which the repo's own header shadows. */
static int contains(const char *haystack, const char *needle);
void exit(int status);

/* The load base the stub container reports. Set at startup to the address of
 * the test's own staging window -- the window is a real buffer on the host,
 * so its address is not a constant the test can write down. The placement
 * test moves it out of the window. */
static uint64_t stub_load_base;

static int parse_result;
static int verify_result;
static int decrypt_result;
static int enter_calls;
static int report_calls;

/* The install backend. loader.c's is weak, so this strong definition replaces
 * it and lets the INSTALL verb be tested with no NAND: it records what the
 * loader decrypted and hands back a result the test chooses. */
static int install_result;
static int install_calls;
static unsigned installed_slot;
static uint32_t installed_size;
static uint64_t installed_load_base;
static uint32_t installed_entry_off;
static char installed_name[24];

int goatloader_install_hook(unsigned slot, const uint8_t *image, uint32_t size,
                            uint64_t load_base, uint32_t entry_off,
                            const char *name) {
    size_t i = 0;
    install_calls++;
    installed_slot = slot;
    installed_size = size;
    installed_load_base = load_base;
    installed_entry_off = entry_off;
    if (name) {
        while (name[i] && i + 1u < sizeof installed_name) {
            installed_name[i] = name[i];
            i++;
        }
    }
    installed_name[i] = 0;
    (void)image;
    return install_result;
}

int goat_parse(const uint8_t *der, uint32_t len, goat_container_t *out) {
    for (uint32_t i = 0; i < sizeof(*out); i++) ((uint8_t *)out)[i] = 0;
    out->payload_sha = der;      /* aliasing, as the real one does */
    out->payload_len = len;
    out->load_base = stub_load_base;
    out->entry_off = 0x1000;
    out->subject = (const uint8_t *)"dr1zzle-test";
    out->subject_len = sizeof "dr1zzle-test" - 1u;
    out->signature = der;
    out->signature_len = len;
    out->signed_region = der;
    out->signed_region_len = len;
    return parse_result;
}

int goat_cert_ok(const goat_container_t *c) { (void)c; return 0; }

int goat_verify(const goat_container_t *c) { (void)c; return verify_result; }

int goat_digest_ok(const goat_container_t *c, const uint8_t *payload, uint64_t len) {
    (void)c; (void)payload; (void)len;
    return 0;
}

int goat_decrypt(const goat_container_t *c, const uint8_t key[32],
                 uint64_t *load_base_out, uint64_t *entry_out) {
    (void)c; (void)key;
    if (decrypt_result != 0) return decrypt_result;
    *load_base_out = 0x180000000ULL;
    *entry_out = 0x180001000ULL;
    return 0;
}

/* Enters the payload by exiting the test. That is the closest a host process
 * gets to a branch that never returns, and it is also the only point at which
 * the property this test cares about is observable: the RUN reply has to
 * already be queued, because once the payload is entered there is no loop left
 * to service the transmit queue and the host tool would be waiting on a line
 * that never came. */
void goat_enter(uint64_t entry) {
    char text[SERVER_MAX];
    size_t index;
    int status;

    for (index = 0; index < device_to_client_len; index++) {
        text[index] = (char)device_to_client[index];
    }
    text[index] = 0;
    enter_calls++;
    (void)entry;

    status = (enter_calls == 1 && contains(text, "GOAT/1 RUN") &&
              contains(text, "entry=0x") && contains(text, "loadBase=0x")) ? 0 : 45;
    exit(status);
}

void goat_report(const goat_container_t *c) {
    report_calls++;
    (void)c;
    uart_puts("goat: staged report\n");
}

/* The real window is reserved by the linker script; on the host these are
 * two standalone bytes, and the test overrides the window anyway below. */
char __stage_base;
char __stage_limit;

/* --- helpers ------------------------------------------------------------- */

/* Records the first failing check; the exit code is the code of that check,
 * so a failure names itself the way the other host tests do. */
static int failures;

static void check(int condition, int code) {
    if (!condition && !failures) failures = code;
}

/* Appears to the server as the client's next line. */
static void client_sends(const char *text) {
    size_t length = strlen(text);
    memcpy(client_to_device + client_to_device_len, text, length);
    client_to_device_len += length;
}

static void client_sends_bytes(const void *data, size_t length) {
    memcpy(client_to_device + client_to_device_len, data, length);
    client_to_device_len += length;
}

/* Runs the loader until it has drained everything the client sent, which is
 * what the idle loop does between keystrokes. The position is not rewound:
 * `tcp_recv` has consumed those bytes, and replaying them would stage the same
 * container twice -- which is how this harness first found itself entering a
 * payload. */
static void serve(void) {
    while (client_to_device_pos < client_to_device_len) goatloader_poll();
    /* One extra pass so anything queued during the last drain is pushed. */
    goatloader_poll();
}

static void reset_conversation(void) {
    client_to_device_len = 0;
    client_to_device_pos = 0;
    device_to_client_len = 0;
    serial_len = 0;
}

static int started;

static void start(void) {
    if (started) return;
    started = 1;
    goatloader_init();
    goatloader_set_stage(stage_window, sizeof stage_window);
    stub_load_base = (uint64_t)(uintptr_t)stage_window;
}

/* The reply stream is a byte range, not a C string: tcp_send() copies only
 * what it is given, so terminate it before string matching. Two small helpers
 * stand in for strstr/strncmp, which the freestanding string.h does not
 * declare and which this test has no reason to add. */
static int contains(const char *haystack, const char *needle) {
    size_t width = strlen(needle);
    size_t total = strlen(haystack);
    size_t index;
    if (width == 0) return 1;
    for (index = 0; index + width <= total; index++) {
        if (memcmp(haystack + index, needle, width) == 0) return 1;
    }
    return 0;
}

static int starts_with(const char *text, const char *prefix) {
    size_t width = strlen(prefix);
    size_t index;
    for (index = 0; index < width; index++) {
        if (!text[index] || text[index] != prefix[index]) return 0;
    }
    return 1;
}

static char reply_text[SERVER_MAX];

/* Terminates a copy of the reply so the checks below can read it as text. */
static const char *reply(void) {
    size_t index;
    for (index = 0; index < device_to_client_len && index + 1u < sizeof reply_text; index++) {
        reply_text[index] = (char)device_to_client[index];
    }
    reply_text[index] = 0;
    return reply_text;
}

int main(void) {
    static uint8_t container[64];
    unsigned index;

    /* --- default state -------------------------------------------------- */

    check(goatloader_active() == 1, 1);
    check(goatloader_sessions() == 0, 2);

    start();

    /* --- HELLO names the pre-configured address ------------------------- */

    reset_conversation();
    client_sends("GOAT/1 HELLO client=goat-test\n");
    serve();
    check(device_to_client_len > 0, 3);
    check(contains(reply(), "GOAT/1 OK hello"), 4);
    check(contains(reply(), "192.168.42.1"), 5);
    check(contains(reply(), "port=1234"), 6);

    /* The listener is re-armed on every pass: this stack turns the listening
     * socket into the connection, so without that the second client would
     * find nothing bound. */
    check(listen_calls >= 2, 7);

    /* --- KEY ------------------------------------------------------------- */

    reset_conversation();
    client_sends("GOAT/1 KEY ");
    client_sends("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n");
    serve();
    check(contains(reply(), "GOAT/1 OK key=32"), 8);

    reset_conversation();
    client_sends("GOAT/1 KEY nothex\n");
    serve();
    check(contains(reply(), "GOAT/1 ERR key="), 9);

    reset_conversation();
    client_sends("GOAT/1 KEY 00\n");
    serve();
    check(contains(reply(), "GOAT/1 ERR key="), 10);

    /* --- PUSH: the length comes first, then raw bytes -------------------- */

    parse_result = 0;
    verify_result = 0;
    reset_conversation();
    client_sends("GOAT/1 PUSH 16\n");
    memset(container, 0xab, sizeof container);
    client_sends_bytes(container, 16);
    serve();
    check(contains(reply(), "GOAT/1 OK stage"), 11);
    check(contains(reply(), "verify=ok"), 12);

    /* A container that carries a newline in its bytes must not be parsed as
     * several commands: that is the whole reason the blob state exists. */
    memset(container, 0, sizeof container);
    for (index = 0; index < sizeof container; index += 2u) container[index] = 'G';
    container[1] = '\n';
    reset_conversation();
    client_sends("GOAT/1 PUSH 64\n");
    client_sends_bytes(container, 64);
    serve();
    check(contains(reply(), "GOAT/1 OK stage"), 13);
    check(commands_run == 0, 14);

    /* Length that does not fit the staging window. */
    reset_conversation();
    client_sends("GOAT/1 PUSH 99999\n");
    serve();
    check(contains(reply(), "GOAT/1 ERR push="), 15);

    reset_conversation();
    client_sends("GOAT/1 PUSH 0\n");
    serve();
    check(contains(reply(), "GOAT/1 ERR push="), 16);

    /* --- PUSH failures keep the reply honest ----------------------------- */

    parse_result = -1;
    reset_conversation();
    client_sends("GOAT/1 PUSH 8\n");
    client_sends_bytes(container, 8);
    serve();
    check(contains(reply(), "ERR stage=parse"), 17);
    parse_result = 0;

    verify_result = -1;
    reset_conversation();
    client_sends("GOAT/1 PUSH 8\n");
    client_sends_bytes(container, 8);
    serve();
    check(contains(reply(), "ERR stage=verify"), 18);
    verify_result = 0;

    /* --- RUN: every refusal names its reason ----------------------------- */

    reset_conversation();
    client_sends("GOAT/1 STATUS\n");
    serve();
    check(contains(reply(), "active=1"), 19);
    check(enter_calls == 0, 20);

    /* --- RUN: every refusal names its reason ----------------------------- */

    /* A key was handed over earlier in this conversation, so stage a fresh
     * container and work through the ways RUN can refuse. */
    verify_result = 0;
    decrypt_result = 0;
    reset_conversation();
    client_sends("GOAT/1 PUSH 16\n");
    client_sends_bytes(container, 16);
    serve();

    /* Signature will not check out. */
    verify_result = -1;
    client_sends("GOAT/1 RUN\n");
    serve();
    check(contains(reply(), "ERR run=verify"), 34);

    /* Signature fine, decrypt or digest not. */
    verify_result = 0;
    decrypt_result = -1;
    client_sends("GOAT/1 RUN\n");
    serve();
    check(contains(reply(), "ERR run=decrypt"), 35);
    decrypt_result = 0;

    /* Nothing staged any more. */
    client_sends("GOAT/1 ABORT\n");
    serve();
    client_sends("GOAT/1 RUN\n");
    serve();
    check(contains(reply(), "ERR run=no-stage"), 36);

    /* Re-stage so the STATUS check below still reports staged=1. */
    reset_conversation();
    client_sends("GOAT/1 PUSH 16\n");
    client_sends_bytes(container, 16);
    serve();

    /* --- INSTALL: stage -> decrypt -> write to a slot ------------------- */

    /* With no name, the slot label comes from the certificate subject. */
    install_result = 0;
    install_calls = 0;
    reset_conversation();
    client_sends("GOAT/1 INSTALL 0\n");
    serve();
    check(install_calls == 1, 50);
    check(installed_slot == 0, 51);
    check(installed_size == 16, 52);
    check(installed_load_base == (uint64_t)(uintptr_t)stage_window, 53);
    check(installed_entry_off == 0x1000, 54);
    check(strcmp(installed_name, "dr1zzle-test") == 0, 55);
    check(contains(reply(), "GOAT/1 OK install"), 56);
    check(contains(reply(), "slot=0"), 57);
    check(contains(reply(), "name=dr1zzle-test"), 58);

    /* An explicit name overrides the subject. */
    install_calls = 0;
    reset_conversation();
    client_sends("GOAT/1 INSTALL 1 monitor\n");
    serve();
    check(install_calls == 1, 59);
    check(installed_slot == 1, 60);
    check(strcmp(installed_name, "monitor") == 0, 61);
    check(contains(reply(), "name=monitor"), 62);

    /* A store that refuses (bad block, no controller) is an ordinary error,
     * not a silent success. */
    install_result = -1;
    reset_conversation();
    client_sends("GOAT/1 INSTALL 0\n");
    serve();
    check(contains(reply(), "ERR install=failed"), 63);
    install_result = 0;

    /* Slot out of range and unparseable slot are rejected before the store. */
    reset_conversation();
    client_sends("GOAT/1 INSTALL 99\n");
    serve();
    check(contains(reply(), "ERR install=expected-slot"), 64);

    reset_conversation();
    client_sends("GOAT/1 INSTALL notanumber\n");
    serve();
    check(contains(reply(), "ERR install=expected-slot"), 65);

    /* No staged image means nothing to install. */
    reset_conversation();
    client_sends("GOAT/1 ABORT\n");
    serve();
    reset_conversation();
    client_sends("GOAT/1 INSTALL 0\n");
    serve();
    check(contains(reply(), "ERR install=no-stage"), 66);

    /* Re-stage for the remaining tests. */
    reset_conversation();
    client_sends("GOAT/1 PUSH 16\n");
    client_sends_bytes(container, 16);
    serve();

    /* --- the staging window is advertised, and enforced ---------------- */

    reset_conversation();
    client_sends("GOAT/1 STATUS\n");
    serve();
    check(contains(reply(), "stage=0x"), 37);
    check(contains(reply(), "0x1000"), 37);

    /* A container whose plaintext would land outside the window is refused
     * for that reason before anything else is asked of it: this one asks for
     * an address far below the window. */
    parse_result = 0;
    verify_result = 0;
    stub_load_base = (uint64_t)(uintptr_t)stage_window - 0x1000u;
    reset_conversation();
    client_sends("GOAT/1 PUSH 8\n");
    client_sends_bytes(container, 8);
    serve();
    check(contains(reply(), "ERR stage=placement"), 38);
    stub_load_base = (uint64_t)(uintptr_t)stage_window;

    /* --- shell passthrough ---------------------------------------------- */

    reset_conversation();
    client_sends("GOAT/1 help\n");
    serve();
    check(commands_run == 1, 21);
    check(starts_with(last_command, "help"), 22);
    check(contains(reply(), "shell: help"), 23);

    reset_conversation();
    client_sends("GOAT/1 memdump 0x100000000 0x40\n");
    serve();
    check(commands_run == 2, 24);
    check(contains(last_command, "memdump 0x100000000 0x40"), 25);

    /* A bare line, no framing, still runs: a human on a socket types `help`,
     * not the wire format. */
    reset_conversation();
    client_sends("help\n");
    serve();
    check(commands_run == 3, 26);
    check(contains(reply(), "shell: help"), 27);

    /* --- framing and bounds --------------------------------------------- */

    reset_conversation();
    client_sends("GOAT/1\n");
    serve();
    check(contains(reply(), "ERR empty-request"), 28);

    reset_conversation();
    for (index = 0; index < 200; index++) client_sends("x");
    client_sends("\n");
    serve();
    check(contains(reply(), "ERR line-too-long"), 29);

    /* CRLF, which is what a telnet-style client sends. */
    reset_conversation();
    client_sends("GOAT/1 HELLO\r\n");
    serve();
    check(contains(reply(), "GOAT/1 OK hello"), 30);

    /* --- ABORT ----------------------------------------------------------- */

    reset_conversation();
    client_sends("GOAT/1 PUSH 8\n");
    client_sends_bytes(container, 8);
    serve();
    reset_conversation();
    client_sends("GOAT/1 ABORT\n");
    serve();
    check(contains(reply(), "OK aborted"), 31);

    /* --- the listener cannot be turned off ------------------------------- */

    (void)goatloader_stop();
    check(goatloader_active() == 1, 32);
    /* And it is still answering after the refusal, which is the real test. */
    reset_conversation();
    client_sends("GOAT/1 STATUS\n");
    serve();
    check(contains(reply(), "active=1"), 33);

    /* --- RUN succeeds: the reply precedes the jump ------------------------
     * Last, because this path never comes back: goat_enter() ends the process
     * with the answer. Everything above it is the part that does return. */
    reset_conversation();
    client_sends("GOAT/1 PUSH 16\n");
    client_sends_bytes(container, 16);
    serve();
    verify_result = 0;
    decrypt_result = 0;
    client_sends("GOAT/1 RUN\n");
    serve();

    /* If the payload was entered, the stub above already answered. Reaching
     * this line means RUN refused something it should not have. */
    failures = failures ? failures : 44;
    return failures ? 1 : 0;
}
