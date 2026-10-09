#include <drizzle/console.h>
#include <drizzle/monitor.h>
#include <drizzle/net.h>
#include <drizzle/time.h>
#include <stdio.h>
#include <string.h>

static void write_text(const char *text) { while (*text) putchar(*text++); }

static void write_decimal(size_t value) {
    char digits[32];
    size_t count = 0;
    do {
        digits[count++] = (char)('0' + (value % 10u));
        value /= 10u;
    } while (value && count < sizeof digits);
    while (count) putchar(digits[--count]);
}

static void help(void) {
    puts("commands:");
    puts("  d      DFU submenu");
    puts("  u      USB config catalog");
    puts("  x      raw USB control transfer");
    puts("  help   show commands");
    puts("  info   show target info");
    puts("  heap   show heap size");
    puts("  memdump <addr> <len>");
    puts("  memwrite <addr> <byte>");
    puts("  net    show network status");
    puts("  time   show timer");
    puts("  clear  redraw prompt");
    puts("  reboot reboot stub");
}

static int same(const char *command, const char *name) { return strcmp(command, name) == 0; }

static int starts_with(const char *text, const char *prefix) {
    while (*prefix) if (*text++ != *prefix++) return 0;
    return 1;
}

static void write_u64(uint64_t value) {
    char digits[32];
    size_t count = 0;
    do {
        digits[count++] = (char)('0' + (value % 10u));
        value /= 10u;
    } while (value && count < sizeof digits);
    while (count) putchar(digits[--count]);
}

static void net_status(void) {
    const drizzle_link_t *link = drizzle_net_link();
    write_text("link=");
    puts(link && link->name ? link->name : "none");
    write_text("state=");
    puts(drizzle_net_state() == DR1ZZLE_NET_UP ? "up" : (drizzle_net_state() == DR1ZZLE_NET_CONFIGURING ? "configuring" : "down"));
    write_text("rx="); write_u64(drizzle_net_frames_rx());
    write_text(" tx="); write_u64(drizzle_net_frames_tx());
    write_text(" drops="); write_u64(drizzle_net_drops());
    putchar('\n');
}

static int read_line(const char *prompt, char *command, size_t capacity) {
    size_t length = 0;
    write_text(prompt);
    for (;;) {
        int c = drizzle_console_read();
        if (c == '\r' || c == '\n') {
            putchar('\n');
            break;
        }
        if ((c == 8 || c == 127) && length) {
            length--;
            write_text("\b \b");
            continue;
        }
        if (c >= 32 && c < 127 && length + 1u < capacity) {
            command[length++] = (char)c;
            putchar(c);
        }
    }
    command[length] = 0;
    return length > 0;
}

static void dfu_status(int state) {
    puts("GETSTATUS status=0 poll_timeout=0 string_index=0");
    write_text("state=");
    write_decimal((size_t)state);
    if (state == 10) puts(" (dfuERROR) meaning=Device in error - CLRSTATUS should clear it");
    else if (state == 2) puts(" (dfuIDLE) meaning=Normal idle - manifest trigger should work");
    else if (state == 6 || state == 7) puts(" (MANIFEST*) meaning=Manifest in progress - good sign");
    else if (state == 0 || state == 1) puts(" (app*) meaning=Not in DFU mode - device did not enter DFU properly");
    else puts(" meaning=unknown/unhandled DFU state");
}

static void dfu_menu(void) {
    char command[32];
    int state = 2;
    puts("DFU submenu (QEMU simulator, no USB device attached)");
    puts("  c CLRSTATUS");
    puts("  s GETSTATUS");
    puts("  g GETSTATE");
    puts("  a ABORT");
    puts("  z DNLOAD(0)");
    puts("  q back");
    for (;;) {
        if (!read_line("dfu> ", command, sizeof command)) continue;
        if (same(command, "q")) return;
        if (same(command, "c")) { state = 2; puts("CLRSTATUS ok; state=dfuIDLE(2)"); }
        else if (same(command, "s")) dfu_status(state);
        else if (same(command, "g")) { write_text("GETSTATE state="); write_decimal((size_t)state); putchar('\n'); }
        else if (same(command, "a")) { state = 2; puts("ABORT ok; state=dfuIDLE(2)"); }
        else if (same(command, "z")) { state = 6; puts("DNLOAD(0) accepted; state=MANIFEST_SYNC(6)"); }
        else puts("dfu commands: c=CLRSTATUS s=GETSTATUS g=GETSTATE a=ABORT z=DNLOAD(0) q=back");
    }
}

static unsigned hex_value(char c, int *ok) {
    if (c >= '0' && c <= '9') return (unsigned)(c - '0');
    if (c >= 'a' && c <= 'f') return (unsigned)(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return (unsigned)(c - 'A' + 10);
    *ok = 0;
    return 0;
}

static int parse_hex_field(const char **cursor, unsigned max, unsigned *value) {
    unsigned result = 0;
    int saw_digit = 0;
    int ok = 1;
    while (**cursor == ' ') (*cursor)++;
    if ((*cursor)[0] == '0' && ((*cursor)[1] == 'x' || (*cursor)[1] == 'X')) *cursor += 2;
    while (**cursor && **cursor != ' ') {
        saw_digit = 1;
        result = result * 16u + hex_value(**cursor, &ok);
        if (!ok || result > max) return 0;
        (*cursor)++;
    }
    *value = result;
    return saw_digit;
}

static int parse_hex64_field(const char **cursor, uint64_t max, uint64_t *value) {
    uint64_t result = 0;
    int saw_digit = 0;
    int ok = 1;
    while (**cursor == ' ') (*cursor)++;
    if ((*cursor)[0] == '0' && ((*cursor)[1] == 'x' || (*cursor)[1] == 'X')) *cursor += 2;
    while (**cursor && **cursor != ' ') {
        saw_digit = 1;
        unsigned digit = hex_value(**cursor, &ok);
        if (!ok || result > (max - digit) / 16u) return 0;
        result = result * 16u + digit;
        (*cursor)++;
    }
    *value = result;
    return saw_digit;
}

static void write_hex_byte(uint8_t value) {
    static const char hex[] = "0123456789abcdef";
    putchar(hex[value >> 4]);
    putchar(hex[value & 0xfu]);
}

static void memdump_command(const char *command) {
    const char *cursor = command + strlen("memdump");
    uint64_t address;
    uint64_t length;
    if (!parse_hex64_field(&cursor, UINT64_MAX, &address) || !parse_hex64_field(&cursor, 256u, &length)) {
        puts("usage: memdump <addr> <len<=0x100>");
        return;
    }
    for (uint64_t i = 0; i < length; i++) {
        if ((i & 0xfu) == 0u) { if (i) putchar('\n'); write_text("  "); }
        write_hex_byte(*(volatile uint8_t *)(uintptr_t)(address + i));
        putchar(' ');
    }
    putchar('\n');
}

static void memwrite_command(const char *command) {
    const char *cursor = command + strlen("memwrite");
    uint64_t address;
    uint64_t value;
    if (!parse_hex64_field(&cursor, UINT64_MAX, &address) || !parse_hex64_field(&cursor, 0xffu, &value)) {
        puts("usage: memwrite <addr> <byte>");
        return;
    }
    *(volatile uint8_t *)(uintptr_t)address = (uint8_t)value;
    puts("memwrite ok");
}

static void raw_transfer(void) {
    char command[96];
    puts("Raw USB control transfer validator (QEMU simulator, no USB device attached)");
    puts("usage: <bmRequestType> <bRequest> <wValue> <wIndex> <wLength>");
    puts("example: 21 01 0000 0000 0000");
    if (!read_line("raw> ", command, sizeof command)) return;
    const char *cursor = command;
    unsigned bm_request_type, request, value, index, length;
    if (!parse_hex_field(&cursor, 0xffu, &bm_request_type) ||
        !parse_hex_field(&cursor, 0xffu, &request) ||
        !parse_hex_field(&cursor, 0xffffu, &value) ||
        !parse_hex_field(&cursor, 0xffffu, &index) ||
        !parse_hex_field(&cursor, 0xffffu, &length)) {
        puts("raw transfer rejected: expected five hex fields");
        return;
    }
    puts("raw transfer parsed ok; not submitted because no USB transport is bound");
}

static void usb_config_catalog(void) {
    char command[32];
    puts("USB config catalog (documentation only)");
    puts("  8020  usbliter8 known-working notes for T8020");
    puts("  8027  usbliter8 known-working notes for T8027");
    puts("  8030  usbliter8 known-working notes for T8030");
    puts("  h     host-controller status");
    puts("  q     back");
    for (;;) {
        if (!read_line("usb> ", command, sizeof command)) continue;
        if (same(command, "q")) return;
        if (same(command, "8020")) {
            puts("T8020 CPID=0x8020 config=usbliter8 status=not executable in dr1zzle");
        } else if (same(command, "8027")) {
            puts("T8027 CPID=0x8027 config=usbliter8 status=not executable in dr1zzle");
        } else if (same(command, "8030")) {
            puts("T8030 CPID=0x8030 config=usbliter8 status=not executable in dr1zzle");
        } else if (same(command, "h")) {
            puts("USB host controller: unavailable");
            puts("pwnDFU chaining: unavailable");
        } else {
            puts("usb commands: 8020 8027 8030 h q");
        }
    }
}

void drizzle_monitor_run(size_t heap_size) {
    char command[32];
    help();
    for (;;) {
        if (!read_line("dr1zzle> ", command, sizeof command) || same(command, "clear")) continue;
        if (same(command, "d")) dfu_menu();
        else if (same(command, "u")) usb_config_catalog();
        else if (same(command, "x")) raw_transfer();
        else if (same(command, "help")) help();
        else if (same(command, "info")) puts("target=qemu-virt arch=aarch64 mode=freestanding");
        else if (same(command, "heap")) { write_text("heap="); write_decimal(heap_size); puts(" bytes"); }
        else if (starts_with(command, "memdump")) memdump_command(command);
        else if (starts_with(command, "memwrite")) memwrite_command(command);
        else if (same(command, "net")) net_status();
        else if (same(command, "time")) { write_text("time_ms="); write_u64(drizzle_time_ms()); putchar('\n'); }
        else if (same(command, "reboot")) puts("reboot unavailable on qemu-virt monitor");
        else puts("unknown command");
    }
}
