#include "util.h"

const char *utoa(uint64_t val) {
    static char buf[32];
    int i = 31;
    buf[i] = 0;
    if (val == 0) { buf[30] = '0'; return &buf[30]; }
    while (val) {
        buf[--i] = '0' + (val % 10);
        val /= 10;
    }
    return &buf[i];
}

const char *utoa_hex(uint64_t val) {
    static char buf[32];
    int i = 31;
    buf[i] = 0;
    if (val == 0) { buf[30] = '0'; return &buf[30]; }
    while (val) {
        uint8_t nibble = val & 0xF;
        buf[--i] = nibble < 10 ? '0' + nibble : 'a' + nibble - 10;
        val >>= 4;
    }
    return &buf[i];
}

uint64_t parse_hex(const char *s) {
    const char *p = s;
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) p += 2;
    uint64_t val = 0;
    while (*p) {
        char c = *p++;
        uint8_t v;
        if (c >= '0' && c <= '9') v = c - '0';
        else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
        else break;
        val = (val << 4) | v;
    }
    return val;
}
