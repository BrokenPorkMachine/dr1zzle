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
