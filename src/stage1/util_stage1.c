/*
 * Minimal utility functions for Stage 1
 * Only functions not in string_stage1.c
 */

#include "util.h"
#include <stddef.h>

/* Stage 2 constants needed for verification */
#define STAGE2_MAGIC    0x5354414732  /* "STAG2" */
#define STAGE2_MAX_SIZE (128 * 1024)  /* 128 KB max */

/* Stage 2 header definition (must match stage1.c) */
typedef struct __attribute__((packed)) {
    uint64_t magic;                 /* STAGE2_MAGIC */
    uint32_t version;               /* Stage 2 format version */
    uint32_t size;                  /* Total size in bytes */
    uint32_t compressed_size;       /* Compressed size (0 = uncompressed) */
    uint32_t crc32;                 /* CRC32 of payload */
    uint32_t flags;                 /* Bit 0 = compressed (LZ4) */
    uint64_t load_address;          /* Where to load in SRAM */
    uint64_t entry_point;           /* Entry point offset from load_address */
    uint8_t  reserved[24];          /* Future expansion */
} stage2_header_t;

#include "uart.h"
#include "memory_map.h"

const char *utoa(uint64_t val) {
    static char buf[32];
    char *p = buf + 31;
    *p = '\0';
    if (val == 0) { *--p = '0'; return p; }
    while (val) {
        *--p = '0' + (val % 10);
        val /= 10;
    }
    return p;
}

const char *utoa_hex(uint64_t val) {
    static char buf[32];
    char *p = buf + 31;
    *p = '\0';
    if (val == 0) { *--p = '0'; return p; }
    while (val) {
        uint8_t nibble = val & 0xF;
        *--p = nibble < 10 ? '0' + nibble : 'a' + nibble - 10;
        val >>= 4;
    }
    return p;
}

uint32_t crc32(const void *data, size_t len) {
    const uint8_t *p = data;
    uint32_t crc = ~0U;
    while (len--) {
        crc ^= *p++;
        for (int i = 0; i < 8; i++) {
            crc = (crc >> 1) ^ ((crc & 1) ? 0xEDB88320 : 0);
        }
    }
    return ~crc;
}

void *memset_explicit(void *s, int c, size_t n) {
    uint8_t *p = s;
    while (n--) *p++ = (uint8_t)c;
    return s;
}

void *memmove(void *dest, const void *src, size_t n) {
    if (dest <= src) return memcpy(dest, src, n);
    uint8_t *d = (uint8_t *)dest + n;
    const uint8_t *s = (const uint8_t *)src + n;
    while (n--) *--d = *--s;
    return dest;
}

/* ========================================================================
 * Stage 2 Header Verification
 * ======================================================================== */

#include "uart.h"
#include "memory_map.h"

#define STAGE2_MAGIC    0x5354414732  /* "STAG2" */
#define STAGE2_MAX_SIZE (128 * 1024)  /* 128 KB max */

int stage1_verify_stage2_header(const stage2_header_t *hdr) {
    if (hdr->magic != STAGE2_MAGIC) {
        uart_puts("stage1: Invalid Stage 2 magic\n");
        return -1;
    }
    if (hdr->version != 1) {
        uart_puts("stage1: Unsupported Stage 2 version\n");
        return -1;
    }
    if (hdr->size > STAGE2_MAX_SIZE) {
        uart_puts("stage1: Stage 2 too large\n");
        return -1;
    }
    return 0;
}