/*
 * libc workarounds for stage3 bootloader
 * Based on pongoOS libc_workarounds.h
 */

#ifndef LIBC_WORKAROUNDS_H
#define LIBC_WORKAROUNDS_H

#include <stdint.h>
#include <stddef.h>

/* Minimal string functions */
static inline void *memset(void *s, int c, size_t n) {
    uint8_t *p = s;
    while (n--) *p++ = (uint8_t)c;
    return s;
}

static inline void *memcpy(void *dest, const void *src, size_t n) {
    uint8_t *d = dest;
    const uint8_t *s = src;
    while (n--) *d++ = *s++;
    return dest;
}

static inline size_t strlen(const char *s) {
    size_t len = 0;
    while (*s++) len++;
    return len;
}

static inline char *strcpy(char *dest, const char *src) {
    char *d = dest;
    while ((*d++ = *src++));
    return dest;
}

/* 128-bit memory operations */
static inline void smemcpy128(void *dest, const void *src, size_t blocks) {
    uint64_t *d = dest;
    const uint64_t *s = src;
    while (blocks--) {
        d[0] = s[0];
        d[1] = s[1];
        d += 2;
        s += 2;
    }
}

static inline void smemset(void *dest, uint8_t val, size_t n) {
    uint8_t *d = dest;
    while (n--) *d++ = val;
}

/* Cache operations */
static inline void invalidate_icache(void) {
    __asm__ volatile("ic ialluis" ::: "memory");
    __asm__ volatile("dsb sy; isb" ::: "memory");
}

/* CPU identification */
static inline int is_16k(void) {
    uint64_t mmfr0;
    __asm__ volatile("mrs %0, id_aa64mmfr0_el1" : "=r"(mmfr0));
    return ((mmfr0 >> 20) & 0xf) == 0x1;
}

static inline uint64_t get_ticks(void) {
    uint64_t val;
    __asm__ volatile("mrs %0, cntpct_el0" : "=r"(val));
    return val;
}

#endif /* LIBC_WORKAROUNDS_H */