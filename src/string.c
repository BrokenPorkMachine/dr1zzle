#include "string.h"
#include <stdint.h>
#include <stdlib.h>

void *memcpy(void *dest, const void *src, size_t n) {
    uint8_t *d = (uint8_t *)dest;
    const uint8_t *s = (const uint8_t *)src;
    while (n--) *d++ = *s++;
    return dest;
}

/* Overlap-safe copy. The firmware loader moves an image from the front of the
 * staging window down over its own header, which is an overlap a plain
 * memcpy would clobber in the wrong direction. */
void *memmove(void *dest, const void *src, size_t n) {
    uint8_t *d = (uint8_t *)dest;
    const uint8_t *s = (const uint8_t *)src;
    if (d == s || n == 0) return dest;
    if (d < s) {
        while (n--) *d++ = *s++;
    } else {
        d += n;
        s += n;
        while (n--) *--d = *--s;
    }
    return dest;
}

int memcmp(const void *a, const void *b, size_t n) {
    const uint8_t *pa = (const uint8_t *)a;
    const uint8_t *pb = (const uint8_t *)b;
    while (n--) {
        if (*pa != *pb) return (int)*pa - (int)*pb;
        pa++;
        pb++;
    }
    return 0;
}

void *memset(void *s, int c, size_t n) {
    uint8_t *p = (uint8_t *)s;
    (void)c;
    while (n--) *p++ = (uint8_t)c;
    return s;
}

int strcmp(const char *s1, const char *s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++; s2++;
    }
    return (unsigned char)*s1 - (unsigned char)*s2;
}

char *strcpy(char *dest, const char *src) {
    char *d = dest;
    while ((*d++ = *src++));
    return dest;
}

char *strcat(char *dest, const char *src) {
    char *d = dest;
    while (*d) d++;
    while ((*d++ = *src++));
    return dest;
}

char *strncpy(char *dest, const char *src, size_t n) {
    char *d = dest;
    while (n-- && (*d++ = *src++));
    while (n--) *d++ = 0;
    return dest;
}

size_t strlen(const char *s) {
    size_t len = 0;
    while (*s++) len++;
    return len;
}

int strncmp(const char *s1, const char *s2, size_t n) {
    while (n-- && *s1 && (*s1 == *s2)) {
        s1++; s2++;
    }
    if (n == (size_t)-1) return 0;
    return (unsigned char)*s1 - (unsigned char)*s2;
}

char *strdup(const char *s) {
    if (!s) return NULL;
    size_t len = strlen(s) + 1;
    char *d = malloc(len);
    if (!d) return NULL;
    return memcpy(d, s, len);
}
