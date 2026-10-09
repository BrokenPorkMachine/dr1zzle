#include "string.h"
#include <stdint.h>

void *memcpy(void *dest, const void *src, size_t n) {
    uint8_t *d = (uint8_t *)dest;
    const uint8_t *s = (const uint8_t *)src;
    while (n--) *d++ = *s++;
    return dest;
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
