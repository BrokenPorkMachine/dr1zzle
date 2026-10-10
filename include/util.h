#ifndef UTIL_H
#define UTIL_H

#include <stdint.h>

/* size_t definition for freestanding environment */
typedef __SIZE_TYPE__ size_t;

const char *utoa(uint64_t val);
const char *utoa_hex(uint64_t val);
uint64_t parse_hex(const char *s);
void *memcpy(void *dest, const void *src, size_t n);
void *memset(void *s, int c, size_t n);
void *memset_explicit(void *s, int c, size_t n);

#endif
