#ifndef DRIZZLE_LIMITS_H
#define DRIZZLE_LIMITS_H
#include <stddef.h>
#include <stdint.h>
#define CHAR_BIT 8
#define SCHAR_MIN (-128)
#define SCHAR_MAX 127
#define UCHAR_MAX 255u
#define INT_MIN INT32_MIN
#define INT_MAX INT32_MAX
#define UINT_MAX UINT32_MAX
#define LONG_MAX __LONG_MAX__
#define LONG_MIN (-LONG_MAX - 1L)
#define ULONG_MAX (~0UL)
#define SIZE_MAX ((size_t)-1)
#endif
