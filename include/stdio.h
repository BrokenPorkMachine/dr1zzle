#ifndef DRIZZLE_STDIO_H
#define DRIZZLE_STDIO_H
#include <stdarg.h>
#include <stddef.h>
int vsnprintf(char *restrict buffer, size_t size, const char *restrict format, va_list arguments);
int snprintf(char *restrict buffer, size_t size, const char *restrict format, ...);
int puts(const char *text); int putchar(int character);
#endif
