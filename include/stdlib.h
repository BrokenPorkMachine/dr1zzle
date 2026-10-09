#ifndef DRIZZLE_STDLIB_H
#define DRIZZLE_STDLIB_H
#include <stddef.h>
#include <stdint.h>
#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1
#define NULL ((void *)0)
typedef int (*drizzle_compare_fn)(const void *, const void *);
void *malloc(size_t size); void *calloc(size_t count, size_t size); void *realloc(void *pointer, size_t size); void free(void *pointer);
void drizzle_heap_reset(void); void drizzle_heap_set(void *begin, size_t size);
int atoi(const char *text); long strtol(const char *restrict text, char **restrict end, int base);
unsigned long strtoul(const char *restrict text, char **restrict end, int base);
void qsort(void *base, size_t count, size_t size, drizzle_compare_fn compare);
void *bsearch(const void *key, const void *base, size_t count, size_t size, drizzle_compare_fn compare);
int abs(int value); long labs(long value);
#endif
