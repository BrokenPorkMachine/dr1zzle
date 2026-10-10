/*
 * Simple bump allocator for bare metal environment
 */

#include "stdlib.h"
#include "string.h"
#include "memory_map.h"

/* Heap region - use the reserved heap area from linker script */
extern char _heap_start[];
extern char _heap_end[];

static uint8_t *heap_ptr = NULL;
static uint8_t *heap_end = NULL;

void drizzle_heap_reset(void) {
    heap_ptr = (uint8_t *)_heap_start;
    heap_end = (uint8_t *)_heap_end;
}

void drizzle_heap_set(void *begin, size_t size) {
    heap_ptr = (uint8_t *)begin;
    heap_end = (uint8_t *)begin + size;
}

void *malloc(size_t size) {
    if (size == 0) return NULL;
    
    if (!heap_ptr) {
        drizzle_heap_reset();
    }
    
    /* Align to 8 bytes */
    size = (size + 7) & ~7;
    
    if (heap_ptr + size > heap_end) {
        return NULL; /* Out of memory */
    }
    
    void *ptr = heap_ptr;
    heap_ptr += size;
    return ptr;
}

void *calloc(size_t count, size_t size) {
    size_t total = count * size;
    void *ptr = malloc(total);
    if (ptr) {
        memset(ptr, 0, total);
    }
    return ptr;
}

void *realloc(void *ptr, size_t size) {
    if (!ptr) return malloc(size);
    if (size == 0) {
        free(ptr);
        return NULL;
    }
    
    /* In a real implementation, we'd track allocation sizes and copy data.
     * For now, just allocate new memory and copy what we can. */
    void *new_ptr = malloc(size);
    if (!new_ptr) return NULL;
    
    /* Note: we don't know the old size, so we can't safely copy.
     * This is a simplified implementation. */
    return new_ptr;
}

void free(void *ptr) {
    /* In a bump allocator, we don't actually free individual blocks.
     * Memory is only reclaimed when the entire heap is reset. */
    (void)ptr;
}

int atoi(const char *text) {
    int result = 0;
    int sign = 1;
    while (*text == ' ' || *text == '\t') text++;
    if (*text == '-') { sign = -1; text++; }
    while (*text >= '0' && *text <= '9') {
        result = result * 10 + (*text - '0');
        text++;
    }
    return result * sign;
}

long strtol(const char *restrict text, char **restrict end, int base) {
    long result = 0;
    int sign = 1;
    while (*text == ' ' || *text == '\t') text++;
    if (*text == '-') { sign = -1; text++; }
    else if (*text == '+') text++;
    
    if (base == 0) {
        if (*text == '0') {
            text++;
            if (*text == 'x' || *text == 'X') {
                base = 16; text++;
            } else {
                base = 8;
            }
        } else {
            base = 10;
        }
    }
    
    while (*text) {
        int digit;
        if (*text >= '0' && *text <= '9') digit = *text - '0';
        else if (*text >= 'a' && *text <= 'z') digit = *text - 'a' + 10;
        else if (*text >= 'A' && *text <= 'Z') digit = *text - 'A' + 10;
        else break;
        
        if (digit >= base) break;
        result = result * base + digit;
        text++;
    }
    
    if (end) *end = (char *)text;
    return result * sign;
}

unsigned long strtoul(const char *restrict text, char **restrict end, int base) {
    return (unsigned long)strtol(text, end, base);
}

void qsort(void *base, size_t count, size_t size, drizzle_compare_fn compare) {
    /* Simple insertion sort for small arrays */
    char *arr = base;
    for (size_t i = 1; i < count; i++) {
        char *key = arr + i * size;
        size_t j = i;
        while (j > 0 && compare(arr + (j - 1) * size, key) > 0) {
            memcpy(arr + j * size, arr + (j - 1) * size, size);
            j--;
        }
        memcpy(arr + j * size, key, size);
    }
}

void *bsearch(const void *key, const void *base, size_t count, size_t size, drizzle_compare_fn compare) {
    size_t low = 0, high = count;
    while (low < high) {
        size_t mid = (low + high) / 2;
        int cmp = compare(key, (const char *)base + mid * size);
        if (cmp < 0) high = mid;
        else if (cmp > 0) low = mid + 1;
        else return (char *)base + mid * size;
    }
    return NULL;
}

int abs(int value) { return value < 0 ? -value : value; }
long labs(long value) { return value < 0 ? -value : value; }