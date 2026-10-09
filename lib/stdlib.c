#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <string.h>

typedef struct block { size_t size; struct block *next; int free; } block_t;
#define ALIGNMENT 16u
#define HEADER_SIZE ((sizeof(block_t) + (ALIGNMENT - 1u)) & ~(ALIGNMENT - 1u))

int drizzle_errno;
static unsigned char *heap_start;
static unsigned char *heap_limit;
static block_t *first_block;

static size_t align_size(size_t size) { if (size > SIZE_MAX - (ALIGNMENT - 1u)) return 0; return (size + (ALIGNMENT - 1u)) & ~(size_t)(ALIGNMENT - 1u); }
void drizzle_heap_set(void *start, size_t size) { heap_start = start; heap_limit = heap_start ? heap_start + size : 0; first_block = 0; drizzle_errno = 0; }
void drizzle_heap_reset(void) { first_block = 0; drizzle_errno = 0; }

static block_t *find_block(const void *pointer) { for (block_t *b = first_block; b; b = b->next) if ((unsigned char *)b + HEADER_SIZE == pointer) return b; return 0; }
static void split_block(block_t *block, size_t needed) {
    if (block->size < needed + HEADER_SIZE + ALIGNMENT) return;
    block_t *tail = (block_t *)((unsigned char *)block + HEADER_SIZE + needed);
    tail->size = block->size - needed - HEADER_SIZE; tail->next = block->next; tail->free = 1;
    block->size = needed; block->next = tail;
}
static void coalesce(void) {
    for (block_t *b = first_block; b && b->next; ) {
        if (b->free && b->next->free && (unsigned char *)b + HEADER_SIZE + b->size == (unsigned char *)b->next) { b->size += HEADER_SIZE + b->next->size; b->next = b->next->next; }
        else b = b->next;
    }
}
void *malloc(size_t size) {
    size = align_size(size);
    if (!size || !heap_start) { drizzle_errno = ENOMEM; return 0; }
    block_t *last = 0;
    for (block_t *b = first_block; b; last = b, b = b->next) if (b->free && b->size >= size) { split_block(b, size); b->free = 0; return (unsigned char *)b + HEADER_SIZE; }
    unsigned char *at = last ? (unsigned char *)last + HEADER_SIZE + last->size : heap_start;
    if (at > heap_limit || (size_t)(heap_limit - at) < HEADER_SIZE + size) { drizzle_errno = ENOMEM; return 0; }
    block_t *b = (block_t *)at; b->size = size; b->next = 0; b->free = 0;
    if (last) last->next = b; else first_block = b;
    return (unsigned char *)b + HEADER_SIZE;
}
void free(void *pointer) { block_t *b = find_block(pointer); if (b) { b->free = 1; coalesce(); } }
void *calloc(size_t count, size_t size) { if (size && count > SIZE_MAX / size) { drizzle_errno = ENOMEM; return 0; } size_t total = count * size; void *p = malloc(total ? total : 1u); if (p) memset(p, 0, total); return p; }
void *realloc(void *pointer, size_t size) {
    if (!pointer) return malloc(size); if (!size) { free(pointer); return 0; }
    block_t *old = find_block(pointer); if (!old) { drizzle_errno = EINVAL; return 0; }
    size_t needed = align_size(size); if (!needed) { drizzle_errno = ENOMEM; return 0; }
    if (old->size >= needed) { split_block(old, needed); return pointer; }
    void *replacement = malloc(size); if (!replacement) return 0; memcpy(replacement, pointer, old->size); free(pointer); return replacement;
}
static int digit(int c) { if (isdigit(c)) return c - '0'; if (isalpha(c)) return tolower(c) - 'a' + 10; return -1; }
unsigned long strtoul(const char *text, char **end, int base) {
    const char *origin = text; while (isspace((unsigned char)*text)) text++; if (*text == '+') text++;
    if (base && (base < 2 || base > 36)) { drizzle_errno = EINVAL; if (end) *end = (char *)origin; return 0; }
    if (!base) { base = 10; if (*text == '0') { base = 8; if (text[1] == 'x' || text[1] == 'X') { base = 16; text += 2; } } }
    else if (base == 16 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) text += 2;
    const char *digits = text; unsigned long value = 0; int d;
    while ((d = digit((unsigned char)*text)) >= 0 && d < base) {
        if (value > (ULONG_MAX - (unsigned long)d) / (unsigned long)base) { drizzle_errno = ERANGE; value = ULONG_MAX; do { text++; d = digit((unsigned char)*text); } while (d >= 0 && d < base); break; }
        value = value * (unsigned long)base + (unsigned long)d; text++;
    }
    if (end) *end = (char *)(text == digits ? origin : text); return value;
}
long strtol(const char *text, char **end, int base) {
    const char *origin = text; while (isspace((unsigned char)*text)) text++; int negative = *text == '-'; if (negative || *text == '+') text++;
    char *tail; unsigned long value = strtoul(text, &tail, base); if (tail == text) { if (end) *end = (char *)origin; return 0; }
    unsigned long limit = negative ? (unsigned long)(-(LONG_MIN + 1L)) + 1UL : (unsigned long)LONG_MAX;
    if (value > limit) { drizzle_errno = ERANGE; if (end) *end = tail; return negative ? LONG_MIN : LONG_MAX; }
    if (end) *end = tail; return negative ? (value == limit ? LONG_MIN : -(long)value) : (long)value;
}
int atoi(const char *text) { return (int)strtol(text, 0, 10); }
int abs(int value) { return value == INT_MIN ? INT_MAX : (value < 0 ? -value : value); }
long labs(long value) { return value == LONG_MIN ? LONG_MAX : (value < 0 ? -value : value); }
static void swap(unsigned char *a, unsigned char *b, size_t size) { while (size--) { unsigned char t = *a; *a++ = *b; *b++ = t; } }
void qsort(void *base, size_t count, size_t size, drizzle_compare_fn compare) { unsigned char *items = base; if (!items || !compare || !size || count > SIZE_MAX / size) return; for (size_t i = 1; i < count; i++) for (size_t j = i; j && compare(items + (j - 1u) * size, items + j * size) > 0; j--) swap(items + (j - 1u) * size, items + j * size, size); }
void *bsearch(const void *key, const void *base, size_t count, size_t size, drizzle_compare_fn compare) { if (!key || !base || !compare || !size || count > SIZE_MAX / size) return 0; const unsigned char *items = base; size_t low = 0, high = count; while (low < high) { size_t mid = low + (high - low) / 2u; const void *item = items + mid * size; int order = compare(key, item); if (!order) return (void *)item; if (order < 0) high = mid; else low = mid + 1u; } return 0; }
