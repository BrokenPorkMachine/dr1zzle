#ifndef DRIZZLE_HARDWARE_H
#define DRIZZLE_HARDWARE_H
#include <stddef.h>
#include <stdint.h>

/* Trusted, compiled board data; never cast an incoming DTB to this type. */
#define DRIZZLE_HW_MAX_REGIONS 8u
#define DRIZZLE_HW_VERSION 1u
enum drizzle_region_kind { DRIZZLE_RAM = 1, DRIZZLE_MMIO, DRIZZLE_RESERVED };
typedef struct {
    uint64_t base, size;
    enum drizzle_region_kind kind;
} drizzle_hw_region;
typedef struct {
    uint64_t image, heap, stack, reserve;
} drizzle_hw_budget;
typedef struct {
    unsigned version;
    const char *name;
    unsigned region_count;
    drizzle_hw_region regions[DRIZZLE_HW_MAX_REGIONS];
    /* Exclusive OS-owned arena, contained in exactly one RAM region. */
    uint64_t arena_base, arena_size;
    drizzle_hw_budget budget;
} drizzle_hw_profile;
enum drizzle_hw_result {
    DRIZZLE_HW_OK = 0, DRIZZLE_HW_INVALID, DRIZZLE_HW_RANGE,
    DRIZZLE_HW_OVERLAP, DRIZZLE_HW_BUDGET
};
/* Pure validation: no allocations, MMIO, probing, or driver side effects. */
enum drizzle_hw_result drizzle_hw_validate(const drizzle_hw_profile *profile);
/* Usage values are actual image (including BSS), heap, and stack bytes.
 * On failure remaining is left untouched; on success it excludes reserve. */
enum drizzle_hw_result drizzle_hw_admit(const drizzle_hw_profile *profile,
    uint64_t image, uint64_t heap, uint64_t stack, uint64_t *remaining);
/* Half-open containment, rejecting zero size and overflowing ranges. */
int drizzle_hw_contains(const drizzle_hw_region *region, uint64_t base, uint64_t size);
extern const drizzle_hw_profile drizzle_hw_qemu_small;
extern const drizzle_hw_profile drizzle_hw_qemu_monitor;
#endif
