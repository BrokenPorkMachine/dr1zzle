#include <drizzle/hardware.h>

static int valid_range(uint64_t base, uint64_t size) {
    return size != 0 && size <= UINT64_MAX - base;
}
int drizzle_hw_contains(const drizzle_hw_region *r, uint64_t base, uint64_t size) {
    return r && valid_range(r->base, r->size) && valid_range(base, size) &&
        base >= r->base && size <= r->size && base - r->base <= r->size - size;
}
static int overlap(uint64_t a, uint64_t as, uint64_t b, uint64_t bs) {
    return a < b + bs && b < a + as;
}
static int consume(uint64_t *left, uint64_t amount) {
    if (amount > *left) return 0;
    *left -= amount;
    return 1;
}
enum drizzle_hw_result drizzle_hw_validate(const drizzle_hw_profile *p) {
    unsigned ram = 0;
    uint64_t left;
    if (!p || p->version != DRIZZLE_HW_VERSION || !p->name || !p->name[0] ||
        !p->region_count || p->region_count > DRIZZLE_HW_MAX_REGIONS)
        return DRIZZLE_HW_INVALID;
    if (!valid_range(p->arena_base, p->arena_size) ||
        (p->arena_base & 15u) || (p->arena_size & 15u)) return DRIZZLE_HW_RANGE;
    for (unsigned i = 0; i < p->region_count; ++i) {
        const drizzle_hw_region *r = &p->regions[i];
        if (r->kind < DRIZZLE_RAM || r->kind > DRIZZLE_RESERVED)
            return DRIZZLE_HW_INVALID;
        if (!valid_range(r->base, r->size)) return DRIZZLE_HW_RANGE;
        for (unsigned j = 0; j < i; ++j)
            if (overlap(r->base, r->size, p->regions[j].base, p->regions[j].size))
                return DRIZZLE_HW_OVERLAP;
        if (r->kind == DRIZZLE_RAM && drizzle_hw_contains(r, p->arena_base, p->arena_size))
            ++ram;
    }
    if (ram != 1) return DRIZZLE_HW_RANGE;
    if (!p->budget.image || !p->budget.stack ||
        ((p->budget.heap | p->budget.stack | p->budget.reserve | p->budget.image) & 15u))
        return DRIZZLE_HW_BUDGET;
    left = p->arena_size;
    if (!consume(&left, p->budget.image) || !consume(&left, p->budget.heap) ||
        !consume(&left, p->budget.stack) || !consume(&left, p->budget.reserve))
        return DRIZZLE_HW_BUDGET;
    return DRIZZLE_HW_OK;
}
enum drizzle_hw_result drizzle_hw_admit(const drizzle_hw_profile *p,
    uint64_t image, uint64_t heap, uint64_t stack, uint64_t *remaining) {
    enum drizzle_hw_result result = drizzle_hw_validate(p);
    uint64_t left;
    if (result != DRIZZLE_HW_OK) return result;
    if (!image || !stack || image > p->budget.image || heap > p->budget.heap ||
        stack > p->budget.stack) return DRIZZLE_HW_BUDGET;
    left = p->arena_size - p->budget.reserve;
    /* Validation proves these subtractions cannot underflow. */
    left -= image;
    left -= heap;
    left -= stack;
    if (remaining) *remaining = left;
    return DRIZZLE_HW_OK;
}
