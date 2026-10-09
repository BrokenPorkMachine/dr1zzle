#include <drizzle/time.h>

static drizzle_clock_fn clock_source;

void drizzle_time_init(drizzle_clock_fn clock) { clock_source = clock; }
uint64_t drizzle_time_ms(void) { return clock_source ? clock_source() : 0u; }
uint32_t drizzle_time_elapsed_ms(uint32_t since) { return (uint32_t)drizzle_time_ms() - since; }
