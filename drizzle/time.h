#ifndef DRIZZLE_TIME_H
#define DRIZZLE_TIME_H

#include <stdint.h>

/* Monotonic millisecond clock.
 *
 * The board layer owns the hardware counter; the stack only ever asks for a
 * millisecond stamp. Tests inject a synthetic clock through the same seam, so
 * retransmission and expiry logic can be verified without real time passing.
 */
typedef uint64_t (*drizzle_clock_fn)(void);

void drizzle_time_init(drizzle_clock_fn clock);
uint64_t drizzle_time_ms(void);

/* Wrap-safe "how long since" helper. Timestamps are 32-bit so that arithmetic
 * stays correct across the 49-day millisecond rollover. */
uint32_t drizzle_time_elapsed_ms(uint32_t since);

#endif
