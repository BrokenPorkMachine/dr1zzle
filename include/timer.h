#ifndef TIMER_H
#define TIMER_H

#include <stdint.h>

/* CNTPCT_EL0 frequency in Hz, read from CNTFRQ_EL0 by timer_init().
 * Before timer_init() runs this is the 24MHz architectural default. */
#define TICKS_PER_SEC 24000000ULL

void timer_init(void);

/* Actual counter frequency as reported by the hardware. */
uint64_t timer_freq_hz(void);

uint64_t timer_now_cycles(void);
uint64_t timer_now_us(void);
uint64_t timer_now_ms(void);
void timer_sleep_us(uint64_t us);
void timer_sleep_ms(uint64_t ms);

/* Poll (*reg & mask) == want, spinning with yield. Returns 0 on match,
 * -1 on timeout. timeout_us of 0 is a single check. */
int timer_wait_reg(volatile uint32_t *reg, uint32_t mask, uint32_t want,
                   uint32_t timeout_us);

#endif /* TIMER_H */