#ifndef TIMER_H
#define TIMER_H

#include <stdint.h>

#define TICKS_PER_SEC 24000000ULL

void timer_init(void);
uint64_t timer_now_cycles(void);
uint64_t timer_now_us(void);
uint64_t timer_now_ms(void);
void timer_sleep_us(uint64_t us);
void timer_sleep_ms(uint64_t ms);

#endif
