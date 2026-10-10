/*
 * Minimal Timer driver for Stage 1 only
 * Provides timer_init, timer_now_ms, timer_sleep_ms
 */

#include "timer.h"
#include "mmio.h"

#define TIMER_BASE      0x20E100000ULL
#define CNTPCT_EL0      0x00
#define CNTP_CTL_EL0    0x08
#define CNTP_CVAL_EL0   0x10

static uint64_t g_timer_freq_hz = 24000000ULL;  /* 24 MHz default */

void timer_init(void) {
    /* Read timer frequency from CNTFRQ_EL0 */
    uint64_t freq;
    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(freq));
    g_timer_freq_hz = freq ? freq : 24000000ULL;
    
    /* Enable timer, no interrupt */
    mmio_write32(TIMER_BASE + CNTP_CTL_EL0, 1);
}

uint64_t timer_freq_hz(void) {
    return g_timer_freq_hz;
}

uint64_t timer_now_cycles(void) {
    uint64_t val;
    __asm__ volatile("mrs %0, cntpct_el0" : "=r"(val));
    return val;
}

uint64_t timer_now_us(void) {
    return (timer_now_cycles() * 1000000ULL) / timer_freq_hz();
}

uint64_t timer_now_ms(void) {
    return (timer_now_cycles() * 1000ULL) / timer_freq_hz();
}

void timer_sleep_us(uint64_t us) {
    uint64_t start = timer_now_cycles();
    uint64_t target = start + (us * timer_freq_hz()) / 1000000ULL;
    while (timer_now_cycles() < target) {
        __asm__ volatile("yield" ::: "memory");
    }
}

void timer_sleep_ms(uint64_t ms) {
    timer_sleep_us(ms * 1000ULL);
}