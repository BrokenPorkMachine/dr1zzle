#include "timer.h"
#include "mmio.h"

/* CNTFRQ_EL0 read back from the system register is authoritative; the
 * original assumed 24MHz and used a local TICKS_PER_SEC constant that
 * nothing verified. Apple silicon does not always run the generic timer at
 * 24MHz, and QEMU virt does not either, so read it. */

static uint64_t tick_hz = 24000000ULL;

void timer_init(void) {
    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(tick_hz));
    if (tick_hz == 0) tick_hz = 24000000ULL;

    /* Enable the counter and mask its interrupt output.
     *
     * The previous value, 1, enabled the timer *interrupt* with nothing to
     * handle it: on this part the ARM generic timers are delivered as FIQs
     * that bypass the AIC, so a comparator the boot firmware left programmed
     * landed in fiq_handler(), which halts the payload. There is no timer
     * interrupt here to want -- every wait in this build polls
     * CNTPCT_EL0 -- so the output is masked. */
    __asm__ volatile(
        "msr cntp_ctl_el0, %0\n\t"
        "msr cntv_ctl_el0, %0\n\t"
        "isb"
        :: "r"(3ULL) : "memory");   /* bit0 ENABLE | bit1 IMASK */
}

uint64_t timer_freq_hz(void) {
    return tick_hz;
}

uint64_t timer_now_cycles(void) {
    uint64_t v;
    __asm__ volatile("mrs %0, cntpct_el0" : "=r"(v));
    return v;
}

uint64_t timer_now_us(void) {
    return timer_now_cycles() / (tick_hz / 1000000ULL);
}

uint64_t timer_now_ms(void) {
    return timer_now_cycles() / (tick_hz / 1000ULL);
}

void timer_sleep_us(uint64_t us) {
    uint64_t deadline = timer_now_cycles() + us * (tick_hz / 1000000ULL);
    while ((int64_t)(timer_now_cycles() - deadline) < 0) {
        __asm__ volatile("yield" ::: "memory");
    }
}

void timer_sleep_ms(uint64_t ms) {
    timer_sleep_us(ms * 1000ULL);
}

/* Busy-wait on a condition, so drivers can express "wait for bit 7 of this
 * MMIO register" without each one open-coding it. */
int timer_wait_reg(volatile uint32_t *reg, uint32_t mask, uint32_t want,
                   uint32_t timeout_us) {
    uint64_t deadline = timer_now_cycles() + timeout_us * (tick_hz / 1000000ULL);
    for (;;) {
        if ((mmio_read32((uintptr_t)reg) & mask) == want) return 0;
        if ((int64_t)(timer_now_cycles() - deadline) >= 0) return -1;
        __asm__ volatile("yield" ::: "memory");
    }
}
