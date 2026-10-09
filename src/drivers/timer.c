#include "timer.h"

void timer_init(void) {
    __asm__ volatile(
        "msr cntp_ctl_el0, %0\n"
        "msr cntv_ctl_el0, %0"
        :: "r"(1ULL)
    );
}

uint64_t timer_now_cycles(void) {
    uint64_t val;
    __asm__ volatile("mrs %0, cntpct_el0" : "=r"(val));
    return val;
}

uint64_t timer_now_us(void) {
    return timer_now_cycles() / 24;
}

uint64_t timer_now_ms(void) {
    return timer_now_us() / 1000;
}

void timer_sleep_us(uint64_t us) {
    uint64_t deadline = timer_now_us() + us;
    while (timer_now_us() < deadline) {
        __asm__ volatile("yield" ::: "memory");
    }
}

void timer_sleep_ms(uint64_t ms) {
    timer_sleep_us(ms * 1000);
}
