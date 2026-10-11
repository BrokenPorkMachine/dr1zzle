/* Host-side stubs for SEP driver tests.
 *
 * Provides timer_sleep_us that counts calls to allow mock time advancement.
 */

#include <stdint.h>

static uint32_t timer_call_count = 0;
static uint32_t timer_advance_us = 0;

int timer_sleep_us(uint32_t us) {
    timer_call_count++;
    timer_advance_us += us;
    return 0;
}

void test_timer_reset(void) {
    timer_call_count = 0;
    timer_advance_us = 0;
}

uint32_t test_timer_calls(void) {
    return timer_call_count;
}

uint32_t test_timer_advanced(void) {
    return timer_advance_us;
}