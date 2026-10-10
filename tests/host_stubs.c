/* Host-side stubs so the display driver can be linked and driven by
 * tests/test_display.py on a workstation.
 *
 * Only functions the display driver actually calls are here. timer_wait_reg
 * is a busy-wait against a device register, which has no host equivalent, so
 * the harness reports "condition met" and lets the caller proceed. Tests that
 * depend on real timing behaviour belong on hardware, not here.
 */

#include <stdint.h>

int timer_wait_reg(volatile uint32_t *reg, uint32_t mask, uint32_t want,
                   uint32_t timeout_us) {
    (void)reg; (void)mask; (void)want; (void)timeout_us;
    return 0;
}