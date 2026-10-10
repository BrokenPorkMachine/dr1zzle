/* Watchdog driver.
 *
 * The counter runs freely and the only way to stop a bite is to clear
 * RESET_EN, so the whole driver is really "keep the control word in the
 * state the caller asked for":
 *
 *   disarm    CTRL = 0
 *   arm       CUR_TIME = 0, BITE_TIME = clk * seconds, CTRL = RESET_EN
 *   kick      CUR_TIME = 0
 *   reset     CTRL = RESET_EN, BITE_TIME = 0, CUR_TIME = 0, then wait
 *
 * `reset` deserves the comment it has in the reference driver: writing a
 * bite time of zero makes the bite condition true immediately, and the SoC
 * can then take over a hundred milliseconds to actually reset. A wait is
 * what stops the caller from powering on and running code into a reset
 * that has already been scheduled.
 *
 * Note the difference between this reset and the PMGR one in start.S: the
 * PMGR path is a blanket assert-and-release of every reset line, which is
 * what a payload that has lost its bearings uses. This path is the one the
 * hardware documents, which is why the shell tries it first and falls back.
 */

#include "watchdog.h"
#include "memory_map.h"
#include "mmio.h"
#include "timer.h"
#include "uart.h"
#include "util.h"

#define WDT_BASE_WORD ((uintptr_t)WATCHDOG_BASE)

static inline void wdt_wr(uint32_t off, uint32_t val) {
    mmio_write32(WDT_BASE_WORD + off, val);
}

static inline uint32_t wdt_rd(uint32_t off) {
    return mmio_read32(WDT_BASE_WORD + off);
}

static uint32_t wdt_armed_timeout_s;
static int      wdt_disarmed_by_us;
static int      wdt_ever_armed_by_us;

uint32_t watchdog_ref_clk(void) {
    return WDT_REF_CLK_HZ;
}

static void wdt_disable_one(uint32_t ctrl_off, uint32_t cur_off) {
    /* Clearing both the trigger and the running counter is belt and
     * braces: an enabled watchdog with a counter past its bite time bites
     * as soon as it is looked at. */
    wdt_wr(ctrl_off, 0);
    wdt_wr(cur_off, 0);
}

void watchdog_init(void) {
    int was_armed = 0;

    if (wdt_rd(WDT_WD0_CTRL) & WDT_CTRL_RESET_EN) {
        was_armed = 1;
        wdt_disable_one(WDT_WD0_CTRL, WDT_WD0_CUR_TIME);
    }
    if (wdt_rd(WDT_WD1_CTRL) & WDT_CTRL_RESET_EN) {
        was_armed = 1;
        wdt_disable_one(WDT_WD1_CTRL, WDT_WD1_CUR_TIME);
    }
    if (wdt_rd(WDT_WD2_CTRL) & WDT_CTRL_RESET_EN) {
        was_armed = 1;
        wdt_disable_one(WDT_WD2_CTRL, WDT_WD2_CUR_TIME);
    }

    /* Clear a latched bark condition, or the next enable would deliver an
     * interrupt nobody asked for. */
    wdt_wr(WDT_WD0_CTRL, WDT_CTRL_IRQ_STATUS);

    if (was_armed) {
        wdt_disarmed_by_us = 1;
        uart_puts("wdog: boot firmware left a watchdog armed; disarmed\n");
    }
    wdt_armed_timeout_s = 0;
}

int watchdog_armed(void) {
    if ((wdt_rd(WDT_WD0_CTRL) | wdt_rd(WDT_WD1_CTRL) | wdt_rd(WDT_WD2_CTRL)) &
        WDT_CTRL_RESET_EN) {
        return 1;
    }
    return 0;
}

void watchdog_arm(uint32_t seconds) {
    if (seconds == 0) {
        watchdog_disarm();
        return;
    }
    if (seconds > WDT_MAX_SECONDS) seconds = WDT_MAX_SECONDS;

    wdt_wr(WDT_WD1_CTRL, 0);
    wdt_wr(WDT_WD1_CUR_TIME, 0);
    wdt_wr(WDT_WD1_BITE_TIME, (uint32_t)seconds * WDT_REF_CLK_HZ);
    wdt_wr(WDT_WD1_CTRL, WDT_CTRL_RESET_EN);

    wdt_armed_timeout_s = seconds;
    wdt_ever_armed_by_us = 1;
}

void watchdog_kick(void) {
    /* Writing the counter to zero is the documented way to feed it; there
     * is no "acknowledge" bit. */
    wdt_wr(WDT_WD1_CUR_TIME, 0);
}

void watchdog_disarm(void) {
    wdt_disable_one(WDT_WD1_CTRL, WDT_WD1_CUR_TIME);
    wdt_armed_timeout_s = 0;
}

uint32_t watchdog_time_left_s(void) {
    if (!(wdt_rd(WDT_WD1_CTRL) & WDT_CTRL_RESET_EN)) return 0;

    uint32_t bite = wdt_rd(WDT_WD1_BITE_TIME);
    uint32_t cur  = wdt_rd(WDT_WD1_CUR_TIME);
    if (cur >= bite) return 0;
    return (bite - cur) / WDT_REF_CLK_HZ;
}

void watchdog_reset(void) {
    /* The reset is queued and then takes ~120ms to land on the hardware.
     * The read-back forces the write out of any posted buffer first. */
    wdt_wr(WDT_WD1_CTRL, WDT_CTRL_RESET_EN);
    wdt_wr(WDT_WD1_BITE_TIME, 0);
    wdt_wr(WDT_WD1_CUR_TIME, 0);

    (void)wdt_rd(WDT_WD1_CUR_TIME);
    timer_sleep_ms(150);
}

void watchdog_dump(void) {
    uart_puts("wdog: base=0x");
    uart_puts(utoa_hex(WATCHDOG_BASE));
    uart_puts(" ref=");
    uart_puts(utoa(WDT_REF_CLK_HZ));
    uart_puts("Hz\n");

    uart_puts("wdog: wd0 ctrl=0x");
    uart_puts(utoa_hex(wdt_rd(WDT_WD0_CTRL)));
    uart_puts(" wd1 ctrl=0x");
    uart_puts(utoa_hex(wdt_rd(WDT_WD1_CTRL)));
    uart_puts(" bite=0x");
    uart_puts(utoa_hex(wdt_rd(WDT_WD1_BITE_TIME)));
    uart_puts(" cur=0x");
    uart_puts(utoa_hex(wdt_rd(WDT_WD1_CUR_TIME)));
    uart_puts(" wd2 ctrl=0x");
    uart_puts(utoa_hex(wdt_rd(WDT_WD2_CTRL)));
    uart_puts("\n");

    uart_puts("wdog: ");
    uart_puts(watchdog_armed() ? "armed" : "disarmed");
    if (watchdog_armed()) {
        uart_puts(", ");
        uart_puts(utoa(watchdog_time_left_s()));
        uart_puts("s left");
    }
    if (wdt_disarmed_by_us) {
        uart_puts(" [boot watchdog was disarmed at init]");
    }
    if (wdt_ever_armed_by_us) {
        uart_puts(" (armed here for ");
        uart_puts(utoa(wdt_armed_timeout_s));
        uart_puts("s)");
    }
    uart_puts("\n");
}
