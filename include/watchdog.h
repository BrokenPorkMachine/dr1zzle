#ifndef WATCHDOG_H
#define WATCHDOG_H

#include <stdint.h>

/* Apple SoC watchdog.
 *
 * Layout grounding: the register map below is the one published by
 * drivers/watchdog/apple_wdt.c. The block carries three independent
 * watchdogs: WD0 resets the SoC into recovery mode, WD1 and WD2 reset it
 * normally. A watchdog "bites" when its running counter reaches the bite
 * time, and WD1 additionally has a bark interrupt that this payload does
 * not use, because using it would mean claiming an AIC line.
 *
 * What is NOT verified: WATCHDOG_BASE from memory_map.h, and the reference
 * clock the counter counts up at. The reference clock is exposed so a
 * mismatch shows up as a wrong timeout rather than as silence.
 *
 * Why the payload disarms it at init: an armed watchdog the boot firmware
 * left running will reset the device while the payload is sitting at a
 * shell prompt, which is indistinguishable from a crash. Arming is then an
 * explicit decision, and `wdog kick` is how a caller holds it off.
 */

/* WD0 bites to recovery; it is never armed by this driver. */
#define WDT_WD0_CUR_TIME      0x00
#define WDT_WD0_BITE_TIME     0x04
#define WDT_WD0_BARK_TIME     0x08
#define WDT_WD0_CTRL          0x0C

/* WD1 resets normally. This is the one the payload arms. */
#define WDT_WD1_CUR_TIME      0x10
#define WDT_WD1_BITE_TIME     0x14
#define WDT_WD1_CTRL          0x1C

/* WD2 resets normally as well and is left alone. */
#define WDT_WD2_CUR_TIME      0x20
#define WDT_WD2_BITE_TIME     0x24
#define WDT_WD2_CTRL          0x2C

#define WDT_CTRL_IRQ_EN       (1u << 0)
#define WDT_CTRL_IRQ_STATUS   (1u << 1)
#define WDT_CTRL_RESET_EN     (1u << 2)

/* Reference clock. 24 MHz is the slowest of the clocks the Apple platform
 * publishes, and therefore the safest assumption: a counter that ticks
 * slower than expected bites late rather than early. */
#define WDT_REF_CLK_HZ        24000000u

/* Longest armable timeout, bounded by the 32-bit bite register. */
#define WDT_MAX_SECONDS       (0xFFFFFFFFu / WDT_REF_CLK_HZ)

void watchdog_init(void);

/* True if any of the three watchdogs has RESET_EN set. */
int  watchdog_armed(void);

/* Arms WD1 to reset the SoC in `seconds` if it is not kicked. Clamped to
 * WDT_MAX_SECONDS. */
void watchdog_arm(uint32_t seconds);
void watchdog_kick(void);
void watchdog_disarm(void);

/* Seconds left on WD1, 0 if it is not armed. */
uint32_t watchdog_time_left_s(void);

/* Immediate SoC reset through WD1, in the way the reference driver's
 * restart callback does it. */
void watchdog_reset(void);

uint32_t watchdog_ref_clk(void);
void watchdog_dump(void);

#endif /* WATCHDOG_H */
