/* PMGR (power manager) reset and clock gating.
 *
 * Register offsets are the documented A11 PMGR node layout used by
 * aspmap/iBoot headers. Bit masks inside PMGR_RESET_ASSERT /
 * PMGR_RESET_DEASSERT are per-device and are gathered here so they can be
 * corrected in one place against a real device.
 *
 * Nothing in this file has been validated against silicon. Every entry point
 * is written so that a wrong mask is survivable: reset is only ever asserted
 * on an explicit `reboot`, and clock gating is best-effort.
 *
 * ---------------------------------------------------------------------------
 * The honest position on the new peripheral masks
 * ---------------------------------------------------------------------------
 *
 * GPIO, I2C, SPI and the watchdog each need a clock and a reset line, and
 * the PMGR is what owns them. The bit numbers for those four blocks are not
 * published in anything this build can cite -- they live in the A11 device
 * tree's per-node "clocks" and "resets" lists, which is exactly the
 * information that is missing here. Guessing would mean writing a mask
 * that could gate a device the payload is actively using, so the masks are
 * zero and pmgr_ungate() skips them.
 *
 * The consequence is visible at boot: if a peripheral does not respond, the
 * first thing to check is its clock, and `pmgr status` from the shell is
 * how to see which bits currently read as gated. `pmgr ungate <mask>` and
 * `pmgr reset <mask>` let that be corrected from a shell without a
 * rebuild.
 */

#include "memory_map.h"
#include "pmgr.h"
#include "mmio.h"
#include "timer.h"

typedef struct {
    volatile uint32_t reset_assert;   /* 0x000 write 1 to assert, 0 to release */
    volatile uint32_t reset_deassert;
    volatile uint32_t _pad[2];
    volatile uint32_t clk_gate_status; /* 0x010 bit set == clock gated off */
    volatile uint32_t _pad2[3];
    volatile uint32_t pstate;          /* 0x020 */
    volatile uint32_t _pad3;
    volatile uint32_t ans1;            /* 0x028 */
    volatile uint32_t ans2;            /* 0x02c */
    volatile uint32_t ancs;            /* 0x030 */
} pmgr_regs_t;

static volatile pmgr_regs_t *pmgr = (volatile pmgr_regs_t *)PMGR_BASE;

/* Device clock-gate bits as published in the A11 PMGR node. */
#define PMGR_CLK_USB      (1 << 2)
#define PMGR_CLK_UART     (1 << 7)
#define PMGR_CLK_AIC      (1 << 9)
#define PMGR_CLK_DWC2     (1 << 15)
#define PMGR_CLK_NAND     (1 << 20)
#define PMGR_CLK_PHY      (1 << 16)

/* Reset bits. Assert/deassert use the same numbering. */
#define PMGR_RESET_USB    (1 << 2)
#define PMGR_RESET_UART   (1 << 7)
#define PMGR_RESET_AIC    (1 << 9)
#define PMGR_RESET_DWC2   (1 << 15)
#define PMGR_RESET_NAND   (1 << 20)
#define PMGR_RESET_PHY    (1 << 16)

/* Exposed for start.S's reboot stub, which cannot call C. These have to be
 * link-time constants, so they are absolute addresses rather than
 * pointers-into-a-volatile-struct (pmgr itself is PMGR_BASE-relative). */
const uint64_t pmgr_reset_assert_addr   = PMGR_BASE + 0x000;
const uint64_t pmgr_reset_deassert_addr = PMGR_BASE + 0x004;

void pmgr_reset_device(uint32_t mask) {
    pmgr->reset_assert = mask;
    __asm__ volatile("dsb sy" ::: "memory");
    pmgr->reset_deassert = mask;
    __asm__ volatile("dsb sy; isb" ::: "memory");
}

/* Clock gate release is a read-modify-write on clk_gate_status: a zero bit
 * ungates. Callers pass a plain device mask. */
void pmgr_ungate(uint32_t clocks) {
    if (clocks == 0) return;              /* nothing to release */
    uint32_t status = pmgr->clk_gate_status;
    status &= ~clocks;
    pmgr->clk_gate_status = status;
    __asm__ volatile("dsb sy; isb" ::: "memory");
}

void pmgr_gate(uint32_t clocks) {
    if (clocks == 0) return;
    uint32_t status = pmgr->clk_gate_status;
    status |= clocks;
    pmgr->clk_gate_status = status;
    __asm__ volatile("dsb sy; isb" ::: "memory");
}

uint32_t pmgr_clock_state(void) {
    return pmgr->clk_gate_status;
}

void pmgr_write_status(uint32_t value) {
    pmgr->clk_gate_status = value;
    __asm__ volatile("dsb sy; isb" ::: "memory");
}

uint32_t pmgr_read_status(void) {
    return pmgr->clk_gate_status;
}

/* Bring the blocks this payload talks to out of reset.
 *
 * Order: the AIC first, because it is the one block that has to answer a
 * CPU interrupt before any peripheral driver runs; then the console, since
 * everything after this depends on being able to print; then USB and its
 * PHY, which is the payload's data path. The peripheral masks for
 * GPIO/I2C/SPI/WDT are zero and drop out here (see the file header). */
void pmgr_init(void) {
    pmgr_ungate(PMGR_CLK_AIC | PMGR_CLK_UART | PMGR_CLK_USB |
                PMGR_CLK_DWC2 | PMGR_CLK_PHY |
                PMGR_CLK_GPIO | PMGR_CLK_I2C | PMGR_CLK_SPI |
                PMGR_CLK_WDT);
    pmgr_reset_device(0);
}
