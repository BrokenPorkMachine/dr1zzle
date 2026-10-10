#ifndef PMGR_H
#define PMGR_H

#include <stdint.h>

/* Absolute addresses of the PMGR reset registers, consumed by the reboot
 * stub in start.S (which cannot call C: it runs with no valid stack).
 * Defined in pmgr.c so the offsets live in exactly one place. */
extern const uint64_t pmgr_reset_assert_addr;
extern const uint64_t pmgr_reset_deassert_addr;

void pmgr_init(void);

/* Assert then release reset for the given device mask. */
void pmgr_reset_device(uint32_t mask);

/* clk_gate_status is read-modify-write; a clear bit ungates a clock. */
void pmgr_ungate(uint32_t clocks);
void pmgr_gate(uint32_t clocks);
uint32_t pmgr_clock_state(void);

/* Device masks. See pmgr.c: the first six come from the published A11 PMGR
 * node and are known-unverified; the four peripheral masks below are
 * placeholders for blocks whose PMGR bit numbers are simply not published
 * anywhere this build can cite. A zero mask is a no-op, so passing one of
 * those is safe and visibly does nothing. */
#define PMGR_CLK_USB      (1 << 2)
#define PMGR_CLK_UART     (1 << 7)
#define PMGR_CLK_AIC      (1 << 9)
#define PMGR_CLK_DWC2     (1 << 15)
#define PMGR_CLK_NAND     (1 << 20)
#define PMGR_CLK_PHY      (1 << 16)

#define PMGR_CLK_GPIO     0u
#define PMGR_CLK_I2C      0u
#define PMGR_CLK_SPI      0u
#define PMGR_CLK_WDT      0u

#define PMGR_RESET_USB    (1 << 2)
#define PMGR_RESET_UART   (1 << 7)
#define PMGR_RESET_AIC    (1 << 9)
#define PMGR_RESET_DWC2   (1 << 15)
#define PMGR_RESET_NAND   (1 << 20)
#define PMGR_RESET_PHY    (1 << 16)

#define PMGR_RESET_GPIO   0u
#define PMGR_RESET_I2C    0u
#define PMGR_RESET_SPI    0u
#define PMGR_RESET_WDT    0u

/* Diagnostic access to the two windows, for bring-up from the shell. The
 * payload should not need it; an operator discovering the correct masks
 * very much does. */
void     pmgr_write_status(uint32_t value);
uint32_t pmgr_read_status(void);

#endif /* PMGR_H */
