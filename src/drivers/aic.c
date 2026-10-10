/* Apple Interrupt Controller (AIC v1) bring-up.
 *
 * The exception vectors in start.S install VBAR and mask everything, which
 * is why the payload used to run without an interrupt controller at all:
 * IRQ dispatch polled DWC2 and called a stubbed aic_eoi(). That polling
 * works only for the sources the code already knows by name, and it cannot
 * tell the difference between "nothing pending" and "pending but nobody
 * claimed it". This driver replaces it by programming the controller, and
 * irq_handler() now dispatches on the line number the controller reports.
 *
 * Sequences here follow the upstream driver's contract:
 *
 *   init   - drain pending events, ack + mask IPIs, then for every
 *            implemented line: target CPU0, clear SW, mask
 *   claim  - target + MASK_CLR (aic_enable)
 *   fire   - handler runs
 *   eoi    - MASK_CLR, because the EVENT read masked the line
 *
 * Nothing in this file has run on an A11. aic_init() fails closed: if the
 * window does not answer like an interrupt controller, no register other
 * than AIC_INFO is touched and the caller falls back to polling.
 */

#include "aic.h"
#include "memory_map.h"
#include "mmio.h"
#include "timer.h"
#include "uart.h"
#include "util.h"

#define AIC_BASE_WORD  ((uintptr_t)AIC_BASE)

static inline uint32_t aic_rd(uint32_t off) {
    return mmio_read32(AIC_BASE_WORD + off);
}

static inline void aic_wr(uint32_t off, uint32_t val) {
    mmio_write32(AIC_BASE_WORD + off, val);
}

static int           aic_initialised;
static unsigned int  aic_nr_irq;

int aic_ready(void) {
    return aic_initialised;
}

unsigned int aic_irq_count(void) {
    return aic_nr_irq;
}

uint32_t aic_whoami(void) {
    return aic_rd(AIC_WHOAMI);
}

uint32_t aic_event(void) {
    /* Not the relaxed accessor: the event read has to be ordered after the
     * interrupt itself, which a plain volatile load on ARMv8 already is for
     * the device mapping, but the barrier costs nothing once per IRQ. */
    return mmio_read32(AIC_BASE_WORD + AIC_EVENT);
}

int aic_init(void) {
    uint32_t info = aic_rd(AIC_INFO);
    unsigned int nr = info & AIC_INFO_NR_IRQ;

    if (nr == 0 || nr > AIC_MAX_IRQ) {
        return -1;
    }

    /* Drain whatever the boot firmware left pending. Each read acknowledges
     * exactly one event; a handful of attempts is enough for a controller
     * that is otherwise idle, and this bound is what keeps a wedged
     * controller from wedging the boot. */
    for (int i = 0; i < 4; i++) {
        if (aic_rd(AIC_EVENT) == 0) break;
    }

    /* Acknowledge and mask both IPI channels. The A11's "fast" IPI path
     * delivers through IMP-DEF system registers instead of this window;
     * those are deliberately left alone. Writing a system register the
     * core does not implement is an undefined-instruction trap, and the
     * only thing it would buy us is an FIQ this payload has no handler
     * for. The MMIO mask covers the classic path. */
    aic_wr(AIC_IPI_ACK, AIC_IPI_SELF | AIC_IPI_OTHER);
    aic_wr(AIC_IPI_MASK_SET, AIC_IPI_SELF | AIC_IPI_OTHER);

    /* Every implemented line: route it to this core, clear any
     * software-generated state, and start masked. Peripheral drivers
     * unmask their own line once they have configured it; doing it here
     * would deliver an interrupt into a half-configured device. */
    for (unsigned int irq = 0; irq < nr; irq++) {
        aic_wr(AIC_TARGET_CPU + irq * 4u, AIC_TARGET_CPU0);
        aic_wr(AIC_MASK_SET + AIC_MASK_REG(irq), AIC_MASK_BIT(irq));
        aic_wr(AIC_SW_CLR + AIC_MASK_REG(irq), AIC_MASK_BIT(irq));
    }

    aic_nr_irq = nr;
    aic_initialised = 1;
    return 0;
}

int aic_event_irq(uint32_t event) {
    if (event == 0) return -1;
    if (((event >> AIC_EVENT_TYPE_SHIFT) & 0xFFu) != AIC_EVENT_TYPE_IRQ) {
        return -1;
    }
    unsigned int num = event & AIC_EVENT_NUM;
    if (num >= aic_nr_irq) return -1;
    return (int)num;
}

void aic_enable(unsigned int irq) {
    if (!aic_initialised || irq >= aic_nr_irq) return;
    aic_wr(AIC_MASK_CLR + AIC_MASK_REG(irq), AIC_MASK_BIT(irq));
}

void aic_disable(unsigned int irq) {
    if (!aic_initialised || irq >= aic_nr_irq) return;
    aic_wr(AIC_MASK_SET + AIC_MASK_REG(irq), AIC_MASK_BIT(irq));
}

void aic_eoi(unsigned int irq) {
    /* The acknowledge in aic_event() already masked this line. Unmask it
     * so it can fire again; if the caller decides the source is not
     * drained it should leave the line alone rather than call this. */
    aic_enable(irq);
}

void aic_dump(void) {
    uart_puts("aic: base=0x");
    uart_puts(utoa_hex(AIC_BASE));
    uart_puts(" info=0x");
    uart_puts(utoa_hex(aic_rd(AIC_INFO)));
    uart_puts(" nr_irq=");
    uart_puts(utoa(aic_nr_irq));
    uart_puts(aic_ready() ? " ready" : " not-ready");

    if (aic_ready()) {
        uart_puts(" whoami=0x");
        uart_puts(utoa_hex(aic_whoami()));
        uart_puts(" event=0x");
        uart_puts(utoa_hex(aic_event()));
        uart_puts(" hw_state[0]=0x");
        uart_puts(utoa_hex(aic_rd(AIC_HW_STATE)));
    }
    uart_puts("\n");
}
