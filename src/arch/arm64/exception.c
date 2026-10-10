#include "uart.h"
#include "util.h"
#include "memory_map.h"
#include "mmio.h"
#include "exception.h"
#include "aic.h"
#include "usb.h"

/* Snapshot instance for fault capture */
regs_snapshot_t g_snapshot = { .valid = 0 };

/* ESR_EL1 EC values we care about naming. */
#define EC_INSN_ABORT_LOW  0x20
#define EC_DATA_ABORT_LOW  0x24
#define EC_PC_ALIGN        0x22
#define EC_SP_ALIGN        0x26
#define EC_FPID            0x2C
#define EC_UNKNOWN         0x00

static const char *ec_name(uint64_t ec) {
    switch (ec) {
        case 0x00: return "EC=0x00 unknown";
        case 0x20: return "EC=0x20 IABT (low)";
        case 0x21: return "EC=0x21 IABT (curr)";
        case 0x22: return "EC=0x22 PC alignment";
        case 0x24: return "EC=0x24 DABT (low)";
        case 0x25: return "EC=0x25 DABT (curr)";
        case 0x26: return "EC=0x26 SP alignment";
        case 0x2C: return "EC=0x2C FP";
        default:   return "EC=?";
    }
}

/* Dump enough state to debug a fault without a debugger attached. */
static void dump_fault(const char *kind, uint64_t esr, uint64_t far) {
    uint64_t ec  = (esr >> 26) & 0x3F;
    uint64_t iss = esr & 0xFFFFFF;

    uart_puts("\n*** ");
    uart_puts(kind);
    uart_puts(" ***\n");
    uart_puts("  ");
    uart_puts(ec_name(ec));
    uart_puts("\n  ESR=0x"); uart_puts(utoa_hex(esr));
    uart_puts("  FAR=0x"); uart_puts(utoa_hex(far));
    uart_puts("\n  ISS=0x"); uart_puts(utoa_hex(iss));
    uart_puts("\n  ELR=0x"); uart_puts(utoa_hex(elr_el1_read()));
    uart_puts("  SP=0x"); uart_puts(utoa_hex(sp_el1_read()));
    uart_puts("\n  CPSR=0x"); uart_puts(utoa_hex(spsr_el1_read()));
    uart_puts("\n  usr=0x"); uart_puts(utoa_hex(tpidr_el1_read()));
    uart_puts("\nhalting.\n");
}

void sync_handler(uint64_t esr, uint64_t far, uint64_t spsr) {
    (void)spsr;
    /* Auto-capture register snapshot on fault for later retrieval */
    regs_snapshot_t *s = &g_snapshot;
    
    /* Capture all registers from the exception frame */
    /* x0-x30 are already saved on stack by SAVE_REGS in start.S */
    /* We need to read them from the stack frame */
    uint64_t *frame = (uint64_t *)((uint64_t)sp_el1_read() - 256);
    for (int i = 0; i < 31; i++) {
        s->x[i] = frame[i];
    }
    s->x[30] = frame[30];  /* x30 */
    s->sp = (uint64_t)frame;  /* SP at frame base */
    
    /* System registers */
    s->elr_el1 = elr_el1_read();
    s->spsr_el1 = spsr_el1_read();
    s->esr_el1 = esr;
    s->far_el1 = far;
    s->tpidr_el1 = tpidr_el1_read();
    s->vbar_el1 = 0; __asm__ volatile("mrs %0, vbar_el1" : "=r"(s->vbar_el1));
    s->sctlr_el1 = 0; __asm__ volatile("mrs %0, sctlr_el1" : "=r"(s->sctlr_el1));
    s->ttbr0_el1 = 0; __asm__ volatile("mrs %0, ttbr0_el1" : "=r"(s->ttbr0_el1));
    s->ttbr1_el1 = 0; __asm__ volatile("mrs %0, ttbr1_el1" : "=r"(s->ttbr1_el1));
    s->tcr_el1 = 0; __asm__ volatile("mrs %0, tcr_el1" : "=r"(s->tcr_el1));
    s->mair_el1 = 0; __asm__ volatile("mrs %0, mair_el1" : "=r"(s->mair_el1));
    s->currentel = 0; __asm__ volatile("mrs %0, currentel" : "=r"(s->currentel));
    s->midr_el1 = 0; __asm__ volatile("mrs %0, midr_el1" : "=r"(s->midr_el1));
    s->mpidr_el1 = 0; __asm__ volatile("mrs %0, mpidr_el1" : "=r"(s->mpidr_el1));
    s->cpacr_el1 = 0; __asm__ volatile("mrs %0, cpacr_el1" : "=r"(s->cpacr_el1));
    s->cntfrq_el0 = 0; __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(s->cntfrq_el0));
    s->cntpct_el0 = 0; __asm__ volatile("mrs %0, cntpct_el0" : "=r"(s->cntpct_el0));
    s->daif = 0; __asm__ volatile("mrs %0, daif" : "=r"(s->daif));
    
    s->x_valid = 1;  /* x0-x30 captured from exception frame */
    s->nzcv = (s->spsr_el1 >> 28) & 0xF;
    s->pmgr_clock_state = mmio_read32(PMGR_BASE + 0x200);
    s->aic_event = aic_ready() ? mmio_read32(AIC_BASE + 0x10) : 0;
    
    s->valid = 1;
    
    dump_fault("SYNC", esr, far);
    uart_puts("\nregs: snapshot auto-captured on fault (use 'regs show' after resume)\n");
    for (;;) { __asm__ volatile("wfe"); }
}

void serror_handler(uint64_t esr, uint64_t far, uint64_t spsr) {
    (void)spsr;
    dump_fault("SERROR", esr, far);
    for (;;) { __asm__ volatile("wfe"); }
}

/* Returning from a data abort is only correct for a recoverable MMU fault.
 * Until the identity map is verified we stop here rather than risk resuming
 * somewhere wrong. */
void abort_handler(uint64_t esr, uint64_t far) {
    dump_fault(esr & (1ULL << 24) ? "DATA ABORT" : "INSN ABORT", esr, far);
    for (;;) { __asm__ volatile("wfe"); }
}

/* ---- IRQ ------------------------------------------------------------- */

/* Dispatch table, indexed by the controller's line number. Sized to the
 * architectural maximum of the AIC rather than to the number of sources
 * this build registers: the controller reports how many lines it has
 * (AIC_INFO) and that is in the hundreds, so a table sized to "the ones we
 * know" would silently drop the rest. 8 KiB of zeroed BSS is 0.4% of SRAM. */
#define IRQ_MAX AIC_MAX_IRQ

static irq_handler_t irq_handlers[IRQ_MAX];
static unsigned int irq_unhandled;
static unsigned int irq_total;

int irq_register(unsigned int irq, irq_handler_t handler) {
    if (irq >= IRQ_MAX || handler == 0) return -1;
    /* Overwriting a live handler would leave the previous source's line
     * dispatching into code that does not expect it. */
    if (irq_handlers[irq] != 0) return -1;
    irq_handlers[irq] = handler;
    aic_enable(irq);
    return 0;
}

void irq_unregister(unsigned int irq) {
    if (irq >= IRQ_MAX) return;
    /* Mask before dropping the handler: a line left enabled with no
     * handler is a source nobody drains. */
    aic_disable(irq);
    irq_handlers[irq] = 0;
}

irq_handler_t irq_lookup(unsigned int irq) {
    if (irq >= IRQ_MAX) return 0;
    return irq_handlers[irq];
}

unsigned int irq_unhandled_count(void) {
    return irq_unhandled;
}

unsigned int irq_total_count(void) {
    return irq_total;
}

/* Path taken when the interrupt controller did not come up: ask the
 * sources we know about whether they want service. This cannot tell us
 * anything about lines we have not mapped, and it cannot report the line
 * number, which is why it is a fallback and not the design. */
static void irq_poll_sources(void) {
    if (usb_irq_pending()) {
        usb_irq_handler();
        return;
    }
    irq_unhandled++;
}

void irq_handler(void) {
    if (!aic_ready()) {
        irq_poll_sources();
        return;
    }

    /* Reading the event acknowledges the line and masks it. Whatever comes
     * back decides everything below. */
    uint32_t event = aic_event();
    int irq = aic_event_irq(event);

    if (irq < 0) {
        /* An IPI, a software-generated event, or a line number past the
         * implemented count. Nothing here can service any of those. */
        if (event != 0) irq_unhandled++;
        return;
    }

    irq_handler_t handler = irq_lookup((unsigned int)irq);
    if (handler == 0) {
        /* Unclaimed. Leave it masked -- the acknowledge already did that,
         * and unmasking a live source with nobody draining it turns into a
         * storm instead of a measly counter increment. */
        irq_unhandled++;
        return;
    }

    handler();
    aic_eoi((unsigned int)irq);
    irq_total++;
}

void fiq_handler(void) {
    /* A FIQ on this payload is always a bug: the sources this SoC routes to
     * FIQ (fast IPIs, the ARM generic timers, the performance counters) are
     * all masked or unused, so control should never arrive here. */
    uart_puts("FIQ: unexpected\n");
    for (;;) { __asm__ volatile("wfe"); }
}

void exception_init(void) {
    /* start.S installed the vectors and VBAR. What remains is the
     * controller that tells us which line fired: without it, irq_handler
     * can only ask the sources it knows by name, which is what it did
     * before aic.c existed. */
    if (aic_init() != 0) {
        uart_puts("aic: no controller at 0x");
        uart_puts(utoa_hex(AIC_BASE));
        uart_puts(" (info=0x");
        uart_puts(utoa_hex(mmio_read32((uintptr_t)AIC_BASE + AIC_INFO)));
        uart_puts("); IRQ dispatch falls back to polling\n");
        return;
    }

    uart_puts("aic: ");
    uart_puts(utoa(aic_irq_count()));
    uart_puts(" lines, cpu ");
    uart_puts(utoa_hex(aic_whoami()));
    uart_puts("\n");
}

/* ---- CPU Register Snapshot ------------------------------------------- */

void regs_snapshot(int nostage) {
    regs_snapshot_t *s = &g_snapshot;
    
    /* Capture general registers from the exception frame.
     * The frame is on the stack at the time of the exception. Since we're
     * calling this from shell (not from exception handler), we capture
     * current register state by reading system registers directly. */
    
    /* We can't easily get x0-x30 from C without inline asm in an exception context.
     * For a shell command, we capture what we can from system registers. */
    __asm__ volatile(
        "mrs %0, elr_el1\n"
        "mrs %1, spsr_el1\n"
        "mrs %2, esr_el1\n"
        "mrs %3, far_el1\n"
        "mrs %4, sp_el1\n"
        "mrs %5, tpidr_el1\n"
        "mrs %6, vbar_el1\n"
        "mrs %7, sctlr_el1\n"
        "mrs %8, ttbr0_el1\n"
        "mrs %9, ttbr1_el1\n"
        "mrs %10, tcr_el1\n"
        "mrs %11, mair_el1\n"
        "mrs %12, currentel\n"
        "mrs %13, midr_el1\n"
        "mrs %14, mpidr_el1\n"
        "mrs %15, cpacr_el1\n"
        "mrs %16, cntfrq_el0\n"
        "mrs %17, cntpct_el0\n"
        "mrs %18, daif\n"
        : "=r"(s->elr_el1), "=r"(s->spsr_el1), "=r"(s->esr_el1),
          "=r"(s->far_el1), "=r"(s->sp), "=r"(s->tpidr_el1),
          "=r"(s->vbar_el1), "=r"(s->sctlr_el1), "=r"(s->ttbr0_el1),
          "=r"(s->ttbr1_el1), "=r"(s->tcr_el1), "=r"(s->mair_el1),
          "=r"(s->currentel), "=r"(s->midr_el1), "=r"(s->mpidr_el1),
          "=r"(s->cpacr_el1), "=r"(s->cntfrq_el0), "=r"(s->cntpct_el0),
          "=r"(s->daif)
    );
    
    s->x_valid = 0;  /* x0-x30 not captured from shell command */
    
    /* Read NZCV from SPSR_EL1 */
    s->nzcv = (s->spsr_el1 >> 28) & 0xF;
    
    /* Read PMGR clock state */
    s->pmgr_clock_state = mmio_read32(PMGR_BASE + 0x200);  /* PMGR_DEVICE_STATE */
    
    /* Read AIC event if available */
    s->aic_event = aic_ready() ? mmio_read32(AIC_BASE + 0x10) : 0;  /* AIC_EVENT */
    
    s->valid = 1;
    
    uart_puts("regs: snapshot captured");
    if (nostage) uart_puts(" (not staged)");
    uart_puts("\n");
}

void regs_show(void) {
    regs_snapshot_t *s = &g_snapshot;
    
    if (!s->valid) {
        uart_puts("regs: no snapshot available - run 'regs snapshot' first\n");
        return;
    }
    
    uart_puts("\n=== CPU Register Snapshot ===\n");
    
    if (s->x_valid) {
        uart_puts("General Registers (x0-x30) - captured from exception frame:\n");
        for (int i = 0; i < 31; i++) {
            uart_puts("  x"); uart_puts(utoa(i)); uart_puts(": 0x"); uart_puts(utoa_hex(s->x[i])); uart_puts("\n");
        }
        uart_puts("  SP:  0x"); uart_puts(utoa_hex(s->sp)); uart_puts("\n\n");
    } else {
        uart_puts("General Registers (x0-x30): not captured (run from shell)\n");
        uart_puts("  Use 'regs snapshot' from exception context or fault to capture\n\n");
    }
    
    uart_puts("System Registers:\n");
    uart_puts("  ELR_EL1:      0x"); uart_puts(utoa_hex(s->elr_el1)); uart_puts("\n");
    uart_puts("  SPSR_EL1:     0x"); uart_puts(utoa_hex(s->spsr_el1)); uart_puts("\n");
    uart_puts("  ESR_EL1:      0x"); uart_puts(utoa_hex(s->esr_el1)); uart_puts("\n");
    uart_puts("  FAR_EL1:      0x"); uart_puts(utoa_hex(s->far_el1)); uart_puts("\n");
    uart_puts("  SP_EL1:       0x"); uart_puts(utoa_hex(s->sp)); uart_puts("\n");
    uart_puts("  TPIDR_EL1:    0x"); uart_puts(utoa_hex(s->tpidr_el1)); uart_puts("\n");
    uart_puts("  VBAR_EL1:     0x"); uart_puts(utoa_hex(s->vbar_el1)); uart_puts("\n");
    uart_puts("  SCTLR_EL1:    0x"); uart_puts(utoa_hex(s->sctlr_el1)); uart_puts("\n");
    uart_puts("  TTBR0_EL1:    0x"); uart_puts(utoa_hex(s->ttbr0_el1)); uart_puts("\n");
    uart_puts("  TTBR1_EL1:    0x"); uart_puts(utoa_hex(s->ttbr1_el1)); uart_puts("\n");
    uart_puts("  TCR_EL1:      0x"); uart_puts(utoa_hex(s->tcr_el1)); uart_puts("\n");
    uart_puts("  MAIR_EL1:     0x"); uart_puts(utoa_hex(s->mair_el1)); uart_puts("\n");
    uart_puts("  CurrentEL:    0x"); uart_puts(utoa_hex(s->currentel)); uart_puts("\n");
    uart_puts("  MIDR_EL1:     0x"); uart_puts(utoa_hex(s->midr_el1)); uart_puts("\n");
    uart_puts("  MPIDR_EL1:    0x"); uart_puts(utoa_hex(s->mpidr_el1)); uart_puts("\n");
    uart_puts("  CPACR_EL1:    0x"); uart_puts(utoa_hex(s->cpacr_el1)); uart_puts("\n");
    uart_puts("  CNTFRQ_EL0:   "); uart_puts(utoa(s->cntfrq_el0)); uart_puts(" Hz\n");
    uart_puts("  CNTPCT_EL0:   0x"); uart_puts(utoa_hex(s->cntpct_el0)); uart_puts("\n");
    uart_puts("  DAIF:         0x"); uart_puts(utoa_hex(s->daif)); uart_puts("\n");
    uart_puts("  NZCV:         0x"); uart_puts(utoa_hex(s->nzcv)); uart_puts("\n");
    uart_puts("  PMGR clocks:  0x"); uart_puts(utoa_hex(s->pmgr_clock_state)); uart_puts("\n");
    uart_puts("  AIC event:    0x"); uart_puts(utoa_hex(s->aic_event)); uart_puts("\n");
    uart_puts("===============================\n\n");
}

void regs_clear(void) {
    g_snapshot.valid = 0;
    uart_puts("regs: snapshot cleared\n");
}

regs_snapshot_t *regs_get_snapshot(void) {
    return g_snapshot.valid ? &g_snapshot : 0;
}
