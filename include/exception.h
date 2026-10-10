#ifndef EXCEPTION_H
#define EXCEPTION_H

#include <stdint.h>

typedef void (*irq_handler_t)(void);

/* Vectors call these with the exception payload already read out of the
 * banked registers (the C code has no way to reach EL1h registers directly
 * without an exception entry of its own). */
void sync_handler(uint64_t esr, uint64_t far, uint64_t spsr);
void serror_handler(uint64_t esr, uint64_t far, uint64_t spsr);
void abort_handler(uint64_t esr, uint64_t far);
void irq_handler(void);
void fiq_handler(void);

/* Installs the vectors' targets: nothing to do with VBAR (start.S owns
 * that) beyond bringing the interrupt controller up. Everything downstream
 * of this point depends on it, so it runs before any peripheral that would
 * claim a line. */
void exception_init(void);

/* Claims an IRQ line. `irq` is the controller's line number, not an index
 * into anything this file owns. Returns 0 on success, -1 if the number is
 * out of range or the slot is taken. */
int irq_register(unsigned int irq, irq_handler_t handler);
void irq_unregister(unsigned int irq);
irq_handler_t irq_lookup(unsigned int irq);

/* Diagnostics: IRQs taken with no registered source claiming them. These
 * are left masked by the controller, so this counter counts claims that
 * were missed rather than storms. */
unsigned int irq_unhandled_count(void);
unsigned int irq_total_count(void);

/* System register readers used by the fault dumper. */
static inline uint64_t elr_el1_read(void) {
    uint64_t v; __asm__ volatile("mrs %0, elr_el1" : "=r"(v)); return v;
}
static inline uint64_t spsr_el1_read(void) {
    uint64_t v; __asm__ volatile("mrs %0, spsr_el1" : "=r"(v)); return v;
}
static inline uint64_t sp_el1_read(void) {
    uint64_t v; __asm__ volatile("mrs %0, sp_el1" : "=r"(v)); return v;
}
static inline uint64_t tpidr_el1_read(void) {
    uint64_t v; __asm__ volatile("mrs %0, tpidr_el1" : "=r"(v)); return v;
}

/* CPU register snapshot - captures full exception frame + system registers */
typedef struct {
    uint64_t x[31];           /* x0-x30 */
    uint64_t sp;
    uint64_t elr_el1;
    uint64_t spsr_el1;
    uint64_t esr_el1;
    uint64_t far_el1;
    uint64_t tpidr_el1;
    uint64_t vbar_el1;
    uint64_t sctlr_el1;
    uint64_t ttbr0_el1;
    uint64_t ttbr1_el1;
    uint64_t tcr_el1;
    uint64_t mair_el1;
    uint64_t currentel;
    uint64_t midr_el1;
    uint64_t mpidr_el1;
    uint64_t cpacr_el1;
    uint64_t cntfrq_el0;
    uint64_t cntpct_el0;
    uint64_t daif;
    uint64_t nzcv;
    uint64_t pmgr_clock_state;
    uint64_t aic_event;
    int valid;                /* snapshot is valid */
    int x_valid;              /* x0-x30 captured from exception frame */
} regs_snapshot_t;

/* Global snapshot instance */
extern regs_snapshot_t g_snapshot;

void regs_snapshot(int nostage);
void regs_show(void);
void regs_clear(void);
regs_snapshot_t *regs_get_snapshot(void);

#endif /* EXCEPTION_H */
