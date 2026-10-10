#ifndef AIC_H
#define AIC_H

#include <stdint.h>

/* Apple Interrupt Controller, version 1 -- the AP-side controller behind
 * the A11's IRQ line.
 *
 * Layout grounding: the upstream Linux driver
 * (drivers/irqchip/irq-apple-aic.c) binds the compatible string
 * "apple,t8015-aic" -- t8015 *is* the A11 -- to its AICv1 descriptor and
 * publishes the v1 offsets used below. They also match the Asahi Linux
 * AIC hardware notes, which were reverse-engineered separately:
 *
 *   0004  INFO       bits 15:0 = number of implemented IRQ lines
 *   0010  CONFIG
 *   2000  WHOAMI     reads back this core's CPU id
 *   2004  EVENT      read to acknowledge; the line is masked on read
 *   2008  IPI_SEND
 *   200C  IPI_ACK
 *   2024  IPI_MASK_SET
 *   2028  IPI_MASK_CLR
 *   3000  TARGET     one word per IRQ, CPU bitfield (1 = CPU0)
 *   4000  SW_SET     software-generated sources
 *   4080  SW_CLR
 *   4100  MASK_SET
 *   4180  MASK_CLR
 *   4200  HW_STATE   live state of the hardware lines
 *
 * Apple's convention throughout the controller is a SET/CLR pair for every
 * bitfield: write the bits you want set into SET, and the bits you want
 * cleared into CLR.
 *
 * What is NOT verified: AIC_BASE in memory_map.h has not been read back
 * from a device. Because that makes every write below a write to a window
 * whose contents are unknown, aic_init() validates AIC_INFO before it
 * programs anything and refuses to continue if the read does not look like
 * an interrupt controller. An unverified base is survivable; an
 * unverified base we blindly write to is not.
 *
 * An IRQ line is claimed by: target it at this CPU, write its bit to
 * MASK_CLR, and then read EVENT when the line fires. Reading EVENT masks
 * the line again, so every handler has to follow up with aic_enable() --
 * that is the "end of interrupt" for this controller.
 */

/* Capability / status */
#define AIC_INFO              0x0004
#define AIC_INFO_NR_IRQ       0xFFFFu
#define AIC_CONFIG            0x0010

/* Per-core view (the AP core that runs this payload) */
#define AIC_WHOAMI            0x2000
#define AIC_EVENT             0x2004

/* IPIs: unused here (single core), but they are IPI *hardware* and will
 * still assert the IRQ line if the boot firmware left one latched. */
#define AIC_IPI_SEND          0x2008
#define AIC_IPI_ACK           0x200C
#define AIC_IPI_MASK_SET      0x2024
#define AIC_IPI_MASK_CLR      0x2028
#define AIC_IPI_OTHER         (1u << 0)
#define AIC_IPI_SELF          (1u << 31)

/* Per-IRQ routing and software triggering */
#define AIC_TARGET_CPU        0x3000
#define AIC_TARGET_CPU0       1u
#define AIC_SW_SET            0x4000
#define AIC_SW_CLR            0x4080

/* Bitfield banks: one bit per IRQ, 32 IRQs per word. */
#define AIC_MASK_SET          0x4100
#define AIC_MASK_CLR          0x4180
#define AIC_HW_STATE          0x4200
#define AIC_MASK_REG(irq)     (4u * ((irq) >> 5))
#define AIC_MASK_BIT(irq)     (1u << ((irq) & 31u))

/* EVENT decode. Bits 23:16 select the source class, bits 15:0 the number. */
#define AIC_EVENT_TYPE_SHIFT  16
#define AIC_EVENT_TYPE_IRQ    1u
#define AIC_EVENT_NUM         0xFFFFu

/* Architectural maximum IRQ count. Linux uses the same figure for its v1
 * descriptor. The dispatch table in exception.c is sized from this. */
#define AIC_MAX_IRQ           1024u

/* Programs the controller: drains stale events, masks every line, targets
 * every line at this core. Returns 0 if the window answered like an AIC,
 * -1 if it did not (in which case nothing else has been written). */
int  aic_init(void);

/* True once aic_init() succeeded. Callers use this to tell "no
 * controller" apart from "controller with nothing pending". */
int  aic_ready(void);

/* Reads and therefore acknowledges the highest-priority pending event.
 * Returns 0 when the controller has nothing to report. */
uint32_t aic_event(void);

/* IRQ number carried by an EVENT word, or -1 when the event is empty, an
 * IPI, or a line past the implemented count. */
int  aic_event_irq(uint32_t event);

/* End of interrupt: re-enable a line after its handler has run. Without
 * this the line stays masked by the acknowledge and never fires again. */
void aic_eoi(unsigned int irq);

void aic_enable(unsigned int irq);
void aic_disable(unsigned int irq);

/* Implemented IRQ count as reported by AIC_INFO, 0 before aic_init(). */
unsigned int aic_irq_count(void);
uint32_t aic_whoami(void);

void aic_dump(void);

#endif /* AIC_H */
