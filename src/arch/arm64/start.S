/* A11 Research Payload - ARM64 Startup
 * Vector table + EL1h entry from checkm8
 */

.section .vectors, "ax", %progbits
.global _vectors
_vectors:
    /* Synchronous (EL1h) */
    b   _sync_el1h
    b   _irq_el1h
    b   _fiq_el1h
    b   _serror_el1h

    /* Lower EL (AArch64) */
    .skip 4 * 4

    /* Lower EL (AArch32) */
    .skip 4 * 4

.global _start
_start:
    /* 1. Disable MMU, caches, alignment check */
    mrs     x0, sctlr_el1
    bic     x0, x0, #(1 << 0)   /* M=0: MMU off */
    bic     x0, x0, #(1 << 2)   /* C=0: D-cache off */
    bic     x0, x0, #(1 << 12)  /* I=0: I-cache off */
    bic     x0, x0, #(1 << 1)   /* A=0: Alignment check off */
    msr     sctlr_el1, x0
    isb

    /* 2. Install vector table (VBAR_EL1) */
    adr     x0, _vectors
    msr     vbar_el1, x0
    isb

    /* 3. Enable physical timer (CNTPCT_EL0 @ 24 MHz) */
    mov     x0, #1
    msr     cntp_ctl_el0, x0    /* Enable, no interrupt mask */
    msr     cntv_ctl_el0, x0

    /* 4. Initialize MMU (identity map + device regions) */
    bl      mmu_init

    /* 5. Early UART for debugging */
    bl      uart_early_init

    /* 6. USB PHY + DWC2 device */
    bl      usb_init

    /* 7. Enable MMU + caches */
    mrs     x0, sctlr_el1
    orr     x0, x0, #(1 << 0)   /* M=1: MMU on */
    orr     x0, x0, #(1 << 2)   /* C=1: D-cache on */
    orr     x0, x0, #(1 << 12)  /* I=1: I-cache on */
    msr     sctlr_el1, x0
    isb

    /* 8. Enable IRQ + FIQ */
    msr     daifclr, #3         /* Clear IRQ/FIQ bits */

    /* 9. C main */
    bl      c_main

    /* Should never return */
    b       .

/* ============================================================
 * Exception Handlers (EL1h)
 * ============================================================ */
.macro SAVE_REGS
    sub     sp, sp, #16 * 8
    stp     x0, x1,  [sp, #0 * 16]
    stp     x2, x3,  [sp, #1 * 16]
    stp     x4, x5,  [sp, #2 * 16]
    stp     x6, x7,  [sp, #3 * 16]
    stp     x8, x9,  [sp, #4 * 16]
    stp     x10, x11, [sp, #5 * 16]
    stp     x12, x13, [sp, #6 * 16]
    stp     x14, x15, [sp, #7 * 16]
    stp     x16, x17, [sp, #8 * 16]
    stp     x18, x19, [sp, #9 * 16]
    stp     x20, x21, [sp, #10 * 16]
    stp     x22, x23, [sp, #10 * 16]
    stp     x24, x25, [sp, #11 * 16]
    stp     x26, x27, [sp, #11 * 16]
    stp     x28, x29, [sp, #12 * 16]
    stp     x28, x29, [sp, #13 * 16]
    str     x30, [sp, #14 * 16]
.endm

.macro RESTORE_REGS
    ldr     x30, [sp, #14 * 16]
    ldp     x28, x29, [sp, #13 * 16]
    ldp     x26, x27, [sp, #12 * 16]
    ldp     x24, x25, [sp, #11 * 16]
    ldp     x22, x23, [sp, #10 * 16]
    ldp     x20, x21, [sp, #10 * 16]
    ldp     x18, x19, [sp, #9 * 16]
    ldp     x16, x17, [sp, #8 * 16]
    ldp     x14, x15, [sp, #7 * 16]
    ldp     x12, x13, [sp, #6 * 16]
    ldp     x10, x11, [sp, #5 * 16]
    ldp     x8, x9,  [sp, #4 * 16]
    ldp     x6, x7,  [sp, #3 * 16]
    ldp     x4, x5,  [sp, #2 * 16]
    ldp     x2, x3,  [sp, #1 * 16]
    ldp     x0, x1,  [sp, #0 * 16]
    add     sp, sp, #16 * 8
.endm

_sync_el1h:
    SAVE_REGS
    mrs     x0, esr_el1
    mrs     x1, far_el1
    bl      sync_handler
    RESTORE_REGS
    eret

_irq_el1h:
    SAVE_REGS
    bl      irq_handler
    RESTORE_REGS
    eret

_fiq_el1h:
    SAVE_REGS
    bl      fiq_handler
    RESTORE_REGS
    eret

_serror_el1h:
    SAVE_REGS
    bl      serror_handler
    RESTORE_REGS
    eret

.global reboot
reboot:
    ldr     x0, =0x100000000
    br      x0
