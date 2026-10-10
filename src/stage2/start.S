/*
 * dr1zzle Stage 2 - Assembly Entry Point
 * Receives handoff from Stage 1, initializes full environment
 */

#include "memory_map.h"

.macro SAVE_REGS
    stp x0, x1, [sp, #-16]!
    stp x2, x3, [sp, #-16]!
    stp x4, x5, [sp, #-16]!
    stp x6, x7, [sp, #-16]!
    stp x8, x9, [sp, #-16]!
    stp x10, x11, [sp, #-16]!
    stp x12, x13, [sp, #-16]!
    stp x14, x15, [sp, #-16]!
    stp x16, x17, [sp, #-16]!
    stp x18, x19, [sp, #-16]!
    stp x20, x21, [sp, #-16]!
    stp x22, x23, [sp, #-16]!
    stp x24, x25, [sp, #-16]!
    stp x26, x27, [sp, #-16]!
    stp x28, x29, [sp, #-16]!
    stp x30, xzr, [sp, #-16]!
.endm

.macro RESTORE_REGS
    ldp x30, xzr, [sp], #16
    ldp x28, x29, [sp], #16
    ldp x26, x27, [sp], #16
    ldp x24, x25, [sp], #16
    ldp x22, x23, [sp], #16
    ldp x20, x21, [sp], #16
    ldp x18, x19, [sp], #16
    ldp x16, x17, [sp], #16
    ldp x14, x15, [sp], #16
    ldp x12, x13, [sp], #16
    ldp x10, x11, [sp], #16
    ldp x8, x9, [sp], #16
    ldp x6, x7, [sp], #16
    ldp x4, x5, [sp], #16
    ldp x2, x3, [sp], #16
    ldp x0, x1, [sp], #16
.endm

.section .vectors, "ax", %progbits
.align 11  /* 2 KB alignment */

_vectors:
    /* Synchronous exceptions from EL1h (SP0) */
    b _sync_el1h_sp0
    b _irq_el1h_sp0
    b _fiq_el1h_sp0
    b _serror_el1h_sp0

    /* Synchronous exceptions from EL1h (SPx) */
    b _sync_el1h_spx
    b _irq_el1h_spx
    b _fiq_el1h_spx
    b _serror_el1h_spx

    /* Synchronous exceptions from EL0 (AArch64) */
    b _sync_el0
    b _irq_el0
    b _fiq_el0
    b _serror_el0

    /* Synchronous exceptions from EL0 (AArch32) - not used */
    b .
    b .
    b .
    b .

/* 16 slots × 128 bytes = 2 KB */
.org _vectors + 0x800

.text

/* ========================================================================
 * Stage 2 Entry - Called from Stage 1 with handoff struct in x0
 * ======================================================================== */
.globl _start
_start:
    /* Mask all interrupts */
    msr daifset, #0xf
    
    /* Save handoff pointer from Stage 1 */
    mov x19, x0
    
    /* Set up stack pointer */
    ldr sp, =_stack_top
    
    /* Zero BSS */
    ldr x0, =__bss_start
    ldr x1, =__bss_end
    sub x2, x1, x0
    bl memset
    
    /* Initialize UART for full output */
    bl uart_early_init
    
    /* Call Stage 2 C entry with handoff */
    mov x0, x19
    bl stage2_main
    
    /* Should never return */
    b .

/* ========================================================================
 * Exception Handlers
 * ======================================================================== */

.macro EXCEPTION_HANDLER name, esr_reg, far_reg
\name:
    SAVE_REGS
    mov \esr_reg, x0
    mov \far_reg, x1
    mov x0, sp
    bl exception_handler
    b .
.endm

EXCEPTION_HANDLER _sync_el1h_sp0, x2, x3
EXCEPTION_HANDLER _irq_el1h_sp0, x2, x3
EXCEPTION_HANDLER _fiq_el1h_sp0, x2, x3
EXCEPTION_HANDLER _serror_el1h_sp0, x2, x3

EXCEPTION_HANDLER _sync_el1h_spx, x2, x3
EXCEPTION_HANDLER _irq_el1h_spx, x2, x3
EXCEPTION_HANDLER _fiq_el1h_spx, x2, x3
EXCEPTION_HANDLER _serror_el1h_spx, x2, x3

EXCEPTION_HANDLER _sync_el0, x2, x3
EXCEPTION_HANDLER _irq_el0, x2, x3
EXCEPTION_HANDLER _fiq_el0, x2, x3
EXCEPTION_HANDLER _serror_el0, x2, x3