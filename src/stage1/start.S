/*
 * dr1zzle Stage 1 - Assembly Entry Point
 * Minimal setup before C entry
 */

/* SRAM constants */
#define SRAM_BASE           0x180000000
#define SRAM_SIZE           0x1E8000
#define STACK_TOP           (SRAM_BASE + SRAM_SIZE)
#define HEAP_START          (SRAM_BASE + 0x8000)
#define HEAP_END            (SRAM_BASE + 0x10000)

.macro SAVE_REGS
    stp x0, x1, [sp, #-16]!
    stp x2, x3, [sp, #-16]!
    stp x4, x5, [sp, #-16]!
    stp x6, x7, [sp, #-16]!
    stp x8, x9, [sp, #-16]!
    stp x10, x11, [sp, #-16]!
    stp x12, x13, [sp, #-16]!
    stp x14, x15, [sp, #-16]!
    stp x14, x15, [sp, #-16]!
    stp x16, x17, [sp, #-16]!
    stp x16, x17, [sp, #-16]!
    stp x18, x19, [sp, #-16]!
    stp x18, x19, [sp, #-16]!
    stp x20, x21, [sp, #-16]!
    stp x20, x21, [sp, #-16]!
    stp x22, x23, [sp, #-16]!
    stp x22, x23, [sp, #-16]!
    stp x24, x25, [sp, #-16]!
    stp x24, x25, [sp, #-16]!
    stp x26, x27, [sp, #-16]!
    stp x26, x27, [sp, #-16]!
    stp x28, x29, [sp, #-16]!
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
 * _start - Entry point from bootloader (checkm8/DFU)
 * x0 = device tree pointer (or 0)
 * ======================================================================== */
.globl _start
_start:
    /* Mask all interrupts */
    msr daifset, #0xf
    
    /* Save device tree pointer */
    mov x19, x0
    
    /* Set up stack pointer */
    ldr x0, =STACK_TOP
    mov sp, x0
    
    /* Zero BSS - linker defines these symbols */
    ldr x0, =__bss_start
    ldr x1, =__bss_end
    sub x2, x1, x0
    bl memset
    
    /* Initialize minimal UART for early output */
    bl uart_early_init
    
    /* Call Stage 1 C entry */
    bl stage1_main
    
    /* Should never return */
    b .

/* ========================================================================
 * Exception Handlers (Minimal - just halt)
 * ======================================================================== */

.macro EXCEPTION_HANDLER name
\name:
    SAVE_REGS
    mov x0, sp
    bl stage1_exception_handler
    b .
.endm

EXCEPTION_HANDLER _sync_el1h_sp0
EXCEPTION_HANDLER _irq_el1h_sp0
EXCEPTION_HANDLER _fiq_el1h_sp0
EXCEPTION_HANDLER _serror_el1h_sp0

EXCEPTION_HANDLER _sync_el1h_spx
EXCEPTION_HANDLER _irq_el1h_spx
EXCEPTION_HANDLER _fiq_el1h_spx
EXCEPTION_HANDLER _serror_el1h_spx

EXCEPTION_HANDLER _sync_el0
EXCEPTION_HANDLER _irq_el0
EXCEPTION_HANDLER _fiq_el0
EXCEPTION_HANDLER _serror_el0

/* ========================================================================
 * Minimal Exception Handler (Stage 1 - just print and halt)
 * ======================================================================== */
.global stage1_exception_handler
stage1_exception_handler:
    /* x0 = sp (stack frame pointer) */
    /* Save registers to local variables */
    str x2, [x0, #16]   /* esr */
    str x3, [x0, #24]   /* far */
    str x4, [x0, #32]   /* elr */
    str x5, [x0, #40]   /* sp */
    
    /* Call C function to print exception */
    bl stage1_exception_handler_c
    
    b .