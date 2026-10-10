/* dr1zzle A11 bare-metal entry.
 *
 * Replaces the previous start.S, which had three defects that made it
 * unusable on silicon:
 *   1. The vector table was 48 bytes of `b`/`.skip` instead of 16 slots of
 *      0x80, and was not 2KB-aligned as VBAR_EL1 requires.
 *   2. SAVE_REGS/RESTORE_REGS allocated 128 bytes but wrote up to [sp,#224],
 *      and reused slots #10 and #11 for two different register pairs, so
 *      x20-x27 were clobbered on every exception.
 *   3. SP was never loaded from _stack_top, and .bss was never zeroed, so the
 *      first C call ran on whatever SP checkm8 happened to leave behind.
 *
 * MMU stays OFF by default. The identity map in mmu.c is real but is
 * untestable from here (see MMU_ENABLE below), and a wrong translation table
 * takes the payload down on the first instruction fetch after SCTLR.M=1.
 */

.section .vectors, "ax", %progbits
.global _vectors
.align 11                              /* VBAR_EL1 needs 2KB alignment */
_vectors:
    /* Current EL with SP0: Sync, IRQ, FIQ, SError */
    .balign 128
    b   _sync_el1h
    .balign 128
    b   _irq_el1h
    .balign 128
    b   _fiq_el1h
    .balign 128
    b   _serror_el1h

    /* Current EL with SPx: Sync, IRQ, FIQ, SError */
    .balign 128
    b   _sync_el1h
    .balign 128
    b   _irq_el1h
    .balign 128
    b   _fiq_el1h
    .balign 128
    b   _serror_el1h

    /* Lower EL using AArch64: Sync, IRQ, FIQ, SError */
    .balign 128
    b   _sync_el1h
    .balign 128
    b   _irq_el1h
    .balign 128
    b   _fiq_el1h
    .balign 128
    b   _serror_el1h

    /* Lower EL using AArch32: Sync, IRQ, FIQ, SError */
    .balign 128
    b   _sync_el1h
    .balign 128
    b   _irq_el1h
    .balign 128
    b   _fiq_el1h
    .balign 128
    b   _serror_el1h
/* Pad out to exactly 0x800 bytes so the table cannot spill into whatever the
 * linker places next. The 15th slot's branch ends at 0x784. */
    .org 0x800, 0

/* 256-byte frame: x0-x30 plus room to grow. Slot n is at [sp, #n*16]. */
.macro SAVE_REGS
    sub     sp, sp, #256
    stp     x0,  x1,  [sp, #0]
    stp     x2,  x3,  [sp, #16]
    stp     x4,  x5,  [sp, #32]
    stp     x6,  x7,  [sp, #48]
    stp     x8,  x9,  [sp, #64]
    stp     x10, x11, [sp, #80]
    stp     x12, x13, [sp, #96]
    stp     x14, x15, [sp, #112]
    stp     x16, x17, [sp, #128]
    stp     x18, x19, [sp, #144]
    stp     x20, x21, [sp, #160]
    stp     x22, x23, [sp, #176]
    stp     x24, x25, [sp, #192]
    stp     x26, x27, [sp, #208]
    stp     x28, x29, [sp, #224]
    str     x30,     [sp, #240]
.endm

.macro RESTORE_REGS
    ldr     x30,     [sp, #240]
    ldp     x28, x29, [sp, #224]
    ldp     x26, x27, [sp, #208]
    ldp     x24, x25, [sp, #192]
    ldp     x22, x23, [sp, #176]
    ldp     x20, x21, [sp, #160]
    ldp     x18, x19, [sp, #144]
    ldp     x16, x17, [sp, #128]
    ldp     x14, x15, [sp, #112]
    ldp     x12, x13, [sp, #96]
    ldp     x10, x11, [sp, #80]
    ldp     x8,  x9,  [sp, #64]
    ldp     x6,  x7,  [sp, #48]
    ldp     x4,  x5,  [sp, #32]
    ldp     x2,  x3,  [sp, #16]
    ldp     x0,  x1,  [sp, #0]
    add     sp, sp, #256
.endm

.section .text.boot, "ax", %progbits
.global _start
_start:
    /* Land at EL1 with interrupts masked and caches off. checkm8 leaves the
       CPU in a known-enough state that we only need to be defensive. */
    msr     daifset, #0xf

    /* x0 holds the device tree pointer the bootloader handed over. Save it
       in x19 before anything below clobbers x0; x19 is callee-saved and is
       preserved by SAVE_REGS, so it survives the whole run. */
    mov     x19, x0

    mrs     x0, CurrentEL
    cmp     x0, #0x8                    /* EL1h */
    b.ne    1f
    mov     x1, #0x3                    /* EL1h + SP_EL1 */
    msr     spsr_el1, x1
    msr     elr_el1, lr
    eret
1:
    /* Stack first: everything below may call into C. */
    ldr     x0, =_stack_top
    mov     sp, x0

    /* Zero .bss before any C code touches a static. */
    ldr     x0, =__bss_start
    ldr     x1, =__bss_end
2:  cmp     x0, x1
    b.hs    3f
    strb    wzr, [x0], #1
    b       2b
3:
    /* MMU and caches off. */
    mrs     x0, sctlr_el1
    bic     x0, x0, #(1 << 0)           /* M  */
    bic     x0, x0, #(1 << 2)           /* C  */
    bic     x0, x0, #(1 << 12)          /* I  */
    bic     x0, x0, #(1 << 1)           /* A  */
    msr     sctlr_el1, x0
    isb

    /* Vector table. adp is +-1MB, which covers a payload this size. */
    adrp    x0, _vectors
    add     x0, x0, :lo12:_vectors
    msr     vbar_el1, x0
    isb

    /* Physical counter: used by timer_now_* and the busy-wait helpers. */
    mov     x0, #1
    msr     cntp_ctl_el0, x0
    msr     cntv_ctl_el0, x0

    /* Publish the entry-state device tree pointer for C. This has to happen
       after the .bss clear above, or the store lands in memory we then zero. */
    adrp    x0, g_boot_dtb
    add     x0, x0, :lo12:g_boot_dtb
    str     x19, [x0]

    bl      c_main

    /* c_main owns driver bring-up. Unmask interrupts only once it is done,
       otherwise we take an IRQ against uninitialised state.

       Only the I bit, not F. Every FIQ source this SoC has -- fast IPIs,
       the ARM generic timers, the performance monitors -- is either
       unused by this payload or masked by its driver, and fiq_handler()
       stops the payload rather than servicing one. */
    msr     daifclr, #2

    /* Should never return. */
    b       .

/* ------------------------------------------------------------------ */
/* Exception vectors.                                                  */
/* ------------------------------------------------------------------ */
.section .text, "ax", %progbits

_sync_el1h:
    SAVE_REGS
    mrs     x0, esr_el1
    mrs     x1, far_el1
    mrs     x2, spsr_el1
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
    mrs     x0, esr_el1
    mrs     x1, far_el1
    bl      serror_handler
    RESTORE_REGS
    eret

/* PMGR-based reset. Address symbols come from pmgr.c so the register offsets
 * are defined once. This runs with a valid stack (it is reached from the
 * shell via C), unlike the early boot path.
 *
 * NOTE: mask is 0xffffffff, i.e. reset everything. Narrow it per-device once
 * the PMGR bit map has been verified against silicon. */
.global reboot
reboot:
    adrp    x0, pmgr_reset_assert_addr
    add     x0, x0, :lo12:pmgr_reset_assert_addr
    ldr     x1, [x0]
    mov     x2, #0xffffffff
    str     x2, [x0]
    dsb     sy
    adrp    x0, pmgr_reset_deassert_addr
    add     x0, x0, :lo12:pmgr_reset_deassert_addr
    str     x2, [x0]
    dsb     sy
    isb
1:  wfe
    b       1b