.section .text.boot
.global _start
_start:
    msr daifset, #0xf
    adr x0, exception_vectors
    mrs x1, CurrentEL
    cmp x1, #0x8
    b.ne 0f
    msr vbar_el2, x0
    b 1f
0:  msr vbar_el1, x0
1:  isb
    ldr x0, =__stack_top
    mov sp, x0
    ldr x0, =__bss_start
    ldr x1, =__bss_end
1:  cmp x0, x1
    b.hs 2f
    strb wzr, [x0], #1
    b 1b
2:  bl kernel_main
3:  wfe
    b 3b

.align 11
exception_vectors:
.rept 16
    b exception_halt
    .space 124
.endr
exception_halt:
    wfe
    b exception_halt
