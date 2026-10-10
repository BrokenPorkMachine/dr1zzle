/*
 * dr1zzle - Clear hook for DRAM clear bypass
 * Based on pongoOS clearhook.S
 */

.globl _clear_hook
.globl _clear_hook_end
.globl _clear_hook_orig_backing

.align 4

_clear_hook:
    mov x16, x30              // Save LR
    mov x30, x5               // Move arg5 to LR (trampoline target)
    
    // Check if address is in DRAM range (0x800000000 - 0x80018e0000)
    mov x3, #0x800000000
    movk x3, #0x1800, lsl#16
    cmp x0, x3
    b.hi _clear_hook_orig_backing
    add x2, x1, x0
    cmp x2, x3
    b.lo _clear_hook_orig_backing
    
    // Check if address is in other protected range
    mov x3, #0x800000000
    movk x3, #0x18e0, lsl#16
    cmp x0, x3
    b.hi _clear_hook_orig_backing
    add x2, x1, x0
    cmp x2, x3
    b.lo _clear_hook_orig_backing
    
    // Not in protected range, allow the clear
    mov x1, #0
    
_clear_hook_orig_backing:
    nop
    nop
    br x16                    // Return to caller
_clear_hook_end: