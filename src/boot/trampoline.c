/*
 * dr1zzle - Trampoline and boot support
 */

#include "libc_workarounds.h"
#include "memory_map.h"
#include "mmio.h"
#include "uart.h"
#include "exception.h"
#include "util.h"

/* Trampoline hook - jumps back to stage3 trampoline_entry */
uint32_t tramp_hook[5] = {
    0x14000000,  // b .
    0x14000000,  // b .
    0x14000000,  // b .
    0x14000000,  // b .
    0x14000000,  // b .
};

/* Clear hook original backing storage */
uint32_t clear_hook_orig_backing[2] = {0, 0};

/* Jump to image at EL1 */
void jump_to_image(uint64_t image, uint64_t args) __attribute__((noreturn));
void jump_to_image(uint64_t image, uint64_t args) {
    (void)image; (void)args;
    /* Set up EL1 entry */
    __asm__ volatile(
        "msr elr_el1, %0\n"
        "msr spsr_el1, %1\n"
        "mov x2, %2\n"
        "mov x3, %3\n"
        "eret\n"
        :
        : "r"(image), "r"((uint64_t)0x3c5), "r"(args), "r"((uint64_t)0)
        : "memory", "x2", "x3"
    );
    __builtin_unreachable();
}

/* Setup EL1 environment and jump to kernel */
void setup_el1(void (*entry)(void), uint64_t image_base, uint64_t boot_args) {
    /* Set up MMU if needed */
    extern int mmu_init(void);
    extern void mmu_enable(void);
    
    /* Initialize timer */
    extern void timer_init(void);
    timer_init();
    
    /* Initialize UART for early output */
    extern void uart_early_init(void);
    uart_early_init();
    
    uart_puts("dr1zzle: setting up EL1...\n");
    uart_puts("dr1zzle: image_base=0x"); uart_puts(utoa_hex(image_base)); uart_puts("\n");
    uart_puts("dr1zzle: boot_args=0x"); uart_puts(utoa_hex(boot_args)); uart_puts("\n");
    
    /* Install vectors and enable interrupts */
    extern void exception_init(void);
    exception_init();
    
    /* Enable IRQ */
    __asm__ volatile("msr daifclr, #2" ::: "memory");
    
    /* Call the entry point */
    uart_puts("dr1zzle: jumping to kernel...\n");
    entry();
}