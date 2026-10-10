/* dr1zzle Stage 1 Linker Script
 * 32 KB limit for minimal bootstrap
 */

MEMORY {
    SRAM (rwx) : ORIGIN = 0x180000000, LENGTH = 32K
}

ENTRY(_start)

SECTIONS {
    . = 0x180000000;

    .vectors : ALIGN(2048) {
        KEEP(*(.vectors))
    } > SRAM

    .text : ALIGN(4096) {
        *(.text.boot)
        *(.text*)
        *(.rodata*)
    } > SRAM

    /* End of flat image */
    __flat_image_end = .;

    ASSERT(__flat_image_end <= ORIGIN(SRAM) + 32K,
           "Stage 1 exceeds 32 KB limit")

    .data : ALIGN(4096) {
        *(.data*)
    } > SRAM

    __bss_start = .;

    .bss (NOLOAD) : ALIGN(4096) {
        *(.bss*)
        *(COMMON)
    } > SRAM

    . = ALIGN(4096);
    __bss_end = .;

    /* Heap: 4 KB */
    .heap (NOLOAD) : ALIGN(4096) {
        _heap_start = .;
        . += 4K;
        _heap_end = .;
    } > SRAM

    /* Stack: 4 KB */
    .stack (NOLOAD) : ALIGN(4096) {
        _stack_bottom = .;
        . += 4K;
        _stack_top = .;
    } > SRAM

    ASSERT(_stack_top <= ORIGIN(SRAM) + LENGTH(SRAM),
           "Stage 1 SRAM overflow")
}