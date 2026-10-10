/* dr1zzle Stage 2 Linker Script
 * 128 KB limit for Asset Manager
 */

MEMORY {
    SRAM (rwx) : ORIGIN = 0x180008000, LENGTH = 128K
}

ENTRY(_start)

SECTIONS {
    . = 0x180008000;

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

    ASSERT(__flat_image_end <= ORIGIN(SRAM) + 128K,
           "Stage 2 exceeds 128 KB limit")

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

    /* Heap: 16 KB */
    .heap (NOLOAD) : ALIGN(4096) {
        _heap_start = .;
        . += 16K;
        _heap_end = .;
    } > SRAM

    /* Stack: 8 KB */
    .stack (NOLOAD) : ALIGN(4096) {
        _stack_bottom = .;
        . += 8K;
        _stack_top = .;
    } > SRAM

    ASSERT(_stack_top <= ORIGIN(SRAM) + LENGTH(SRAM),
           "Stage 2 SRAM overflow")
}