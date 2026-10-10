/* dr1zzle Stage 3 Linker Script
 * Unbounded payload - prefers DRAM, falls back to SRAM
 */

MEMORY {
    DRAM (rwx) : ORIGIN = 0x800000000, LENGTH = 256M
    SRAM (rwx) : ORIGIN = 0x180028000, LENGTH = 1M
}

ENTRY(_start)

SECTIONS {
    /* Try DRAM first, fallback to SRAM if DRAM not available */
    . = 0x800000000;

    .vectors : ALIGN(2048) {
        KEEP(*(.vectors))
    } > DRAM

    .text : ALIGN(4096) {
        *(.text.boot)
        *(.text*)
        *(.rodata*)
    } > DRAM

    .data : ALIGN(4096) {
        *(.data*)
    } > DRAM

    __bss_start = .;

    .bss (NOLOAD) : ALIGN(4096) {
        *(.bss*)
        *(COMMON)
    } > DRAM

    . = ALIGN(4096);
    __bss_end = .;

    /* Heap: 1 MB in DRAM */
    .heap (NOLOAD) : ALIGN(4096) {
        _heap_start = .;
        . += 1M;
        _heap_end = .;
    } > DRAM

    /* Stack: 64 KB */
    .stack (NOLOAD) : ALIGN(4096) {
        _stack_bottom = .;
        . += 64K;
        _stack_top = .;
    } > DRAM

    /* Fallback SRAM sections if DRAM unavailable */
    .sram_fallback : {
        *(.sram_fallback)
    } > SRAM

    ASSERT(_stack_top <= ORIGIN(DRAM) + LENGTH(DRAM),
           "Stage 3 DRAM overflow")
}