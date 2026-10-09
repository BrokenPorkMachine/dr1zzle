/* A11 Research Payload Linker Script
 * Target: Apple A11 (T8015) - iPhone 8/X
 * SRAM: 0x1800_00000 - 0x1801_E8000 (1.9 MB)
 */

MEMORY
{
    SRAM (rwx) : ORIGIN = 0x180000000, LENGTH = 0x1E8000
}

ENTRY(c_main)

SECTIONS
{
    . = 0x180000000;
    
    .vectors : 
    {
        KEEP(*(.vectors))
    } > SRAM

    .bss : ALIGN(4096)
    {
        *(.bss*)
        *(COMMON)
    } > SRAM

    .text : ALIGN(4096)
    {
        *(.text*)
        *(.rodata*)
    } > SRAM

    .data : ALIGN(4096)
    {
        *(.data*)
    } > SRAM

    .heap : ALIGN(4096)
    {
        _heap_start = .;
        . += 64K;
        _heap_end = .;
    } > SRAM

    .stack : ALIGN(4096)
    {
        _stack_bottom = .;
        . += 16K;
        _stack_top = .;
    } > SRAM

    _stack_top = 0x1801E8000;
    _heap_start = .;
}
