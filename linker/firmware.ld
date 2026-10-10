/* dr1zzle firmware linker script.
 *
 * A firmware is one of the specialized images the core menu (or `goat push
 * --run`) lays down on demand: the full monitor, a dumping build, a
 * diagnostics build. It does not share the core's tight budget, because it is
 * not written through the pwndfu command window -- the core copies it to the
 * SRAM tail and enters it. So there is no "must end below 0x18001C000" rule
 * here, only "must fit above the core and below the top of SRAM".
 *
 * The base is the SRAM tail (0x180100000), the same address as the goatloader
 * staging window and the host tool's GOAT_STAGE_BASE, so a firmware submitted
 * by `goat push --run` lands exactly where a NAND-resident one would.
 *
 * The .bss here is deliberately smaller than the old single-image build's:
 * this image does not link the MMU translation tables (it runs with the MMU
 * off, as the whole payload does), and those tables alone were ~590 KB. With
 * them the image would not fit between 0x180100000 and the top of SRAM.
 */

MEMORY
{
    FW (rwx) : ORIGIN = 0x180100000, LENGTH = 0xE8000
}

ENTRY(_start)

SECTIONS
{
    . = 0x180100000;

    .vectors : ALIGN(2048)
    {
        KEEP(*(.vectors))
    } > FW

    .text : ALIGN(4096)
    {
        *(.text.boot)
        *(.text*)
        *(.rodata*)
    } > FW

    __flat_image_end = .;

    .data : ALIGN(4096)
    {
        *(.data*)
    } > FW

    __bss_start = .;

    .bss (NOLOAD) : ALIGN(4096)
    {
        *(.bss*)
        *(COMMON)
    } > FW

    . = ALIGN(4096);
    __bss_end = .;

    .heap (NOLOAD) : ALIGN(4096)
    {
        _heap_start = .;
        . += 64K;
        _heap_end = .;
    } > FW

    .stack (NOLOAD) : ALIGN(4096)
    {
        _stack_bottom = .;
        . += 16K;
        _stack_top = .;
    } > FW

    ASSERT(_stack_top <= ORIGIN(FW) + LENGTH(FW),
           "A11 firmware exceeds the SRAM tail")

    /* The firmware links goat/loader.c for the `server` shell command, which
       needs __stage_base/__stage_limit to exist. It never receives a pushed
       container itself -- the core owns that listener -- so this window is
       only here to satisfy the symbol, and is sized to whatever is left. */
    .stage (NOLOAD) : ALIGN(4096)
    {
        __stage_base = .;
        . = ORIGIN(FW) + LENGTH(FW);
        __stage_limit = .;
    } > FW

    /DISCARD/ :
    {
        *(.comment)
        *(.note*)
        *(.eh_frame*)
    }
}
