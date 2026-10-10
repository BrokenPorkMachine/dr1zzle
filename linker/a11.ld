/* A11 Research Payload Linker Script
 * Target: Apple A11 (T8015) - iPhone 8/X
 * SRAM: 0x1800_00000 - 0x1801_E8000 (1.9 MB)
 *
 * VBAR_EL1 requires the vector table to sit on a 2KB boundary, so .vectors
 * comes first and is 2KB-aligned. __bss_start/__bss_end are consumed by
 * start.S to zero .bss before the first C call.
 */

MEMORY
{
    SRAM (rwx) : ORIGIN = 0x180000000, LENGTH = 0x1E8000
}

ENTRY(_start)

SECTIONS
{
    . = 0x180000000;

    .vectors : ALIGN(2048)
    {
        KEEP(*(.vectors))
    } > SRAM

    .text : ALIGN(4096)
    {
        *(.text.boot)
        *(.text*)
        *(.rodata*)
    } > SRAM

    /* End of the flat image. Everything past this point is initialised RAM,
       and the image itself has to end below the pwndfu command area at
       0x18001C000 (goat/usb.py, DFU_IMAGE_BASE) -- that is the channel the
       upload travels through, so overlapping it is the one placement failure
       that cannot be recovered from on the device. Asserted rather than
       measured, because a link failure that names the rule is worth more than
       a host-side test that notices afterwards.

       This is the *core* image, so the bound is the real one (0x1C000), not
       the padded 0x20000 the single-image build used while it was being
       trimmed back under it. */
    __flat_image_end = .;

    ASSERT(__flat_image_end <= ORIGIN(SRAM) + 0x1C000,
           "A11 flat image overlaps the pwndfu command area")

    .data : ALIGN(4096)
    {
        *(.data*)
    } > SRAM

    __bss_start = .;

    .bss (NOLOAD) : ALIGN(4096)
    {
        *(.bss*)
        *(COMMON)
    } > SRAM

    . = ALIGN(4096);
    __bss_end = .;

    /* Heap contents are runtime state and must not inflate the flat payload. */
    .heap (NOLOAD) : ALIGN(4096)
    {
        _heap_start = .;
        . += 64K;
        _heap_end = .;
    } > SRAM

    .stack (NOLOAD) : ALIGN(4096)
    {
        _stack_bottom = .;
        . += 16K;
        _stack_top = .;
    } > SRAM

    /* .stack grows down from _stack_top; keep it clear of the 2MB image
       window entry.S copies when the payload is loaded via checkm8. */
    ASSERT(_stack_top <= ORIGIN(SRAM) + LENGTH(SRAM),
           "A11 SRAM overflow: payload exceeds 1.9MB")

    /* Goatloader staging window, pinned to the tail of SRAM.
     *
     * The base is a shared constant, not a leftover: goat/container.py's
     * GOAT_STAGE_BASE is 0x180100000 and the host tool refuses to place a
     * container outside [GOAT_STAGE_BASE, SRAM end]. The device side used to
     * compute this address dynamically from wherever .bss/heap/stack happened
     * to end, which quietly drifted above 0x180100000 once .bss grew -- the
     * two sides then disagreed and every `goat push` was rejected as a
     * placement error. Pinning it here, and asserting the core's own RAM
     * stays below it, is what keeps the two definitions equal.
     *
     * This is also where a firmware loaded from a NAND slot (fw_store.c) is
     * copied before it is entered, so the push window and the run window are
     * deliberately the same 0xE8000 bytes. */
    .stage (NOLOAD) : ALIGN(4096)
    {
        __stage_base = ORIGIN(SRAM) + 0x100000;
        . = ORIGIN(SRAM) + LENGTH(SRAM);
        __stage_limit = .;
    } > SRAM

    ASSERT(_stack_top <= __stage_base,
           "A11 core RAM reaches into the staging window; shrink .bss/heap")

    ASSERT(__stage_limit - __stage_base >= 64K,
           "A11 SRAM exhausted: no room for a staging window")

    /DISCARD/ :
    {
        *(.comment)
        *(.note*)
        *(.eh_frame*)
    }
}
