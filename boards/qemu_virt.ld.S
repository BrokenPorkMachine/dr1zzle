#include "qemu_budget.h"
ENTRY(_start)
MEMORY { ARENA (rwx) : ORIGIN = 0x40080000, LENGTH = QEMU_ARENA }
SECTIONS {
  . = ORIGIN(ARENA);
  __image_start = .;
  .text : { KEEP(*(.text.boot)) *(.text*) } > ARENA
  .rodata : { *(.rodata*) } > ARENA
  .data : { *(.data*) } > ARENA
  .bss (NOLOAD) : ALIGN(16) {
    __bss_start = .; *(.bss*) *(COMMON) . = ALIGN(16); __bss_end = .;
  } > ARENA
  .heap (NOLOAD) : ALIGN(16) {
    __heap_start = .; . += QEMU_HEAP; __heap_end = .;
  } > ARENA
  .stack (NOLOAD) : ALIGN(16) {
    __stack_bottom = .; . += QEMU_STACK; __stack_top = .;
  } > ARENA
  ASSERT(__heap_start - __image_start <= QEMU_IMAGE, "profile image budget exceeded")
  ASSERT(__stack_top + QEMU_RESERVE <= ORIGIN(ARENA) + LENGTH(ARENA), "profile arena exhausted")
  /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) }
}
