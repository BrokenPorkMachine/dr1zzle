ENTRY(_start)
SECTIONS {
  . = 0x40080000;
  .text : { KEEP(*(.text.boot)) *(.text*) }
  .rodata : { *(.rodata*) }
  .data : { *(.data*) }
  . = ALIGN(16); __bss_start = .; .bss : { *(.bss*) *(COMMON) } __bss_end = .;
  . = ALIGN(16); __heap_start = .; . += 0x10000; __heap_end = .;
  . = ALIGN(16); __stack_bottom = .; . += 0x10000; __stack_top = .;
}
