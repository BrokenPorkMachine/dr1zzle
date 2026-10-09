# libdrizzle support

`libdrizzle` is a freestanding libc subset for the dr1zzle monitor. It is not a
host libc replacement and it does not provide syscalls, files, locale, threads,
floating point formatting, or process APIs.

Implemented headers:

- `stddef.h`
- `stdint.h`
- `stdarg.h`
- `stdbool.h`
- `limits.h`
- `errno.h`
- `string.h`
- `ctype.h`
- `stdlib.h`
- `stdio.h`

Implemented runtime areas:

- memory and string primitives: `memcpy`, `memmove`, `memset`, `memcmp`,
  `strlen`, `strcmp`, `strncmp`, `strcpy`, `strncpy`, `strchr`, `strrchr`,
  `strstr`
- character classes and case conversion
- bounded heap allocation with `malloc`, `calloc`, `realloc`, and `free`
- integer conversion with `atoi`, `strtol`, and `strtoul`
- sorting/search with `qsort` and `bsearch`
- console output with `putchar` and `puts`
- bounded formatting with `snprintf` and `vsnprintf` for `%c`, `%s`, `%d`,
  `%i`, `%u`, `%x`, `%X`, `%p`, and `%%`, including common width, precision,
  sign, zero-padding, left-align, alternate-hex, and `hh`/`h`/`l`/`ll`/`z`
  length handling

Known limits:

- `snprintf`/`vsnprintf` are covered by host tests but are not used in the
  boot-critical QEMU path until the freestanding variadic call path has deeper
  exception diagnostics.
- `abs(INT_MIN)` and `labs(LONG_MIN)` saturate instead of invoking undefined
  behavior.
- The allocator is a simple bounded first-fit heap intended for monitor-scale
  use, not long-running fragmentation-heavy workloads.
