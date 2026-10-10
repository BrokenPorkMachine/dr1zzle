# Portable serial console mirroring

The portable console in `lib/console.c` sends each output character to its
serial writer and optional display writer. Serial remains the only input
source. Prompts, command output, and input echoed by `kernel/monitor.c` are
mirrored automatically. This does not forward incoming bytes until the monitor
echoes them, and does not buffer or replay output emitted before attachment.

For an existing text display driver, call
`drizzle_console_bind_display(driver_putc)` after driver initialization.
Pass a null function pointer to detach. Binding serial again preserves the
display binding. Callbacks must complete synchronously and must not rebind
the console. Recursive writes are dropped. The console is single-threaded;
callers must serialize access and avoid interrupt-context output.

For a ready-to-use RAM display, compile `kernel/display.c`,
`kernel/display_font.c` and `kernel/display_memory.c`, then call
`drizzle_display_memory_init()` after binding serial and before printing.
It returns 1 on success and provides a 640x240, 32-bit RGB framebuffer with
an 80x30 ASCII console, consuming 614400 bytes of static RAM. Initialization
clears the buffer and attaches the output mirror. Use
`drizzle_display_memory_config()` to access the buffer and its geometry for
presentation or inspection. This backend does not configure hardware scanout
by itself. The QEMU monitor profile uses `kernel/qemu_ramfb.c` to connect this
buffer to QEMU's `ramfb` device through `fw_cfg`. Run `make qemu` for the
display and an interactive PL011 UART in the terminal.

For a caller-supplied mapped framebuffer, compile `kernel/display.c` and
`kernel/display_font.c` and call
`drizzle_display_attach()` with a `drizzle_display_config_t`. The caller
provides the buffer, its capacity, dimensions, stride in pixels, foreground
and background in the framebuffer's native 32-bit pixel format, and an ASCII
8x8 bitmap font, or NULL to use the built-in font. The built-in font reuses
the repository's authored 5x7 ASCII artwork in 8x8 cells; its table is
generated with `python3 scripts/gen_font.py --portable`. Both buffer and
any custom font must remain valid until detachment. An optional flush callback handles
visibility for noncoherent displays. No hardware registers are accessed.

The renderer handles carriage return, newline, backspace, tab, form feed,
wrapping and scrolling. High bytes render as `?`; this is an ASCII text sink,
not a UTF-8 or ANSI terminal. Backspace moves the cursor, allowing the
monitor's backspace-space-backspace sequence to erase. Only complete 8x8
cells are rendered; row padding and partial-cell margins are preserved.
Invalid configurations fail without replacing an existing attachment.

Run the memory-backed driver and serial passthrough checks from the repo root:

```sh
make -f tests/Makefile.console test
make -f tests/Makefile.console preview
```

The preview exports the actual rendered RAM buffer to
`/tmp/dr1zzle-console-tests/display.ppm`, including letters, numbers and
punctuation. It is a host preview, not output captured from a physical panel.

This implementation belongs to the portable `kernel/` and `lib/` tree.
The root Makefile's A11 payload uses a separate UART implementation and is
not connected to this adapter. Physical display scanout still needs a board
integration.
The hardware research stubs remain unchanged.

Reference: [pongoOS framebuffer driver](https://github.com/checkra1n/pongoOS/blob/master/src/drivers/framebuffer/fb.c)
was consulted for the high-level separation of framebuffer dimensions, row
stride and write visibility. No implementation or font data was copied.
