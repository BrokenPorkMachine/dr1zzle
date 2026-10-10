# The on-screen menu

The firmware monitor (`build/firmware/dr1zzle`) draws a menu into the
framebuffer the bootloader left scanning out. Input stays on the serial
console; the menu is *output*, not a widget toolkit.

Implementation: `src/ui/menu.c`, API in `include/menu.h`, wired up in
`src/main.c` right after `display_attach_discovered()`.

## Layout

The framebuffer is split into three bands of 8-pixel text rows:

```
row 0            title
row 1            lede
rows 2 .. 9      command summary (one line per group)
row 10           separator
rows 11 .. n-3   output pane         <- reserved space below the menu
row n-2          separator
row n-1          pinned status line
```

`n` is `height / 8`. On any real A11 panel the pane is large — iPhone 8
portrait gives roughly 150 rows, a 640x240 panel gives 17 — so the menu never
has to truncate the reserved space to fit.

The panel is a *summary*, not the whole `help` text: the full command list is
dozens of lines and belongs on the serial console. The panel points at it
(`help`) and lists the groups.

## Why the menu never moves

`clear` used to call `display_console_clear()`, which cleared a full-screen
raster console that nothing wrote to, so the screen appeared not to clear
while the menu (drawn elsewhere) stayed put. That path is replaced.

The menu owns the screen and is drawn once. Command output is *mirrored* into
the pane through a byte hook, and the shell arms the hook only for the
duration of a command:

- `uart_putc()` calls the weak `uart_mirror_hook()` for every byte.
- `src/ui/menu.c` gives that hook a strong definition that renders into the
  pane, but only while `menu_exec_begin()`/`menu_exec_end()` have armed it.
- `shell_run()` and `shell_exec()` bracket each `execute(...)` with those two
  calls. The typed line echo and the `research>` prompt are emitted *outside*
  that window, so they never reach the pane.

The result is exactly the requested behaviour: issuing a command does not
start a new line under the menu. The echo and prompt live on the operator's
serial terminal; the command's output appears in the reserved pane and scrolls
*within its band* (the panel and status line are never touched).

The core bootstrap links only the weak no-op — it has no framebuffer and does
not need one.

## Commands

- `clear` — wipe the whole framebuffer, redraw the panel and status line, and
  blank the output pane. A genuinely fresh canvas, not a scroll.
- `menu` — redraw the menu without blanking the pane (useful after `pattern`).
- `display` — reports the framebuffer geometry and whether the menu is up.

Every menu entry point is a safe no-op when no framebuffer is attached, so the
firmware behaves the same on a headless bring-up.

## Overlay fallback

The design brief allowed an overlay-with-OK-button if the menu were ever too
long to leave output space. It is not: the panel is a fixed summary and the
pane is whatever is left, so the reserved-space option is always available and
the overlay was not needed.

## Tests

`make menu-test` builds `tests/menu_host_test.c` on the host with a framebuffer
double (a host pointer is 64-bit; `display_fb_attach()` takes a 32-bit
physical address, so the test supplies its own backing store). It checks the
three-band layout, that command output lands in the pane, that the echo window
does not, that scrolling stays inside the pane, that `clear` recreates the
canvas, and that a detached framebuffer makes every call a no-op.
