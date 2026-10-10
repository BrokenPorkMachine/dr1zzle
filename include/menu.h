#ifndef DR1ZZLE_MENU_H
#define DR1ZZLE_MENU_H

#include <stdint.h>

/* On-screen menu for the firmware monitor (src/ui/menu.c).
 *
 * The framebuffer is split into three bands of text rows:
 *
 *   1. a fixed menu panel at the top (title, command summary, hint),
 *   2. a scrolling output pane in the middle,
 *   3. a pinned status line at the bottom.
 *
 * Commands are typed on the serial console. Only command *output* is
 * mirrored into the pane -- never the echo, the prompt, or the banner -- so
 * issuing a command does not start a new line under the menu; the panel
 * stays put and the output occupies the reserved rows below it.
 *
 * The mirror runs through the weak hook uart_mirror_hook() in uart.c, which
 * this file overrides. The core bootstrap links only the weak no-op and no
 * nothing about a framebuffer.
 *
 * `clear` (menu_redraw) recreates the whole canvas: the framebuffer is
 * wiped and the panel and status line are drawn fresh, so the operator is
 * never looking at leftovers from the previous session.
 *
 * Every function is safe to call with no framebuffer attached; they no-op.
 */

void menu_init(void);         /* fresh canvas at display bring-up */
void menu_redraw(void);       /* full wipe + panel + status (the `clear` path) */

void menu_output_clear(void); /* blank the pane, cursor to its top-left */
void menu_output_putc(char c);
void menu_output_puts(const char *s);

void menu_exec_begin(void);   /* mirror command output into the pane */
void menu_exec_end(void);     /* stop mirroring (echo/prompts stay serial-only) */

void menu_status_write(const char *s); /* rewrite the pinned status line */

int  menu_active(void);       /* 1 iff the menu owns a live framebuffer */

/* The row index of the separator under the panel: the panel occupies rows
 * 0..menu_panel_rows(), and the output pane starts on the row after it. The
 * host test derives the pane geometry from this rather than hardcoding it,
 * which would break every time the panel summary gains a line. */
uint32_t menu_panel_rows(void);

/* Called by uart.c for every emitted byte; this strong definition feeds the
 * pane while a command is executing. The core has only the weak no-op. */
void uart_mirror_hook(char c);

#endif /* DR1ZZLE_MENU_H */