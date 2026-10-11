/* On-screen menu for the firmware monitor.
 *
 * ---------------------------------------------------------------------------
 * Layout
 * ---------------------------------------------------------------------------
 *
 * The framebuffer is divided into three bands of text rows:
 *
 *   rows  0 .. panel_end          the menu panel (title, summary, separator)
 *   rows  panel_end+1 .. sep-1    the output pane, a scrolling console
 *   row   total-2                 separator
 *   row   total-1                 pinned status line
 *
 * The panel is deliberately small: it is a summary that survives any panel
 * geometry, not the whole `help` text, which stays on the serial console.
 * A real A11 panel gives the pane at least a dozen rows (iPhone 8 portrait
 * is 166 text rows tall; even a 480-line landscape panel clears 55); the
 * pane is clamped to fit whatever the geometry allows.
 *
 * Output reaches the pane through the weak uart_mirror_hook() in uart.c,
 * overridden here. The shell wraps each command with menu_exec_begin/end,
 * so the echo of the typed line and the prompt (both emitted outside a
 * command) never touch the screen.
 *
 * No device registers are touched: this draws into the framebuffer the
 * bootloader left scanning out, exactly like display_fb.c.
 */

#include "menu.h"

#include "display.h"
#include "string.h"

/* --- colours (ARGB8888) -------------------------------------------------- */

#define PANEL_BG    0xff0a0a12u
#define TITLE_FG    0xffffd75au
#define LEDE_FG     0xff9aa2b8u
#define LINE_FG     0xffcfd4e0u
#define SEP_FG      0xff333a52u
#define PANE_BG     0xff000000u
#define PANE_FG     0xffe9e9f2u
#define STATUS_BG   0xff0e111cu
#define STATUS_FG   0xff7b86a0u

/* --- panel content ------------------------------------------------------- */

#define MENU_TITLE  "dr1zzle A11 monitor"
#define MENU_LEDE   "type on serial; output renders below - panel is fixed"

static const char *const MENU_LINES[] = {
    "dump    securerom sepos iboot llb nand nor ace2",
    "        UID GID sram dram baseband keybag + reg (dump list)",
    "nand    id info bad read dump export | erase write verify",
    "fw      list save install   (write firmware to a NAND slot)",
    "sep     ping random boot_tz0 status memdump",
    "wifi    scan select connect disconnect status",
    "aes     cbc|ecb enc|dec 128|192|256 uid|gid0|gid1",
    "display pattern mipi clear menu",
    "dash    place move group pair tile lock report",
};

#define MENU_LINE_COUNT (sizeof(MENU_LINES) / sizeof(MENU_LINES[0]))

/* Rows consumed by the panel above the separator: title + lede + menu lines. */
#define PANEL_END (2u + (uint32_t)MENU_LINE_COUNT)

#define MENU_STATUS_DEFAULT \
    "dr1zzle OpenEyeBoot  -  serial console  -  help for all commands"

/* --- state --------------------------------------------------------------- */

static int menu_up;
static int mirror_active;

static struct {
    int      live;
    uint32_t top_row;     /* first text row of the pane */
    uint32_t rows;        /* text rows in the pane */
    uint32_t cols;        /* text columns (whole width) */
    uint32_t row, col;    /* cursor within the pane */
    uint32_t fg, bg;
} pane;

/* --- drawing ------------------------------------------------------------- */

static void draw_char(uint32_t abs_col, uint32_t abs_row, uint8_t code,
                      uint32_t fg) {
    const display_fb_t *fb = display_fb();
    if (!fb) return;
    if (code < FONT_FIRST || code > FONT_LAST) code = ' ';

    uint32_t x = abs_col * FONT_CELL_W;
    uint32_t y = abs_row * FONT_CELL_H;
    if (x >= fb->width || y >= fb->height) return;

    const uint8_t *glyph = font8x8[code - FONT_FIRST];
    for (uint32_t i = 0; i < FONT_GLYPH_H; i++) {
        uint8_t bits = glyph[i];
        if (!bits) continue;
        for (uint32_t j = 0; j < FONT_GLYPH_W; j++) {
            if (bits & (1u << j)) display_fb_pixel(x + j, y + i, fg);
        }
    }
}

static void draw_text(uint32_t abs_col, uint32_t abs_row, const char *s,
                      uint32_t fg, uint32_t limit_cols) {
    const display_fb_t *fb = display_fb();
    uint32_t cols = fb ? fb->width / FONT_CELL_W : 0;
    uint32_t col = abs_col;
    while (*s && (limit_cols == 0 || col < limit_cols)) {
        if (col < cols) draw_char(col, abs_row, (uint8_t)*s, fg);
        col++;
        s++;
    }
}

/* --- output pane --------------------------------------------------------- */

static void pane_clear_cell(uint32_t col, uint32_t row) {
    const display_fb_t *fb = display_fb();
    if (!fb || !pane.live || col >= pane.cols || row >= pane.rows) return;
    display_fb_fill_rect(col * FONT_CELL_W, (pane.top_row + row) * FONT_CELL_H,
                         FONT_CELL_W, FONT_CELL_H, pane.bg);
}

static void pane_scroll(void) {
    const display_fb_t *fb = display_fb();
    if (!fb || pane.rows < 2) return;

    /* Slide every pane row up one cell row; the band stays where it is, so
     * the panel and the status line are never touched. */
    uint32_t row_bytes = fb->stride * FONT_CELL_H;
    uint8_t *base = (uint8_t *)fb->pixels +
                    (uintptr_t)pane.top_row * fb->stride * FONT_CELL_H;
    for (uint32_t r = 1; r < pane.rows; r++) {
        memcpy(base + (r - 1) * row_bytes, base + r * row_bytes, row_bytes);
    }

    uint32_t last_y = (pane.top_row + pane.rows - 1) * FONT_CELL_H;
    display_fb_fill_rect(0, last_y, fb->width, FONT_CELL_H, pane.bg);
    pane.row = pane.rows - 1;
}

static void pane_newline(void) {
    pane.col = 0;
    if (pane.row + 1u < pane.rows) {
        pane.row++;
        return;
    }
    pane_scroll();
}

void menu_output_putc(char c) {
    if (!pane.live || pane.rows == 0) return;

    if (c == '\n') { pane_newline(); return; }
    if (c == '\r') { pane.col = 0; return; }
    if (c == '\b') {
        if (pane.col > 0) {
            pane.col--;
            pane_clear_cell(pane.col, pane.row);
        }
        return;
    }

    if (pane.col >= pane.cols) pane_newline();
    pane_clear_cell(pane.col, pane.row);
    draw_char(pane.col, pane.top_row + pane.row, (uint8_t)c, pane.fg);
    if (++pane.col >= pane.cols) pane_newline();
}

void menu_output_puts(const char *s) {
    while (*s) menu_output_putc(*s++);
}

void menu_output_clear(void) {
    const display_fb_t *fb = display_fb();
    pane.row = pane.col = 0;
    if (!pane.live || !fb || pane.rows == 0) return;
    display_fb_fill_rect(0, pane.top_row * FONT_CELL_H, fb->width,
                         pane.rows * FONT_CELL_H, pane.bg);
}

/* --- public surface ------------------------------------------------------ */

int menu_active(void) {
    return menu_up;
}

uint32_t menu_panel_rows(void) {
    return (uint32_t)PANEL_END;
}

void menu_redraw(void) {
    const display_fb_t *fb = display_fb();
    menu_up = 0;
    pane.live = 0;
    pane.row = pane.col = 0;
    if (!fb) return;

    uint32_t cols = fb->width / FONT_CELL_W;
    uint32_t rows = fb->height / FONT_CELL_H;
    if (cols == 0 || rows == 0) return;
    menu_up = 1;

    /* Fresh canvas: whatever was on the panel (bootloader splash, a colour
     * bar, a crashed session) is gone. */
    display_fb_fill(PANEL_BG);

    draw_text(1, 0, MENU_TITLE, TITLE_FG, 0);
    draw_text(1, 1, MENU_LEDE, LEDE_FG, 0);
    for (uint32_t i = 0; i < MENU_LINE_COUNT; i++) {
        draw_text(1, 2u + i, MENU_LINES[i], LINE_FG, 0);
    }
    display_fb_fill_rect(0, PANEL_END * FONT_CELL_H, fb->width, 1, SEP_FG);

    /* Pinned status line at the very bottom. */
    uint32_t status_sep = rows > 2 ? rows - 2u : 0;
    uint32_t status_row = rows > 1 ? rows - 1u : 0;
    if (status_sep > PANEL_END) {
        display_fb_fill_rect(0, status_sep * FONT_CELL_H, fb->width, 1, SEP_FG);
    }
    if (rows > 1) {
        display_fb_fill_rect(0, status_row * FONT_CELL_H, fb->width,
                             FONT_CELL_H, STATUS_BG);
        draw_text(1, status_row, MENU_STATUS_DEFAULT, STATUS_FG, 0);
    }

    /* Output pane: every row between the panel and the status line. */
    pane.live = 1;
    pane.cols = cols;
    pane.top_row = PANEL_END + 1u;
    pane.rows = status_sep > pane.top_row ? status_sep - pane.top_row : 0;
    pane.row = pane.col = 0;
    pane.fg = PANE_FG;
    pane.bg = PANE_BG;
    if (pane.rows > 0) {
        display_fb_fill_rect(0, pane.top_row * FONT_CELL_H, fb->width,
                             pane.rows * FONT_CELL_H, pane.bg);
    }
}

void menu_init(void) {
    menu_redraw();
}

void menu_status_write(const char *s) {
    const display_fb_t *fb = display_fb();
    if (!menu_up || !fb) return;
    uint32_t rows = fb->height / FONT_CELL_H;
    if (rows < 2) return;
    uint32_t status_row = rows - 1;
    display_fb_fill_rect(0, status_row * FONT_CELL_H, fb->width,
                         FONT_CELL_H, STATUS_BG);
    draw_text(1, status_row, s ? s : MENU_STATUS_DEFAULT, STATUS_FG, 0);
}

void menu_exec_begin(void) {
    mirror_active = 1;
}

void menu_exec_end(void) {
    mirror_active = 0;
}

/* The strong definition of the weak hook in uart.c: byte-per-byte mirror of
 * command output into the pane. */
void uart_mirror_hook(char c) {
    if (mirror_active) menu_output_putc(c);
}
