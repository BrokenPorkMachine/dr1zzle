/* Host tests for the on-screen menu (src/ui/menu.c).
 *
 * The menu's on-device contract is a layout one: a fixed panel at the top, a
 * scrolling output pane in the reserved rows below it, and a pinned status
 * line -- plus a `clear` (menu_redraw) that recreates the whole canvas. None
 * of that needs a real panel; it needs a framebuffer with rows in it.
 *
 * display_fb_attach() takes a 32-bit physical address, which a host pointer
 * is not, so this test supplies its own framebuffer backing store and the
 * display_fb_* entry points menu.c calls. The code under test is menu.c's own
 * layout and pane-scrolling logic.
 *
 *   make menu-test
 */

#include <stdint.h>
#include <string.h>

#include "display.h"
#include "menu.h"

/* The project's include/stdio.h shadows the host one on this include path and
 * does not declare printf, so declare exactly what this test uses. */
int printf(const char *fmt, ...);

#define FB_W 640u
#define FB_H 240u

/* --- framebuffer double (the display_fb_* surface menu.c calls) ---------- */

static display_fb_t fb;
static uint32_t store[FB_W * FB_H];

static void fb_double(uint32_t width, uint32_t height) {
    fb.width = width;
    fb.height = height;
    fb.bpp = 32;
    fb.stride = width * 4u;
    fb.pixels = store;
    fb.valid = 1;
}

const display_fb_t *display_fb(void) { return fb.valid ? &fb : 0; }

void display_fb_pixel(uint32_t x, uint32_t y, uint32_t pixel) {
    if (!fb.valid || x >= fb.width || y >= fb.height) return;
    *(uint32_t *)((uint8_t *)fb.pixels + y * fb.stride + x * 4u) = pixel;
}

void display_fb_fill_rect(uint32_t x, uint32_t y, uint32_t w, uint32_t h,
                          uint32_t pixel) {
    if (!fb.valid) return;
    if (x >= fb.width || y >= fb.height) return;
    if (x + w > fb.width) w = fb.width - x;
    if (y + h > fb.height) h = fb.height - y;
    if (w == 0 || h == 0) return;

    uint8_t *row = (uint8_t *)fb.pixels + y * fb.stride;
    uint32_t *r = (uint32_t *)row;
    for (uint32_t i = 0; i < w; i++) r[x + i] = pixel;
    for (uint32_t j = 1; j < h; j++)
        memcpy(row + j * fb.stride, row, w * 4u);
}

void display_fb_fill(uint32_t pixel) {
    display_fb_fill_rect(0, 0, fb.width, fb.height, pixel);
}

/* --- tiny check harness -------------------------------------------------- */

static int failures, checks;

static void check(int cond, const char *what) {
    checks++;
    if (!cond) {
        failures++;
        printf("  FAIL: %s\n", what);
    }
}

static uint32_t px(uint32_t x, uint32_t y) {
    return *(uint32_t *)((uint8_t *)store + y * (FB_W * 4u) + x * 4u);
}

/* 1 if any pixel in [x0,x1) on row y differs from bg. */
static int row_has_ink(uint32_t y, uint32_t x0, uint32_t x1, uint32_t bg) {
    for (uint32_t x = x0; x < x1; x++) {
        if (px(x, y) != bg) return 1;
    }
    return 0;
}

/* Layout for a 640x240 panel (30 text rows), which is what the double
 * provides. menu.c puts the separator under the panel at row 10, the pane at
 * rows 11..27 (17 rows), the status separator at row 28 and the status line
 * at row 29. */
#define PANEL_BG    0xff0a0a12u
#define PANE_BG     0xff000000u
#define SEP_FG      0xff333a52u
#define STATUS_BG   0xff0e111cu
#define PANE_TOP_Y  (11u * 8u)  /* 88  */
#define PANE_LAST_Y (27u * 8u)  /* 216 */
#define STATUS_SEP_Y (28u * 8u) /* 224 */
#define STATUS_Y    (29u * 8u)  /* 232 */

int main(void) {
    printf("menu host tests\n");

    fb_double(FB_W, FB_H);
    memset(store, 0x55, sizeof store);

    /* --- fresh canvas -------------------------------------------------- */
    printf(" fresh canvas\n");
    menu_redraw();
    check(menu_active() == 1, "menu reports active with a framebuffer");
    check(px(0, 0) == PANEL_BG, "canvas wiped to the panel background");
    check(row_has_ink(0, 6, 120, PANEL_BG), "title drawn on the top row");
    check(px(0, PANE_TOP_Y) == PANE_BG, "output pane starts blank");
    check(px(0, PANE_LAST_Y) == PANE_BG, "last pane row is inside the pane");
    check(px(0, STATUS_SEP_Y) == SEP_FG, "separator above the status line");
    check(px(0, STATUS_Y) == STATUS_BG, "status line pinned at the bottom");

    /* --- command output renders into the pane -------------------------- */
    printf(" output pane\n");
    menu_exec_begin();
    uart_mirror_hook('A');
    uart_mirror_hook('\n');
    uart_mirror_hook('B');
    menu_exec_end();
    check(row_has_ink(PANE_TOP_Y, 0, 6, PANE_BG), "'A' rendered at the pane top");
    check(row_has_ink(PANE_TOP_Y + 8u, 0, 6, PANE_BG), "'B' on the second pane row");
    check(px(0, 0) == PANEL_BG || row_has_ink(0, 6, 120, PANEL_BG),
          "panel untouched by command output");

    /* Input echo and prompts (emitted outside a command) must not mirror. */
    uart_mirror_hook('Z');
    check(px(6, PANE_TOP_Y + 16u) == PANE_BG,
          "no mirroring while no command is executing");

    /* --- scrolling stays inside the pane band -------------------------- */
    printf(" pane scrolling\n");
    menu_redraw();
    menu_exec_begin();
    uart_mirror_hook('A');                 /* lands on pane row 0 */
    for (int i = 0; i < 17; i++) uart_mirror_hook('\n');
    uart_mirror_hook('X');
    menu_exec_end();
    check(!row_has_ink(PANE_TOP_Y, 0, 6, PANE_BG), "old pane row scrolled away");
    check(row_has_ink(PANE_LAST_Y, 0, 6, PANE_BG), "'X' at the last pane row");
    check(px(0, STATUS_Y) == STATUS_BG, "scrolling never reaches the status line");
    check(row_has_ink(0, 6, 120, PANEL_BG), "panel still drawn after scrolling");

    /* --- clear recreates the whole canvas ------------------------------ */
    printf(" clear\n");
    display_fb_fill(0xff00ff00u);          /* simulate a stale, crashed screen */
    menu_redraw();
    check(px(0, 0) == PANEL_BG, "clear wipes the whole framebuffer");
    check(px(0, PANE_TOP_Y) == PANE_BG, "clear blanks the output pane");
    check(row_has_ink(0, 6, 120, PANEL_BG), "clear redraws the panel");

    /* --- no framebuffer: every entry point is a safe no-op ------------- */
    printf(" detached\n");
    fb.valid = 0;
    menu_redraw();
    check(menu_active() == 0, "menu reports off with no framebuffer");
    menu_output_putc('Q');                  /* must not crash or draw */
    menu_status_write("ignored");
    menu_exec_begin();
    uart_mirror_hook('Q');
    menu_exec_end();

    printf("menu host tests: %d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
