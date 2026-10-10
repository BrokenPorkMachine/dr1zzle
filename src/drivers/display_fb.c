/* Framebuffer drawing and raster console.
 *
 * Nothing here touches a device register. The framebuffer is one the
 * bootloader already configured and is scanning out; this file adopts it and
 * draws into it. That makes everything here checkable without hardware, and
 * it keeps the unverified panel-link code in display_attach.c from being
 * load-bearing for anything except discovery.
 *
 * Memory ordering: the raster engine reads this memory over the display
 * fabric, not coherently with this core. On A-series the pipeline is already
 * running, so writes are posted normally. If you turn on the MMU
 * (DR1ZZLE_ENABLE_MMU) and the framebuffer sits outside the mapped regions,
 * add an explicit cache clean over the modified rows -- see display_attach.c.
 */

#include "display.h"
#include "string.h"

static display_fb_t fb;

int display_fb_attach(uint32_t base, uint32_t width, uint32_t height,
                      uint32_t stride_bytes, uint32_t bpp) {
    if (base == 0 || width == 0 || height == 0) return -1;
    if (bpp != 16 && bpp != 32) return -1;

    /* Trust the firmware's rowBytes over width*bpp/8: these disagree whenever
     * the panel is padded to a wider pitch, which is common. */
    uint32_t min_stride = width * (bpp / 8);
    if (stride_bytes < min_stride) return -1;

    /* Reject a geometry whose buffer would wrap a 32-bit address space. */
    if (stride_bytes != 0 && height > 0xffffffffu / stride_bytes) return -1;

    fb.width = width;
    fb.height = height;
    fb.bpp = bpp;
    fb.stride = stride_bytes;
    fb.pixels = (uint32_t *)(uintptr_t)base;
    fb.valid = 1;
    return 0;
}

const display_fb_t *display_fb(void) {
    return fb.valid ? &fb : 0;
}

void display_fb_detach(void) {
    fb.valid = 0;
}

void display_fb_pixel(uint32_t x, uint32_t y, uint32_t pixel) {
    if (!fb.valid || x >= fb.width || y >= fb.height) return;
    uint8_t *row = (uint8_t *)fb.pixels + y * fb.stride;
    if (fb.bpp == 16) {
        ((uint16_t *)row)[x] = (uint16_t)pixel;
    } else {
        ((uint32_t *)row)[x] = pixel;
    }
}

void display_fb_fill(uint32_t pixel) {
    display_fb_fill_rect(0, 0, fb.width, fb.height, pixel);
}

void display_fb_fill_rect(uint32_t x, uint32_t y, uint32_t w, uint32_t h,
                          uint32_t pixel) {
    if (!fb.valid) return;

    /* Clip rather than reject: a caller asking for a rectangle that runs off
     * the edge should still get the visible part of it. */
    if (x >= fb.width || y >= fb.height) return;
    if (x + w > fb.width) w = fb.width - x;
    if (y + h > fb.height) h = fb.height - y;
    if (w == 0 || h == 0) return;

    uint8_t *row = (uint8_t *)fb.pixels + y * fb.stride;
    uint32_t row_bytes = w * (fb.bpp / 8);

    if (fb.bpp == 16) {
        uint16_t p = (uint16_t)pixel;
        for (uint32_t i = 0; i < w; i++) ((uint16_t *)row)[x + i] = p;
    } else {
        uint32_t *r = (uint32_t *)row;
        for (uint32_t i = 0; i < w; i++) r[x + i] = pixel;
    }

    /* Replicate the first row for the rest of the rectangle. */
    for (uint32_t j = 1; j < h; j++) {
        memcpy(row + j * fb.stride, row, row_bytes);
    }
}

void display_fb_stroke_rect(uint32_t x, uint32_t y, uint32_t w, uint32_t h,
                            uint32_t pixel) {
    if (!fb.valid || w == 0 || h == 0) return;
    display_fb_fill_rect(x, y, w, 1, pixel);
    display_fb_fill_rect(x, y + h - 1, w, 1, pixel);
    display_fb_fill_rect(x, y, 1, h, pixel);
    display_fb_fill_rect(x + w - 1, y, 1, h, pixel);
}

/* --- text console ------------------------------------------------------- */

static uint32_t con_fg, con_bg;
static uint32_t con_col, con_row;
static uint32_t con_cols, con_rows;

void display_console_init(uint32_t fg, uint32_t bg) {
    if (!fb.valid) return;
    con_fg = fg;
    con_bg = bg;
    con_cols = fb.width / FONT_CELL_W;
    con_rows = fb.height / FONT_CELL_H;
    con_col = con_row = 0;
    display_console_clear();
}

void display_console_clear(void) {
    if (!fb.valid || con_cols == 0) return;
    display_fb_fill(con_bg);
    con_col = con_row = 0;
}

uint32_t display_console_cursor(void) {
    return con_row * con_cols + con_col;
}

static void console_scroll(void) {
    if (con_rows == 0) return;

    /* Move every row up one cell row and repaint the last one. */
    uint32_t cell_h = FONT_CELL_H;
    uint32_t bytes = fb.stride * cell_h;
    uint8_t *base = (uint8_t *)fb.pixels;
    uint8_t *dst = base;
    uint8_t *src = base + bytes;

    for (uint32_t r = 1; r < con_rows; r++) {
        memcpy(dst, src, bytes);
        dst += bytes;
        src += bytes;
    }

    uint32_t last_y = (con_rows - 1) * cell_h;
    for (uint32_t c = 0; c < con_cols; c++) {
        display_fb_fill_rect(c * FONT_CELL_W, last_y,
                             FONT_CELL_W, cell_h, con_bg);
    }
    con_row = con_rows - 1;
}

static void console_newline(void) {
    con_col = 0;
    con_row++;
    if (con_row >= con_rows) console_scroll();
}

void display_console_putc(char c) {
    if (!fb.valid || con_cols == 0) return;

    if (c == '\n') {
        console_newline();
        return;
    }
    if (c == '\r') {
        con_col = 0;
        return;
    }
    if (c == '\b') {
        if (con_col > 0) {
            con_col--;
            display_fb_fill_rect(con_col * FONT_CELL_W, con_row * FONT_CELL_H,
                                 FONT_CELL_W, FONT_CELL_H, con_bg);
        }
        return;
    }

    /* Anything outside the printable range (including tab) is consumed as a
     * single blank cell. Tab-stop handling is not worth the state for a
     * bring-up console; expand to spaces would be the fix if it matters. */
    uint8_t code = (uint8_t)c;
    if (code < FONT_FIRST || code > FONT_LAST) code = ' ';

    uint32_t px = con_col * FONT_CELL_W;
    uint32_t py = con_row * FONT_CELL_H;
    display_fb_fill_rect(px, py, FONT_CELL_W, FONT_CELL_H, con_bg);

    const uint8_t *glyph = font8x8[code - FONT_FIRST];
    for (uint32_t y = 0; y < FONT_GLYPH_H; y++) {
        uint8_t bits = glyph[y];
        if (!bits) continue;
        for (uint32_t x = 0; x < FONT_GLYPH_W; x++) {
            if (bits & (1u << x)) {
                display_fb_pixel(px + x, py + y, con_fg);
            }
        }
    }

    if (++con_col >= con_cols) console_newline();
}

void display_console_write(const char *s) {
    while (*s) display_console_putc(*s++);
}