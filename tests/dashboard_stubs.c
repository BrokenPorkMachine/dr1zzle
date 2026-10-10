/* Host stubs for the dashboard test.
 *
 * dashboard.c renders through display_fb_* and prints through console_*.
 * Rendering is the part that needs hardware, so those calls are recorded
 * rather than drawn: the tests assert on geometry, and a stub that counted
 * draw calls is enough to prove the draw path runs without touching a
 * framebuffer.
 */

#include "display.h"
#include "console.h"

#include <stddef.h>
#include <stdint.h>

static display_fb_t fb = { 2436, 1125, 32, 2436 * 4, (uint32_t *)0x800000000, 1 };

const display_fb_t *display_fb(void) { return &fb; }

void display_fb_pixel(uint32_t x, uint32_t y, uint32_t pixel) {
    (void)x; (void)y; (void)pixel;
}
void display_fb_fill_rect(uint32_t x, uint32_t y, uint32_t w, uint32_t h,
                          uint32_t pixel) {
    (void)x; (void)y; (void)w; (void)h; (void)pixel;
}
void display_fb_stroke_rect(uint32_t x, uint32_t y, uint32_t w, uint32_t h,
                            uint32_t pixel) {
    (void)x; (void)y; (void)w; (void)h; (void)pixel;
}

/* Console sinks: collect into a buffer the test can search. */
static char out_buf[8192];
size_t out_len;

void console_puts(const char *s) {
    while (*s) console_putc(*s++);
}
void console_putc(char c) {
    if (out_len + 1 < sizeof(out_buf)) out_buf[out_len++] = c;
    out_buf[out_len] = 0;
}
void console_put_uint(uint64_t v) {
    char tmp[24];
    int n = 0;
    if (v == 0) tmp[n++] = '0';
    while (v) { tmp[n++] = (char)('0' + v % 10); v /= 10; }
    while (n--) console_putc(tmp[n]);
}
void console_put_hex(uint64_t v) { (void)v; }

const char *dashboard_test_output(void) { return out_buf; }
size_t dashboard_test_output_len(void) { return out_len; }
void dashboard_test_output_clear(void) { out_len = 0; out_buf[0] = 0; }
