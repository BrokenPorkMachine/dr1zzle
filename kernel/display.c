#include <drizzle/console.h>
#include <drizzle/display.h>

static drizzle_display_config_t display;
static size_t column, row, columns, rows;
static int attached;

static void flush(void) {
    if (display.flush)
        display.flush(display.context, display.pixels,
                      display.stride_pixels * display.height * sizeof(uint32_t));
}

static void erase_rows(size_t first, size_t end) {
    for (size_t y = first; y < end; y++)
        for (size_t x = 0; x < columns * 8; x++)
            display.pixels[y * display.stride_pixels + x] = display.background;
}

void drizzle_display_clear(void) {
    if (!attached) return;
    erase_rows(0, rows * 8);
    column = row = 0;
    flush();
}

static void newline(void) {
    column = 0;
    if (++row < rows) return;
    for (size_t y = 0; y < (rows - 1) * 8; y++)
        for (size_t x = 0; x < columns * 8; x++)
            display.pixels[y * display.stride_pixels + x] =
                display.pixels[(y + 8) * display.stride_pixels + x];
    row = rows - 1;
    erase_rows(row * 8, rows * 8);
}

static void glyph(unsigned char c) {
    /* Delay wrapping so a newline after a full line advances only once. */
    if (column == columns) newline();
    for (size_t y = 0; y < 8; y++)
        for (size_t x = 0; x < 8; x++)
            display.pixels[(row * 8 + y) * display.stride_pixels + column * 8 + x] =
                (display.font[c][y] & (0x80u >> x)) ?
                display.foreground : display.background;
    column++;
}

static void display_write(char character) {
    unsigned char c = (unsigned char)character;
    if (!attached) return;
    switch (c) {
    case '\r': column = 0; break;
    case '\n': newline(); break;
    case '\b': if (column) column--; break;
    case '\t': {
        if (column == columns) newline();
        size_t spaces = 8 - column % 8;
        while (spaces--) glyph(' ');
        break;
    }
    case '\f': drizzle_display_clear(); return;
    default:
        if (c < 32 || c == 127) return;
        glyph(c < 128 ? c : '?');
        break;
    }
    flush();
}

int drizzle_display_attach(const drizzle_display_config_t *config) {
    const size_t max = (size_t)-1;
    if (!config || !config->pixels ||
        (uintptr_t)config->pixels % _Alignof(uint32_t) ||
        config->width < 8 || config->height < 8 ||
        config->stride_pixels < config->width ||
        config->stride_pixels > max / sizeof(uint32_t) / config->height ||
        config->capacity_bytes < config->stride_pixels * config->height * sizeof(uint32_t))
        return 0;
    display = *config;
    if (!display.font) display.font = drizzle_display_font;
    columns = display.width / 8;
    rows = display.height / 8;
    attached = 1;
    drizzle_display_clear();
    drizzle_console_bind_display(display_write);
    return 1;
}

void drizzle_display_detach(void) {
    drizzle_console_bind_display(0);
    attached = 0;
    display = (drizzle_display_config_t){0};
}
