#include <drizzle/display.h>

enum { WIDTH = 640, HEIGHT = 240 };
static uint32_t pixels[WIDTH * HEIGHT];
static const drizzle_display_config_t memory_display = {
    .pixels = pixels,
    .capacity_bytes = sizeof pixels,
    .width = WIDTH,
    .height = HEIGHT,
    .stride_pixels = WIDTH,
    .font = drizzle_display_font,
    .foreground = 0x00eeeeee,
    .background = 0x00101010
};

int drizzle_display_memory_init(void) {
    return drizzle_display_attach(&memory_display);
}

const drizzle_display_config_t *drizzle_display_memory_config(void) {
    return &memory_display;
}
