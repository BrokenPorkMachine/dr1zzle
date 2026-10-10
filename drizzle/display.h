#ifndef DRIZZLE_DISPLAY_H
#define DRIZZLE_DISPLAY_H
#include <stddef.h>
#include <stdint.h>

/* Caller owns the mapped framebuffer and font for the duration of attachment.
 * Pixels are native uint32_t words; colors must already match the pixel format.
 * font contains 128 ASCII glyphs, eight rows each, bit 7 at the left edge.
 * A NULL font selects the built-in ASCII font.
 * flush is optional for coherent memory, required otherwise. It must return
 * after making writes visible and must not call the console or rebind sinks.
 * These APIs are single-threaded and must not be called from interrupts.
 */
typedef struct {
    uint32_t *pixels;
    size_t capacity_bytes;
    size_t width, height, stride_pixels;
    const uint8_t (*font)[8];
    uint32_t foreground, background;
    void (*flush)(void *context, uint32_t *pixels, size_t bytes);
    void *context;
} drizzle_display_config_t;

/* Returns 0 on invalid configuration, retaining any previous attachment.
 * Success clears the text viewport and attaches the console output mirror.
 */
int drizzle_display_attach(const drizzle_display_config_t *config);
void drizzle_display_detach(void);
void drizzle_display_clear(void);

extern const uint8_t drizzle_display_font[128][8];

/* Optional RAM backend: 80 columns by 30 rows, native pixels 0x00RRGGBB.
 * Initialization clears and attaches this buffer. It does not start scanout.
 * The descriptor and buffer have static lifetime, including after detachment.
 */
int drizzle_display_memory_init(void);
const drizzle_display_config_t *drizzle_display_memory_config(void);
#endif
