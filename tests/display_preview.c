#include <drizzle/console.h>
#include <drizzle/display.h>
#include <stdio.h>

static void text(const char *s) {
    while (*s) drizzle_console_write(*s++);
}

int main(int argc, char **argv) {
    if (argc != 2 || !drizzle_display_memory_init()) return 1;
    text("dr1zzle portable framebuffer\n\n");
    text("dr1zzle> info\ntarget=memory framebuffer=640x240 console=80x30\n\n");
    text("ABCDEFGHIJKLMNOPQRSTUVWXYZ\nabcdefghijklmnopqrstuvwxyz\n0123456789\n\n");
    for (int c = 32; c < 127; c++) {
        drizzle_console_write((char)c);
        if (c == 79) drizzle_console_write('\n');
    }
    text("\n\ndr1zzle> ");
    const drizzle_display_config_t *fb = drizzle_display_memory_config();
    FILE *out = fopen(argv[1], "wb");
    if (!out) return 1;
    int failed = fprintf(out, "P6\n%zu %zu\n255\n", fb->width, fb->height) < 0;
    for (size_t y = 0; y < fb->height && !failed; y++) {
        for (size_t x = 0; x < fb->width; x++) {
            uint32_t pixel = fb->pixels[y * fb->stride_pixels + x];
            unsigned char rgb[3] = {pixel >> 16, pixel >> 8, pixel};
            if (fwrite(rgb, 1, sizeof rgb, out) != sizeof rgb) {
                failed = 1;
                break;
            }
        }
    }
    if (fclose(out)) failed = 1;
    return failed;
}
