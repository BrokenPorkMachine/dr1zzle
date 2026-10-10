#include <drizzle/console.h>
#include <drizzle/display.h>
#include <stdio.h>

#define CHECK(condition) do { if (!(condition)) return __LINE__; } while (0)
static char serial[256], mirrored[256];
static size_t serial_count, mirror_count, flush_count;
static uint32_t storage[18 * 16 + 2];
static const uint8_t font[128][8] = {
    ['A'] = {0x80, 0x40, 0x20, 0x10, 8, 4, 2, 1},
    ['B'] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
    ['?'] = {0xff}
};
static void serial_write(char c) { serial[serial_count++] = c; }
static void mirror_write(char c) { mirrored[mirror_count++] = c; }
static int serial_read(void) { return 'z'; }
static void recursive_write(char c) { mirror_write(c); drizzle_console_write(c); }
static void flush(void *context, uint32_t *pixels, size_t bytes) {
    if (context == storage && pixels == storage + 1 && bytes == 18 * 16 * 4)
        flush_count++;
}
static void text(const char *s) { while (*s) drizzle_console_write(*s++); }

int main(void) {
    CHECK(drizzle_console_read() == -1);
    drizzle_console_bind(serial_write, serial_read);
    drizzle_console_bind_display(mirror_write);
    puts("prompt>");
    CHECK(serial_count == 8 && mirror_count == 8);
    for (size_t i = 0; i < serial_count; i++) CHECK(serial[i] == mirrored[i]);
    CHECK(drizzle_console_read() == 'z');
    drizzle_console_bind_display(0);
    putchar('x');
    CHECK(serial_count == 9 && mirror_count == 8);
    drizzle_console_bind_display(serial_write);
    putchar('y');
    CHECK(serial_count == 10);
    drizzle_console_bind_display(recursive_write);
    putchar('r');
    CHECK(serial_count == 11 && mirror_count == 9);

    for (size_t i = 0; i < sizeof storage / sizeof storage[0]; i++) storage[i] = 0xdeadbeef;
    drizzle_display_config_t config = {
        .pixels = storage + 1, .capacity_bytes = 18 * 16 * 4,
        .width = 16, .height = 16, .stride_pixels = 18, .font = font,
        .foreground = 0xffffff, .background = 0,
        .flush = flush, .context = storage
    };
    CHECK(drizzle_display_attach(&config));
    CHECK(flush_count == 1);
    putchar('A');
    CHECK(storage[1] == 0xffffff && storage[2] == 0);
    CHECK(storage[1 + 7 * 18 + 7] == 0xffffff);
    text("B\nA");
    CHECK(storage[1 + 8] == 0xffffff);
    CHECK(storage[1 + 8 * 18] == 0xffffff);
    text("\rB\n");
    CHECK(storage[1 + 7] == 0xffffff);
    CHECK(storage[1 + 8 * 18] == 0);
    text("B\b \b");
    CHECK(storage[1 + 8 * 18] == 0);
    text("\fA");
    CHECK(storage[1] == 0xffffff && storage[1 + 8 * 18] == 0);
    text("\r\t");
    CHECK(storage[1] == 0);
    text("\f\xff");
    CHECK(storage[1] == 0xffffff && storage[1 + 18] == 0);
    for (size_t y = 0; y < 16; y++) {
        CHECK(storage[1 + y * 18 + 16] == 0xdeadbeef);
        CHECK(storage[1 + y * 18 + 17] == 0xdeadbeef);
    }
    CHECK(storage[0] == 0xdeadbeef && storage[18 * 16 + 1] == 0xdeadbeef);
    CHECK(!drizzle_display_attach(0));
    config.capacity_bytes--;
    CHECK(!drizzle_display_attach(&config));
    config.capacity_bytes++;
    config.stride_pixels = (size_t)-1;
    CHECK(!drizzle_display_attach(&config));
    config.stride_pixels = 18;
    config.height = 0;
    CHECK(!drizzle_display_attach(&config));
    text("\fB"); /* Invalid replacement retained the working attachment. */
    CHECK(storage[1 + 7 * 18 + 7] == 0xffffff);
    size_t flushed = flush_count;
    drizzle_display_detach();
    putchar('A');
    CHECK(flush_count == flushed && drizzle_console_read() == 'z');
    drizzle_console_bind(0, 0);
    drizzle_console_bind_display(mirror_write);
    size_t count = mirror_count;
    putchar('d');
    CHECK(mirror_count == count + 1);
    drizzle_console_bind_display(0);
    config.height = 16;
    config.font = 0;
    CHECK(drizzle_display_attach(&config));
    putchar('A');
    CHECK(storage[1] == 0 && storage[3] == 0xffffff);
    drizzle_display_detach();

    for (unsigned c = 33; c < 127; c++) {
        unsigned ink = 0;
        for (unsigned y = 0; y < 8; y++) ink |= drizzle_display_font[c][y];
        CHECK(ink != 0);
    }
    CHECK(drizzle_display_memory_init());
    const drizzle_display_config_t *memory = drizzle_display_memory_config();
    CHECK(memory->width == 640 && memory->height == 240);
    CHECK(memory->capacity_bytes == 614400 && memory->font == drizzle_display_font);
    putchar('A');
    CHECK(memory->pixels[2] == memory->foreground);
    CHECK(memory->pixels[0] == memory->background);
    for (unsigned i = 0; i < 30; i++) putchar('\n');
    CHECK(memory->pixels[2] == memory->background);
    putchar('A');
    CHECK(memory->pixels[232 * 640 + 2] == memory->foreground);
    drizzle_display_detach();
    putchar('\f');
    CHECK(memory->pixels[232 * 640 + 2] == memory->foreground);
    CHECK(drizzle_display_memory_init());
    CHECK(memory->pixels[232 * 640 + 2] == memory->background);
    drizzle_display_detach();
    return 0;
}
