#include <drizzle/console.h>
#include <stdio.h>
static void (*writer)(char);
static int (*reader)(void);
static void (*display_writer)(char);
static int writing;
void drizzle_console_bind(void (*write)(char), int (*read)(void)) { writer = write; reader = read; }
void drizzle_console_bind_display(void (*write)(char)) { display_writer = write; }
void drizzle_console_write(char character) {
    /* A sink must not recursively feed its output back into the console. */
    if (writing) return;
    writing = 1;
    if (writer) writer(character);
    if (display_writer && display_writer != writer) display_writer(character);
    writing = 0;
}
int drizzle_console_read(void) { return reader ? reader() : -1; }
int putchar(int c) { drizzle_console_write((char)c); return (unsigned char)c; }
int puts(const char *s) { while (*s) putchar(*s++); putchar('\n'); return 0; }
