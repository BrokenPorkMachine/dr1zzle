#include <drizzle/console.h>
#include <stdio.h>
static void (*writer)(char);
static int (*reader)(void);
void drizzle_console_bind(void (*write)(char), int (*read)(void)) { writer = write; reader = read; }
void drizzle_console_write(char character) { if (writer) writer(character); }
int drizzle_console_read(void) { return reader ? reader() : -1; }
int putchar(int c) { drizzle_console_write((char)c); return (unsigned char)c; }
int puts(const char *s) { while (*s) putchar(*s++); putchar('\n'); return 0; }
