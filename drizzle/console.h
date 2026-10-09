#ifndef DRIZZLE_CONSOLE_H
#define DRIZZLE_CONSOLE_H
#include <stdint.h>
void drizzle_console_write(char character);
int drizzle_console_read(void);
void drizzle_console_bind(void (*write)(char), int (*read)(void));
#endif
