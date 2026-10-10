#ifndef DRIZZLE_CONSOLE_H
#define DRIZZLE_CONSOLE_H
#include <stdint.h>
void drizzle_console_write(char character);
int drizzle_console_read(void);
void drizzle_console_bind(void (*write)(char), int (*read)(void));
/* Optional output mirror. Pass NULL to detach; input stays on the serial reader. */
void drizzle_console_bind_display(void (*write)(char));
#endif
