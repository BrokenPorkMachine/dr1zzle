#ifndef SHELL_H
#define SHELL_H

/* One shell, two inputs.
 *
 * The UART console and a telnet session feed bytes into the same line
 * processor and the same command table, which is what "the TCP shell is
 * identical to the UART shell" means here: there is no second implementation
 * to keep in sync. Output goes through the console, so both consoles and the
 * display mirror see it.
 */

#define SHELL_SOURCE_SERIAL 0
#define SHELL_SOURCE_NET    1

/* Runs one command line and returns. This is what the UART loop uses and
 * what the goatloader uses to run a command on behalf of a remote session:
 * one command loop, one command table, two callers. Output goes wherever
 * uart_putc() writes it, which is why the loader can capture a command's
 * output without the shell knowing a network exists. */
void shell_exec(const char *line);

/* Feed one byte of input from the given source. Executes the line on CR/LF. */
void shell_feed(int source, int c);

/* Drain the serial input queue. Call from the main loop. */
void shell_poll(void);

void shell_run(void);
void shell_print_prompt(void);
void reboot(void);

#endif /* SHELL_H */
