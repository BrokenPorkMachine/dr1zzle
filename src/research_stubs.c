#include "uart.h"
#include <stdint.h>

static void unavailable(const char *name) {
    uart_puts(name);
    uart_puts(": not built into this image\n");
}

void dump_secure_rom(void) { unavailable("dump-securerom"); }
void dump_memory_range(uint64_t start, uint64_t end) { (void)start; (void)end; unavailable("dump-memory"); }
void dump_dram(void) { unavailable("dump-dram"); }
void dump_sram(void) { unavailable("dump-sram"); }
void dump_baseband(void) { unavailable("dump-baseband"); }
void dump_iboot(void) { unavailable("dump-iboot"); }
void dump_gid(void) { unavailable("dump-gid"); }
void dump_uid(void) { unavailable("dump-uid"); }
void parse_panic_log(void) { unavailable("panic"); }
