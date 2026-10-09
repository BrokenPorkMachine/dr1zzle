#include "uart.h"
#include <stdint.h>

static void unavailable(const char *name) {
    uart_puts(name);
    uart_puts(": not built into this image\n");
}

void dump_secure_rom(void) { unavailable("dump-securerom"); }
void dump_sepos(void) { unavailable("dump-sepos"); }
void dump_memory_range(uint64_t start, uint64_t end) { (void)start; (void)end; unavailable("dump-memory"); }
void dump_dram(void) { unavailable("dump-dram"); }
void dump_sram(void) { unavailable("dump-sram"); }
void dump_baseband(void) { unavailable("dump-baseband"); }
void dump_nand_range(uint32_t start, uint32_t end) { (void)start; (void)end; unavailable("dump-nand"); }
void dump_nand_all(void) { unavailable("dump-nand"); }
void extract_apfs_files(void) { unavailable("dump-apfs"); }
void dump_iboot(void) { unavailable("dump-iboot"); }
void dump_gid(void) { unavailable("dump-gid"); }
void dump_uid(void) { unavailable("dump-uid"); }
void aes_test(void) { unavailable("aes"); }
void aes_decrypt_gid(const uint8_t *ciphertext, uint8_t *plaintext, const uint8_t *iv) { (void)ciphertext; (void)plaintext; (void)iv; unavailable("aes decrypt"); }
void decrypt_keybag(const uint8_t *data, uint32_t len) { (void)data; (void)len; unavailable("keybag"); }
void ace2_init(void) { unavailable("ace2 init"); }
void ace2_dump(void) { unavailable("ace2 dump"); }
void ace2_port_reset(int port) { (void)port; unavailable("ace2 port reset"); }
void ace2_port_enable(int port) { (void)port; unavailable("ace2 port enable"); }
void ace2_dump_port_status(int port) { (void)port; unavailable("ace2 port status"); }
int sep_send_command(uint16_t opcode, const uint8_t *data, uint32_t len) { (void)opcode; (void)data; (void)len; unavailable("sepos command"); return -1; }
void sepos_memdump(uint64_t addr, uint32_t len) { (void)addr; (void)len; unavailable("sepos memdump"); }
void sepos_status(void) { unavailable("sepos status"); }
void wifi_init(void) { unavailable("wifi init"); }
void wifi_scan(void) { unavailable("wifi scan"); }
void wifi_status(void) { unavailable("wifi status"); }
void parse_panic_log(void) { unavailable("panic"); }
