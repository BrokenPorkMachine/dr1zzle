#ifndef SEPOS_H
#define SEPOS_H
#include <stdint.h>

int sep_send_command(uint16_t opcode, const uint8_t *data, uint32_t len);
void dump_sepos(void);
void sepos_memdump(uint64_t addr, uint32_t len);
void sepos_status(void);

#endif
