#ifndef MEMORY_DUMP_H
#define MEMORY_DUMP_H

void dump_memory_range(uint64_t start, uint64_t end);
void dump_dram(void);
void dump_sram(void);
void dump_baseband(void);
void dump_iboot(void);
void dump_gid(void);
void dump_uid(void);

#endif
