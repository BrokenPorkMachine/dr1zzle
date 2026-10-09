#ifndef NAND_DUMP_H
#define NAND_DUMP_H

void dump_nand_all(void);
void dump_nand_range(uint32_t start_block, uint32_t end_block);
void extract_apfs_files(void);

#endif
