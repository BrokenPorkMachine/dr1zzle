#ifndef KERNEL_PATCH_H
#define KERNEL_PATCH_H

void patch_kernel_ram(uint64_t kernel_base, const uint8_t *patches, uint32_t num_patches);
void kernel_patch_amfi(void);
void kernel_patch_code_sign(void);

#endif
