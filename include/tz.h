#ifndef TZ_H
#define TZ_H

#include <stdint.h>
#include <stdbool.h>

/* TrustZone TZ0/TZ1 register interface for A11 (T8015) */
void tz_setup(void);
void tz_lockdown(void);
bool tz_blackbird(void);
void tz0_set(uint64_t base, uint64_t end);
void *tz0_calculate_encrypted_block_addr(uint64_t offset);
bool tz0_is_locked(void);
uint64_t tz0_base(void);
uint64_t tz0_size(void);

void tz_cmd(const char *cmd, char *args);

#endif /* TZ_H */