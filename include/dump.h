#ifndef DUMP_H
#define DUMP_H

#include <stdint.h>

/* Memory and firmware dump engine.
 *
 * The engine itself is a hex dump over a physical address range: it works on
 * anything the CPU can read, which on this payload means SRAM, SecureROM, and
 * any device window listed in memory_map.h. Everything more interesting
 * (NAND flash contents, SEP memory, key material) sits behind a driver or a
 * key that does not exist yet, so those are exposed as named targets with an
 * explicit status instead of pretend implementations.
 *
 * Every byte of output goes through uart_puts, so it lands on both the serial
 * console and whatever display mirror is bound to it.
 */

/* Target readiness. This is the distinction the menu exists to make visible:
 * a READY target can be dumped right now, an UNVERIFIED one is a published
 * guess at address/geometry, and NO_DRIVER ones wait on silicon-verified
 * register maps or keys that are not in this build. */
typedef enum {
    DUMP_READY = 0,
    DUMP_UNVERIFIED = 1,
    DUMP_NO_DRIVER = 2
} dump_status_t;

typedef struct {
    const char   *name;
    const char   *desc;
    const char   *depends;   /* what a NO_DRIVER entry waits on, else 0 */
    uint64_t      base;
    uint64_t      length;
    dump_status_t status;
} dump_target_t;

const dump_target_t *dump_targets(unsigned *count);
const dump_target_t *dump_target_find(const char *name);

/* Print the target menu: every target with its status and reason. */
void dump_targets_list(void);

typedef struct {
    uint32_t width;   /* element width in bytes: 1, 2, 4 or 8 */
    int      ascii;   /* ASCII column */
    int      sparse;  /* collapse repeated rows to "*" */
} dump_opts_t;

#define DUMP_OPTS_DEFAULT { 4, 1, 1 }

/* Hex dump [addr, addr+length). Capped; see DUMP_MAX_LENGTH. */
void dump_run(uint64_t addr, uint64_t length, const dump_opts_t *opts);

#define DUMP_MAX_LENGTH (1024ULL * 1024ULL)

/* SHA-256 over a physical range (uses the goat digest, not a new copy). */
void dump_digest(uint64_t addr, uint64_t length);

/* Search a physical range for a byte pattern. Returns the number of hits and
 * prints each address. */
int dump_find(uint64_t addr, uint64_t length, const uint8_t *pattern,
              uint32_t pattern_len);

#endif /* DUMP_H */
