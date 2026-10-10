#ifndef DR1ZZLE_FW_STORE_H
#define DR1ZZLE_FW_STORE_H

#include <stdint.h>

#include "firmware.h"

/* NAND-resident firmware store: the multi-stage loader's slot layer.
 *
 * A slot holds one firmware_header_t record (see include/firmware.h): the
 * header followed by the image it describes. The core reads slot headers at
 * bring-up and copies a chosen slot to its load address; the writer below lays
 * a record down. Both images link this file so the format is defined once.
 */

/* Read every slot header (one header read per slot) and remember which slots
 * hold a plausible firmware. Cheap: a slot that was never written costs a
 * single rejected header. */
void fw_store_scan(void);

/* Slots with a header that passes the magic/size/range checks. */
int fw_store_count(void);

/* The header for `slot`, or NULL when the slot is empty or out of range. */
const firmware_header_t *fw_store_slot(unsigned slot);

/* Read slot `slot` to its own load base, verify its CRC, and enter it. Returns
 * only on error. */
void fw_run_slot(unsigned slot);

/* Erase every block a slot can occupy. Returns 0 on success. */
int fw_store_erase(unsigned slot);

/* Lay a firmware record down in `slot`.
 *
 * `image`/`size` are the flat image (the same bytes `goat push` seals); they
 * are linked for `load_base` and entered at `load_base + entry_off`. The header
 * -- magic, version, geometry, size, CRC32 and `name` -- is built here, so the
 * on-NAND format and the goat container format stay one definition. The block
 * is erased first, every page is programmed, and every page is read back and
 * compared before the call reports success.
 *
 * Returns 0 on success, negative on failure: -1 bad arguments, -2 slot past the
 * end of the device, -3 bad block in the slot, -4 erase failed, -5 program
 * failed, -6 readback mismatch. The slot cache is refreshed on success. */
int fw_store_install(unsigned slot, const uint8_t *image, uint32_t size,
                     uint64_t load_base, uint32_t entry_off, const char *name);

#endif /* DR1ZZLE_FW_STORE_H */
