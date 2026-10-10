#ifndef DR1ZZLE_NAND_EXPORT_H
#define DR1ZZLE_NAND_EXPORT_H

#include <stdint.h>

/* Verified NAND egress.
 *
 * The driver can read pages; this adds the part a corpus needs: every page
 * and every block carries a SHA-256 that a receiver can recompute, so a long
 * transfer over a lossy link is verifiable rather than merely plausible.
 *
 * This is why the shell's `nand read` withholds raw bytes by default. That is
 * the right default for an interactive console -- dump a 4 KiB page as hex and
 * you have 8 KiB of noise -- but a corpus is exactly the case where the bytes
 * are the point, so they are emitted here with per-block and whole-transfer
 * digests wrapped around them.
 */

/* Stream the range as hex with digests. Returns 0 on success, negative on a
 * driver or transport failure. Blocks that read as bad are reported and
 * skipped, and the skip is named in the output so the receiver can tell a
 * deliberate gap from a truncated transfer. */
int nand_export_range(uint32_t first_block, uint32_t last_block);

#endif /* DR1ZZLE_NAND_EXPORT_H */
