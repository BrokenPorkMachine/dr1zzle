/* Globals published across the whole build.
 *
 * These used to live next to their first consumer (g_boot_dtb in
 * display_attach.c, g_boot_args in main.c). The multi-stage split made that
 * untenable: the core bootstrap links neither of those files, but start.S
 * still stores into g_boot_dtb and goat.c still reads it before entering a
 * firmware. One definition, linked by every image, is the only arrangement
 * that does not depend on which particular image happens to be built.
 */

#include <stdint.h>
#include <stddef.h>

/* Device tree pointer the bootloader hands over in x0; start.S publishes it
 * here before the first C call. Goat's entry path forwards it to the firmware
 * being launched. */
uint64_t g_boot_dtb;

/* Boot arguments string. Empty rather than NULL so callers can print it
 * without a check. */
char *g_boot_args = (char *)"";
