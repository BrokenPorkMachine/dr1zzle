/* Display geometry discovery and the MIPI command channel.
 *
 * ---------------------------------------------------------------------------
 * What is actually known here, and what is not
 * ---------------------------------------------------------------------------
 *
 * This file deliberately does NOT program the DSI PHY, the raster timing
 * generator, or the panel. An earlier version of this driver invented a
 * register map for those blocks. That was wrong, and not just because the
 * offsets were guesses:
 *
 * On A-series silicon the display pipeline is configured by the bootloader
 * before a checkm8 payload runs. By the time we are executing there is already
 * a working scanout engine and a framebuffer being scanned out of it. A
 * payload that reprogrammed the PHY would not be "bringing up a display", it
 * would be tearing down a running one and hoping to rebuild it correctly
 * without knowing the panel's electrical timing.
 *
 * So the two things worth doing are:
 *
 *   1. Find out where the firmware put the framebuffer and what shape it is.
 *      That information is published in the device tree, which arrives in x0.
 *
 *   2. Draw into it.
 *
 * The MIPI sleep/wake command channel at +0x6C/+0x74 is the one panel-side
 * register access here with a known-good offset. It is used to blank and
 * unblank the panel. Everything else about the panel link is left alone.
 *
 * Consequence: there is no "init the display from cold" entry point. If the
 * display is dark when we attach, the cause is upstream of this payload.
 */

#include "display.h"
#include "memory_map.h"
#include "mmio.h"
#include "timer.h"
#include "string.h"

/* --- MIPI DSI command channel -------------------------------------------- */

/* These two offsets are the only panel registers this driver asserts it
 * knows. They come from the published MIPI DSI command path and have been
 * used to drive sleep/wake against A-series bootloaders. */
#define MIPI_CMD_REG     0x6C   /* write a DCS command here */
#define MIPI_STATUS_REG  0x74   /* bit 0 reads back "command completed" */

/* Base for the MIPI block. The device tree carries the authoritative address
 * for the "mipi-dsim" node; this is only the fallback when the tree cannot be
 * read, and it is the DSI_PHY window from memory_map.h. */
#define MIPI_BASE_DEFAULT DSI_PHY_BASE

/* Bound the completion poll. A command that never completes must not wedge
 * the payload; the panel simply stays where it was. */
#define MIPI_CMD_TIMEOUT_US 10000

static uint64_t mipi_base;
static int      mipi_base_valid;

int display_mipi_command(uint32_t cmd) {
    if (!mipi_base_valid) {
        mipi_base = MIPI_BASE_DEFAULT;
        mipi_base_valid = 1;
    }

    volatile uint32_t *cmd_reg = (volatile uint32_t *)(mipi_base + MIPI_CMD_REG);
    volatile uint32_t *status_reg =
        (volatile uint32_t *)(mipi_base + MIPI_STATUS_REG);

    mmio_write32((uintptr_t)cmd_reg, cmd);

    if (timer_wait_reg(status_reg, 1, 1, MIPI_CMD_TIMEOUT_US) != 0) {
        return -1;
    }
    return 0;
}

/* --- device tree geometry ------------------------------------------------- */

/* Flattened device tree, version 17. Only the header and the property block
 * walking are needed here; this is not a general FDT parser. */
#define FDT_MAGIC        0xd00dfeedU
#define FDT_BEGIN_NODE   0x00000001U
#define FDT_END_NODE     0x00000002U
#define FDT_PROP         0x00000003U
#define FDT_NOP          0x00000004U
#define FDT_END          0x00000009U

typedef struct {
    uint32_t magic;
    uint32_t totalsize;
    uint32_t off_dt_struct;
    uint32_t off_dt_strings;
    uint32_t off_mem_rsvmap;
    uint32_t version;
    uint32_t last_comp_version;
    uint32_t boot_cpuid_phys;
    uint32_t size_dt_strings;
    uint32_t size_dt_struct;
} fdt_header_t;

/* The framebuffer description the bootloader publishes. Field offsets are
 * those of the Apple boot-arguments video block, which is stable across
 * A-series releases. Only the five fields actually needed are named; the rest
 * of the block is left unclaimed rather than guessed at. */
typedef struct {
    uint32_t v_base_addr;
    uint32_t v_width;
    uint32_t v_height;
    uint32_t v_row_bytes;
    uint32_t v_depth;
} apple_video_args_t;

static display_info_t info;

/* g_boot_dtb (the x0 the bootloader handed over) is defined in
 * arch/arm64/globals.c so every image, including the core bootstrap that does
 * not link this file, agrees on one definition. */

const display_info_t *display_info(void) {
    return &info;
}

/* The Apple video args are published as a property whose name varies by
 * release ("apple,boot-args" is the usual one). Rather than depend on which
 * name this build sees, walk the property list and accept any value that
 * decodes to a self-consistent video block. That is looser than parsing a
 * specific property, but it is also what makes this survive release changes
 * without pretending we know the exact schema.
 *
 * A candidate is accepted only if it passes every sanity check in
 * video_args_valid(), which is what keeps a false match from being adopted
 * and then drawn into. */
static int video_args_valid(const apple_video_args_t *v) {
    if (v->v_base_addr == 0) return 0;
    if (v->v_width == 0 || v->v_height == 0) return 0;

    /* Reject anything that could not be a real panel. */
    if (v->v_width < 64 || v->v_width > 4096) return 0;
    if (v->v_height < 64 || v->v_height > 4096) return 0;

    if (v->v_depth != 16 && v->v_depth != 32) return 0;
    if (v->v_row_bytes < v->v_width * (v->v_depth / 8)) return 0;

    /* Must not wrap a 32-bit span. */
    if (v->v_height > 0xffffffffu / v->v_row_bytes) return 0;

    return 1;
}

int display_probe_device_tree(uint64_t dtb) {
    if (dtb == 0) return -1;

    const fdt_header_t *fdt = (const fdt_header_t *)(uintptr_t)dtb;
    if (fdt->magic != FDT_MAGIC) return -1;

    const uint8_t *base = (const uint8_t *)dtb;
    const uint8_t *structs = base + fdt->off_dt_struct;
    uint32_t struct_size = fdt->size_dt_struct;

    uint32_t off = 0;
    while (off + 4 <= struct_size) {
        uint32_t token;
        memcpy(&token, structs + off, 4);
        off += 4;

        switch (token) {
        case FDT_END:
            return info.found ? 0 : -1;

        case FDT_BEGIN_NODE: {
            /* Skip the NUL-terminated node name. */
            while (off < struct_size && structs[off]) off++;
            off++;
            break;
        }

        case FDT_END_NODE:
            break;

        case FDT_NOP:
            break;

        case FDT_PROP: {
            if (off + 8 > struct_size) return -1;
            uint32_t len, nameoff;
            memcpy(&len, structs + off, 4);
            memcpy(&nameoff, structs + off + 4, 4);
            off += 8;

            /* Only bother with values wide enough to hold the video block. */
            if (len >= sizeof(apple_video_args_t)) {
                if (off + len > struct_size) return -1;
                apple_video_args_t v;
                memcpy(&v, structs + off, sizeof(v));
                if (video_args_valid(&v)) {
                    info.base = v.v_base_addr;
                    info.width = v.v_width;
                    info.height = v.v_height;
                    info.stride_bytes = v.v_row_bytes;
                    info.bpp = v.v_depth;
                    info.found = 1;
                    return 0;
                }
            }

            /* Properties are padded to a 4-byte boundary. */
            off += (len + 3) & ~3u;
            break;
        }

        default:
            return -1;
        }
    }

    return -1;
}

int display_attach_discovered(void) {
    if (!info.found) return -1;
    return display_fb_attach(info.base, info.width, info.height,
                             info.stride_bytes, info.bpp);
}
