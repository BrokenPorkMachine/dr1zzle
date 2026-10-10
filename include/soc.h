#ifndef DR1ZZLE_SOC_H
#define DR1ZZLE_SOC_H

/*
 * SoC profile selector — the hardware abstraction layer.
 *
 * dr1zzle was built for the A11 (T8015) because that was the silicon available
 * for reverse-engineering. Every binding that varies between SoCs — register
 * base addresses, IRQ numbers, peripheral IP blocks, NAND geometry, exploit
 * constants — is gathered into a per-SoC header under include/soc/ so a new
 * SoC can be added by writing one header and selecting it at build time,
 * rather than editing drivers.
 *
 * Selection is build-time only:
 *
 *     make SOC=t8015          # the default; A11
 *     make SOC=t8010          # A10 (registry/host tier: no peripheral map)
 *
 * There is no runtime dispatch: one binary per SoC, exactly like the existing
 * boards/ profiles. A SoC that needs genuinely different *code* (not just
 * different addresses) should be a separate driver, not a profile.
 *
 * The original registry covered the ten CPIDs checkm8 supports. It now also
 * records the newer T8020/T8021/T8027/T8030 identities, whose public USB
 * tooling and register evidence are separate from checkm8. Each profile under
 * include/soc/ defines the whole contract below, whether or not it has a
 * peripheral map: the registry, the host toolchain and the build selection all
 * read the same header, so a SoC is either fully described or explicitly
 * marked as having no register map. See docs/SOCS.md for the table and for what
 * promotes a profile between tiers.
 */

/* ----------------------------------------------------------------------- */
/* Token pasting                                                           */
/* ----------------------------------------------------------------------- */

/* DR1ZZLE_SOC_PREFIX is the namespaced prefix of the selected profile
 * (SOC_T8015), so DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _SRAM_BASE) is the
 * selected profile's SRAM base. The indirection through DR1ZZLE_CAT is what
 * makes the prefix expand before the paste; without it the leading token is
 * taken literally.
 *
 * The prefix is deliberately the *upper-case* form: the build selects a
 * profile with -DSOC_t8015, which defines the macro SOC_t8015 as 1, and a
 * macro expanded through a paste comes out as its value -- DR1ZZLE_CAT would
 * produce 1_SRAM_BASE instead of a field name. SOC_T8015 is not a macro, so
 * it pastes. */
#define DR1ZZLE_CAT_(a, b) a##b
#define DR1ZZLE_CAT(a, b) DR1ZZLE_CAT_(a, b)

/* ----------------------------------------------------------------------- */
/* Architectures a profile can target                                      */
/* ----------------------------------------------------------------------- */

/* Only AArch64 profiles can build an image here. start.S, the vector table,
 * the MMU setup and every driver in src/ are ARMv8-A; a 32-bit profile is
 * recorded for the registry and the host toolchain and cannot produce a
 * payload, whatever else it knows. */
#define SOC_ARCH_AARCH64   1
#define SOC_ARCH_ARMV7     2
#define SOC_ARCH_ARMV7S    3
#define SOC_ARCH_ARMV7K    4

/* ----------------------------------------------------------------------- */
/* Tiers                                                                   */
/* ----------------------------------------------------------------------- */

/* A profile's tier says what this tree can *do* with it, not how much is
 * known about it. A host-tier profile may know ROM, SRAM, DRAM and DFU
 * geometry in full detail and still be host tier, because a payload needs a
 * console and a console needs a register base. */
#define SOC_TIER_HOST      0   /* registry, host tooling and exploit only */
#define SOC_TIER_PAYLOAD   1   /* the peripheral map needed to link an image */

/* ----------------------------------------------------------------------- */
/* Register blocks a profile can map                                       */
/* ----------------------------------------------------------------------- */

/* One bit per block family. A profile sets SOC_<name>_MAPPED_BLOCKS to the
 * ones it has; the payload gate in the linker templates refuses a build whose
 * selected profile does not have them all. The order is stable so a test can
 * compare two registries without depending on either one's spelling. */
#define SOC_BLK_ROM        (1u << 0)
#define SOC_BLK_SRAM       (1u << 1)
#define SOC_BLK_DRAM       (1u << 2)
#define SOC_BLK_UART       (1u << 3)
#define SOC_BLK_TIMER      (1u << 4)
#define SOC_BLK_AIC        (1u << 5)
#define SOC_BLK_PMGR       (1u << 6)
#define SOC_BLK_GPIO       (1u << 7)
#define SOC_BLK_I2C        (1u << 8)
#define SOC_BLK_SPI        (1u << 9)
#define SOC_BLK_WDT        (1u << 10)
#define SOC_BLK_NAND       (1u << 11)
#define SOC_BLK_USB        (1u << 12)
#define SOC_BLK_DCP        (1u << 13)   /* display/crypto pipe: AES engine */
#define SOC_BLK_MAILBOX    (1u << 14)    /* AP-visible SEP mailbox window */
#define SOC_BLK_ACE2       (1u << 15)
#define SOC_BLK_RECFG      (1u << 16)
#define SOC_BLK_WIFI       (1u << 17)
#define SOC_BLK_DISPLAY    (1u << 18)

/* The blocks a core payload image is built out of. This list is fixed rather
 * than per-image: a payload with no UART cannot report what went wrong, so
 * there is no smaller useful image. */
#define SOC_BLK_PAYLOAD \
    (SOC_BLK_ROM | SOC_BLK_SRAM | SOC_BLK_DRAM | SOC_BLK_UART | \
     SOC_BLK_TIMER | SOC_BLK_AIC | SOC_BLK_PMGR | SOC_BLK_GPIO | \
     SOC_BLK_I2C | SOC_BLK_SPI | SOC_BLK_WDT | SOC_BLK_NAND | \
     SOC_BLK_USB | SOC_BLK_DCP)

/* ----------------------------------------------------------------------- */
/* How a part enters DFU                                                   */
/* ----------------------------------------------------------------------- */

/* From checkm8.py's device configurations. Two of the ten need a DFU-loop
 * re-entry instead of the button hold, which changes the instructions the
 * host prints and nothing else. Keeping it in the profile means the host tool
 * does not need a table of its own to get the advice right. */
#define SOC_DFU_TRIGGER_BUTTONS 0
#define SOC_DFU_TRIGGER_LOOP    1

/* ----------------------------------------------------------------------- */
/* Which public exploit reaches this part                                  */
/* ----------------------------------------------------------------------- */

/* The registry started out as "the ten SoCs checkm8 covers", which made the
 * exploit a property of the set rather than of a part. That stopped being true
 * when a second, later bootrom bug was published (usbliter8) for parts checkm8
 * never covered, so the mapping is now per-profile where it belongs.
 *
 * It is recorded here because the host tool needs it: `goat pwn` shells out to
 * the vendored checkm8 tooling, and pointing that tool at an A12 does not fail
 * in a way that explains itself. A profile that names its exploit lets the
 * host say what is true instead.
 *
 * `SOC_EXPLOIT_NONE` is a real answer, not a gap: it records that no public
 * exploit path is known to this tree for the part, which is what makes an
 * A12X refuse cleanly rather than be attempted and fail. */
#define SOC_EXPLOIT_NONE       0
#define SOC_EXPLOIT_CHECKM8    1   /* ipwndfu, over a Mac's own USB stack */
#define SOC_EXPLOIT_USBLITER8  2   /* needs an RP2350 as the USB host */

/* ----------------------------------------------------------------------- */
/* A field with no source in this tree                                     */
/* ----------------------------------------------------------------------- */

/* Not zero. Zero is a plausible-looking address, and a placement rule built on
 * a base that was never measured is exactly the failure the registry exists to
 * prevent, so "not recorded" has to be distinguishable from 0x0 at a glance. A
 * profile that leaves a field the payload needs as this value is refused by the
 * gate below rather than linked against it. */
#define SOC_UNRECORDED         (~0ULL)

/* ----------------------------------------------------------------------- */
/* Selection                                                               */
/* ----------------------------------------------------------------------- */

#if defined(SOC_t8030)
#  define DR1ZZLE_SOC_PREFIX SOC_T8030
#  define DR1ZZLE_SOC_NAME "t8030"
#  include "soc/t8030.h"
#elif defined(SOC_t8027)
#  define DR1ZZLE_SOC_PREFIX SOC_T8027
#  define DR1ZZLE_SOC_NAME "t8027"
#  include "soc/t8027.h"
#elif defined(SOC_t8021)
#  define DR1ZZLE_SOC_PREFIX SOC_T8021
#  define DR1ZZLE_SOC_NAME "t8021"
#  include "soc/t8021.h"
#elif defined(SOC_t8020)
#  define DR1ZZLE_SOC_PREFIX SOC_T8020
#  define DR1ZZLE_SOC_NAME "t8020"
#  include "soc/t8020.h"
#elif defined(SOC_t8015)
#  define DR1ZZLE_SOC_PREFIX SOC_T8015
#  define DR1ZZLE_SOC_NAME "t8015"
#  include "soc/t8015.h"
#elif defined(SOC_t8011)
#  define DR1ZZLE_SOC_PREFIX SOC_T8011
#  define DR1ZZLE_SOC_NAME "t8011"
#  include "soc/t8011.h"
#elif defined(SOC_t8010)
#  define DR1ZZLE_SOC_PREFIX SOC_T8010
#  define DR1ZZLE_SOC_NAME "t8010"
#  include "soc/t8010.h"
#elif defined(SOC_s5l8960)
#  define DR1ZZLE_SOC_PREFIX SOC_S5L8960
#  define DR1ZZLE_SOC_NAME "s5l8960"
#  include "soc/s5l8960.h"
#elif defined(SOC_t8004)
#  define DR1ZZLE_SOC_PREFIX SOC_T8004
#  define DR1ZZLE_SOC_NAME "t8004"
#  include "soc/t8004.h"
#elif defined(SOC_t8002)
#  define DR1ZZLE_SOC_PREFIX SOC_T8002
#  define DR1ZZLE_SOC_NAME "t8002"
#  include "soc/t8002.h"
#elif defined(SOC_s5l8955)
#  define DR1ZZLE_SOC_PREFIX SOC_S5L8955
#  define DR1ZZLE_SOC_NAME "s5l8955"
#  include "soc/s5l8955.h"
#elif defined(SOC_s5l8950)
#  define DR1ZZLE_SOC_PREFIX SOC_S5L8950
#  define DR1ZZLE_SOC_NAME "s5l8950"
#  include "soc/s5l8950.h"
#elif defined(SOC_s5l8947)
#  define DR1ZZLE_SOC_PREFIX SOC_S5L8947
#  define DR1ZZLE_SOC_NAME "s5l8947"
#  include "soc/s5l8947.h"
#else
   /* No profile selected. The reference profile is the default so that any
    * translation unit that includes soc.h without a build-time profile still
    * sees a complete, consistent map — the A11 one — instead of a set of
    * undefined names. The Makefile always passes a profile; this branch is
    * for the other way in. */
#  define DR1ZZLE_SOC_PREFIX SOC_T8015
#  define DR1ZZLE_SOC_NAME "t8015"
#  include "soc/t8015.h"
#endif

/* ----------------------------------------------------------------------- */
/* The selected profile, in the form build and drivers can test            */
/* ----------------------------------------------------------------------- */

#define DR1ZZLE_SOC_CPID     DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _CPID)
#define DR1ZZLE_SOC_ARCH     DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _ARCH)
#define DR1ZZLE_SOC_TIER     DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _TIER)
#define DR1ZZLE_SOC_BLOCKS   DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _MAPPED_BLOCKS)
#define DR1ZZLE_SOC_EXPLOIT  DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _EXPLOIT)
#define DR1ZZLE_SOC_TRIGGER \
    DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _DFU_TRIGGER)

/*
 * The contract every profile satisfies, spelled out once. A header that
 * misses one of these fails at the use site rather than here, so this list is
 * documentation for the reader and the entry point for a new profile — but
 * tests/test_socs.py asserts each header defines all of them.
 */

/* Geometry: what the host places an image against, and what it can read.
 * Read-only, and independent of the peripheral map below. */
#define DR1ZZLE_SOC_SRAM_BASE    DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _SRAM_BASE)
#define DR1ZZLE_SOC_SRAM_SIZE    DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _SRAM_SIZE)
#define DR1ZZLE_SOC_SECURE_ROM_BASE \
    DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _SECURE_ROM_BASE)
#define DR1ZZLE_SOC_SECURE_ROM_SIZE \
    DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _SECURE_ROM_SIZE)
#define DR1ZZLE_SOC_DRAM_BASE    DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _DRAM_BASE)

#define DR1ZZLE_SOC_DFU_IMAGE_BASE \
    DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _DFU_IMAGE_BASE)
#define DR1ZZLE_SOC_DFU_LOAD_BASE \
    DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _DFU_LOAD_BASE)
#define DR1ZZLE_SOC_RECOVERY_IMAGE_BASE \
    DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _RECOVERY_IMAGE_BASE)
#define DR1ZZLE_SOC_RECOVERY_LOAD_BASE \
    DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _RECOVERY_LOAD_BASE)

#define DR1ZZLE_SOC_ROM_BASE     DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _ROM_BASE)
#define DR1ZZLE_SOC_ROM_SIZE     DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _ROM_SIZE)
#define DR1ZZLE_SOC_ROM_SHA1     DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _ROM_SHA1)
#define DR1ZZLE_SOC_NONCE_LENGTH \
    DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _NONCE_LENGTH)
#define DR1ZZLE_SOC_SEP_NONCE_LENGTH \
    DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _SEP_NONCE_LENGTH)
#define DR1ZZLE_SOC_DEMOTION_REG \
    DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _DEMOTION_REG)

/* The placement bound the payload link is asserted against: the pwndfu
 * command area begins at the DFU image base, so everything the exploit
 * delivers has to end below it. Expressed as an offset from SRAM so a link
 * script can use it without knowing either number. */
#define DR1ZZLE_SOC_DFU_IMAGE_OFFSET \
    (DR1ZZLE_SOC_DFU_IMAGE_BASE - DR1ZZLE_SOC_SRAM_BASE)

/* ----------------------------------------------------------------------- */
/* Payload gate                                                            */
/* ----------------------------------------------------------------------- */

/* A profile with no peripheral map cannot be built into an image, and the
 * reason belongs in the message rather than in a cascade of undeclared base
 * addresses from whichever driver happened to be compiled first.
 *
 * This is deliberately a compile-time refusal and not a link-time warning: a
 * payload that touches address 0 because a base was never measured is worse
 * than one that was never built. The registry values in the profile are still
 * real and still read by the host tooling; what is missing is a register map.
 *
 * It is an assertion rather than an #error because #error does not expand
 * macros, so the profile could not name itself in the message.
 *
 * Lifting this for a profile means adding the map and setting its tier to
 * SOC_TIER_PAYLOAD -- see docs/SOCS.md. */
#if DR1ZZLE_SOC_TIER < SOC_TIER_PAYLOAD
#  define DR1ZZLE_GATE_PROSE "no peripheral register map for "
#  define DR1ZZLE_GATE_TAIL \
      " in this tree, so no image can be built for it: the ROM/SRAM/DRAM/DFU " \
      "geometry is recorded, and a payload still needs somewhere to put a " \
      "console. See docs/SOCS.md."
_Static_assert(DR1ZZLE_SOC_TIER >= SOC_TIER_PAYLOAD,
               DR1ZZLE_GATE_PROSE DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _NAME)
               DR1ZZLE_GATE_TAIL);
#endif

#endif /* DR1ZZLE_SOC_H */
