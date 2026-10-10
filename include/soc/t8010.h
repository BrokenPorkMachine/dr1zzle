#ifndef DR1ZZLE_SOC_T8010_H
#define DR1ZZLE_SOC_T8010_H

/*
 * T8010 (A10) SoC profile — AArch64, host tier.
 *
 * The second AArch64 part in the checkm8 list, and the closest cousin to the
 * A11 this tree already supports: same SRAM base, same SRAM size, same 32-bit
 * nonce, same SEP nonce length, same DFU load base. That similarity is
 * exactly why this profile exists with an explicit tier on it — the geometry
 * is genuinely known and known-different in the one place it matters most:
 *
 *   ROM size   0x20000   (A11: 0x100000)
 *   DFU image  0x1800B0000  (A11: 0x18001C000)
 *   demotion   0x2102BC000  (A11: 0x2352BC000)
 *
 * A pointer-sized assumption carried over from the A11 would read a quarter
 * of this part's ROM and place an image 0x94000 above the command area. So
 * the placement rule is per-SoC, read from here, and the payload gate below
 * is not a formality: it stops an image being built against a map it does not
 * have.
 */

#define SOC_T8010_NAME         "t8010"

#define SOC_T8010_CPID         0x8010u
#define SOC_T8010_CPRV         0x11u
#define SOC_T8010_SCEP         0x01u
#define SOC_T8010_SRTG         "iBoot-2696.0.0.1.33"
#define SOC_T8010_ARCH         SOC_ARCH_AARCH64

/* AArch64, but no peripheral map: the geometry cannot place a console. */
#define SOC_T8010_TIER         SOC_TIER_HOST
#define SOC_T8010_MAPPED_BLOCKS \
    (SOC_BLK_ROM | SOC_BLK_SRAM | SOC_BLK_DRAM)

/* ----------------------------------------------------------------------- */
/* Memory layout                                                           */
/* ----------------------------------------------------------------------- */

#define SOC_T8010_SRAM_BASE          0x180000000ULL
#define SOC_T8010_SRAM_SIZE          0x200000ULL

#define SOC_T8010_SECURE_ROM_BASE    0x100000000ULL
#define SOC_T8010_SECURE_ROM_SIZE    0x20000ULL

/* ----------------------------------------------------------------------- */
/* Exploit geometry (checkm8)                                              */
/* ----------------------------------------------------------------------- */

#define SOC_T8010_DFU_IMAGE_BASE     0x1800B0000ULL
#define SOC_T8010_DFU_LOAD_BASE      0x800000000ULL
#define SOC_T8010_ROM_BASE           0x100000000ULL
#define SOC_T8010_ROM_SIZE           0x20000ULL
#define SOC_T8010_ROM_SHA1           "41a488b3c46ff06c1a2376f3405b079fb0f15316"
#define SOC_T8010_DRAM_BASE          0x800000000ULL
#define SOC_T8010_RECOVERY_IMAGE_BASE 0x1800B0000ULL
#define SOC_T8010_RECOVERY_LOAD_BASE  0x800000000ULL
#define SOC_T8010_NONCE_LENGTH       32u
#define SOC_T8010_SEP_NONCE_LENGTH   20u
#define SOC_T8010_DEMOTION_REG       0x2102BC000ULL

#define SOC_T8010_DFU_TRIGGER        SOC_DFU_TRIGGER_BUTTONS

#define SOC_T8010_EXPLOIT  SOC_EXPLOIT_CHECKM8

#endif /* DR1ZZLE_SOC_T8010_H */
