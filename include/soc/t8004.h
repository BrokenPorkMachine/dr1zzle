#ifndef DR1ZZLE_SOC_T8004_H
#define DR1ZZLE_SOC_T8004_H

/*
 * T8004 SoC profile — 32-bit (ARMv7k), host tier.
 *
 * The last of the ten CPIDs checkm8 supports (ipwndfu/README.md, "current SoC
 * support"). Geometry from ipwndfu/device_platform.py; no peripheral map, and
 * an ARMv7k CPU — see include/soc/s5l8947.h.
 *
 * Two things about this part are worth knowing before anyone writes a profile
 * for it: its SecureROM window is 128 KiB (0x20000, against the 1 MiB the
 * other t8 parts report), and its SRAM is the largest in the 32-bit set at
 * 0x140000. Both are in the geometry below rather than derived from a
 * sibling, which is the habit this registry is trying to keep.
 */

#define SOC_T8004_NAME         "t8004"

#define SOC_T8004_CPID         0x8004u
#define SOC_T8004_CPRV         0x10u
#define SOC_T8004_SCEP         0x01u
#define SOC_T8004_SRTG         "iBoot-2651.0.0.3.3"
#define SOC_T8004_ARCH         SOC_ARCH_ARMV7K

#define SOC_T8004_TIER         SOC_TIER_HOST
#define SOC_T8004_MAPPED_BLOCKS \
    (SOC_BLK_ROM | SOC_BLK_SRAM | SOC_BLK_DRAM)

/* ----------------------------------------------------------------------- */
/* Memory layout                                                           */
/* ----------------------------------------------------------------------- */

#define SOC_T8004_SRAM_BASE          0x48800000ULL
#define SOC_T8004_SRAM_SIZE          0x140000ULL

#define SOC_T8004_SECURE_ROM_BASE    0x40000000ULL
#define SOC_T8004_SECURE_ROM_SIZE    0x20000ULL

/* ----------------------------------------------------------------------- */
/* Exploit geometry (checkm8)                                              */
/* ----------------------------------------------------------------------- */

#define SOC_T8004_DFU_IMAGE_BASE     0x48818000ULL
#define SOC_T8004_DFU_LOAD_BASE      0x80000000ULL
#define SOC_T8004_ROM_BASE           0x40000000ULL
#define SOC_T8004_ROM_SIZE           0x20000ULL
#define SOC_T8004_ROM_SHA1           "8afdcd6c147ac63fddadd1b92536d1f80c0b8a21"
#define SOC_T8004_DRAM_BASE          0x80000000ULL
#define SOC_T8004_RECOVERY_IMAGE_BASE 0x48818000ULL
#define SOC_T8004_RECOVERY_LOAD_BASE  0x80000000ULL
#define SOC_T8004_NONCE_LENGTH       32u
#define SOC_T8004_SEP_NONCE_LENGTH   20u
#define SOC_T8004_DEMOTION_REG       0x481BC000ULL

#define SOC_T8004_DFU_TRIGGER        SOC_DFU_TRIGGER_BUTTONS

#define SOC_T8004_EXPLOIT  SOC_EXPLOIT_CHECKM8

#endif /* DR1ZZLE_SOC_T8004_H */
