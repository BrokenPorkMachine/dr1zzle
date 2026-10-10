#ifndef DR1ZZLE_SOC_S5L8947_H
#define DR1ZZLE_SOC_S5L8947_H

/*
 * S5L8947 SoC profile — 32-bit (ARMv7), host tier.
 *
 * This is one of the ten CPIDs checkm8 supports (ipwndfu/README.md, "current
 * SoC support"). Everything below the geometry block comes from
 * ipwndfu/device_platform.py, which is this tree's one vetted source for
 * platform geometry; nothing here was measured or inferred.
 *
 * There is no peripheral map. Two independent reasons, and both are fatal on
 * their own:
 *
 *   1. The CPU is ARMv7, not ARMv8-A. start.S, the vectors, the MMU setup and
 *      every driver in src/ are AArch64, so an image built for this part could
 *      not run even with a perfect register map.
 *   2. This tree has never mapped this part's peripherals.
 *
 * What this profile *is* for: the registry, the host toolchain and the build
 * system all key off it. `goat pwn` and the vendored exploit support this CPID
 * today; `goat pull` uses the geometry below; and the corpus manifest records
 * where each address came from.
 */

#define SOC_S5L8947_NAME       "s5l8947x"

#define SOC_S5L8947_CPID       0x8947u
#define SOC_S5L8947_CPRV       0x00u
#define SOC_S5L8947_SCEP       0x10u
#define SOC_S5L8947_SRTG       "iBoot-1458.2"
#define SOC_S5L8947_ARCH       SOC_ARCH_ARMV7

/* Registry and host tooling only: no AArch64 payload, no peripheral map. */
#define SOC_S5L8947_TIER       SOC_TIER_HOST
#define SOC_S5L8947_MAPPED_BLOCKS \
    (SOC_BLK_ROM | SOC_BLK_SRAM | SOC_BLK_DRAM)

/* ----------------------------------------------------------------------- */
/* Memory layout                                                           */
/* ----------------------------------------------------------------------- */

#define SOC_S5L8947_SRAM_BASE          0x34000000ULL
#define SOC_S5L8947_SRAM_SIZE          0x40000ULL

/* The SecureROM window, from device_platform.py. Note the A11 value has a
 * different base entirely: pre-A7 parts map ROM at 0x3F000000, and the
 * 64 KiB size is not a typo. */
#define SOC_S5L8947_SECURE_ROM_BASE    0x3F000000ULL
#define SOC_S5L8947_SECURE_ROM_SIZE    0x10000ULL

/* ----------------------------------------------------------------------- */
/* Exploit geometry (checkm8)                                              */
/* ----------------------------------------------------------------------- */

#define SOC_S5L8947_DFU_IMAGE_BASE     0x34000000ULL
#define SOC_S5L8947_DFU_LOAD_BASE      0x9FF00000ULL
#define SOC_S5L8947_ROM_BASE           0x3F000000ULL
#define SOC_S5L8947_ROM_SIZE           0x10000ULL
#define SOC_S5L8947_ROM_SHA1           "d9320ddd4bdb1de79ae0601f20e7db23441ab1a7"
#define SOC_S5L8947_DRAM_BASE          0x80000000ULL
#define SOC_S5L8947_RECOVERY_IMAGE_BASE 0x9FF00000ULL
#define SOC_S5L8947_RECOVERY_LOAD_BASE  0x80000000ULL
#define SOC_S5L8947_NONCE_LENGTH       20u
#define SOC_S5L8947_SEP_NONCE_LENGTH   0u
#define SOC_S5L8947_DEMOTION_REG       0x3F500000ULL

#define SOC_S5L8947_DFU_TRIGGER        SOC_DFU_TRIGGER_LOOP

#define SOC_S5L8947_EXPLOIT  SOC_EXPLOIT_CHECKM8

#endif /* DR1ZZLE_SOC_S5L8947_H */
