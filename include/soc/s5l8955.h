#ifndef DR1ZZLE_SOC_S5L8955_H
#define DR1ZZLE_SOC_S5L8955_H

/*
 * S5L8955 SoC profile — 32-bit (ARMv7s), host tier.
 *
 * One of the ten CPIDs checkm8 supports (ipwndfu/README.md, "current SoC
 * support"). Geometry from ipwndfu/device_platform.py; no peripheral map, and
 * an ARMv7s CPU — see include/soc/s5l8947.h for why neither on its own is
 * survivable.
 */

#define SOC_S5L8955_NAME       "s5l8955x"

#define SOC_S5L8955_CPID       0x8955u
#define SOC_S5L8955_CPRV       0x20u
#define SOC_S5L8955_SCEP       0x10u
#define SOC_S5L8955_SRTG       "iBoot-1145.3.3"
#define SOC_S5L8955_ARCH       SOC_ARCH_ARMV7S

/* Registry and host tooling only: no AArch64 payload, no peripheral map. */
#define SOC_S5L8955_TIER       SOC_TIER_HOST
#define SOC_S5L8955_MAPPED_BLOCKS \
    (SOC_BLK_ROM | SOC_BLK_SRAM | SOC_BLK_DRAM)

/* ----------------------------------------------------------------------- */
/* Memory layout                                                           */
/* ----------------------------------------------------------------------- */

#define SOC_S5L8955_SRAM_BASE          0x10000000ULL
#define SOC_S5L8955_SRAM_SIZE          0x80000ULL

#define SOC_S5L8955_SECURE_ROM_BASE    0x3F000000ULL
#define SOC_S5L8955_SECURE_ROM_SIZE    0x10000ULL

/* ----------------------------------------------------------------------- */
/* Exploit geometry (checkm8)                                              */
/* ----------------------------------------------------------------------- */

#define SOC_S5L8955_DFU_IMAGE_BASE     0x10000000ULL
#define SOC_S5L8955_DFU_LOAD_BASE      0xBFF00000ULL
#define SOC_S5L8955_ROM_BASE           0x3F000000ULL
#define SOC_S5L8955_ROM_SIZE           0x10000ULL
#define SOC_S5L8955_ROM_SHA1           "3af575cc84e54f951db2a83227737664abdc8f40"
#define SOC_S5L8955_DRAM_BASE          0x80000000ULL
#define SOC_S5L8955_RECOVERY_IMAGE_BASE 0xBFF00000ULL
#define SOC_S5L8955_RECOVERY_LOAD_BASE  0x80000000ULL
#define SOC_S5L8955_NONCE_LENGTH       20u
#define SOC_S5L8955_SEP_NONCE_LENGTH   0u
#define SOC_S5L8955_DEMOTION_REG       0x3F500000ULL

#define SOC_S5L8955_DFU_TRIGGER        SOC_DFU_TRIGGER_BUTTONS

#endif /* DR1ZZLE_SOC_S5L8955_H */
