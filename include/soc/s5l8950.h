#ifndef DR1ZZLE_SOC_S5L8950_H
#define DR1ZZLE_SOC_S5L8950_H

/*
 * S5L8950 SoC profile — 32-bit (ARMv7s), host tier.
 *
 * One of the ten CPIDs checkm8 supports (ipwndfu/README.md, "current SoC
 * support"). The geometry below is the whole of what this tree has for it:
 * ipwndfu/device_platform.py. No peripheral map exists here, and the ARMv7s
 * CPU is the first reason it could not be used if it did — see the note in
 * include/soc/s5l8947.h.
 */

#define SOC_S5L8950_NAME       "s5l8950x"

#define SOC_S5L8950_CPID       0x8950u
#define SOC_S5L8950_CPRV       0x20u
#define SOC_S5L8950_SCEP       0x10u
#define SOC_S5L8950_SRTG       "iBoot-1145.3"
#define SOC_S5L8950_ARCH       SOC_ARCH_ARMV7S

/* Registry and host tooling only: no AArch64 payload, no peripheral map. */
#define SOC_S5L8950_TIER       SOC_TIER_HOST
#define SOC_S5L8950_MAPPED_BLOCKS \
    (SOC_BLK_ROM | SOC_BLK_SRAM | SOC_BLK_DRAM)

/* ----------------------------------------------------------------------- */
/* Memory layout                                                           */
/* ----------------------------------------------------------------------- */

#define SOC_S5L8950_SRAM_BASE          0x10000000ULL
#define SOC_S5L8950_SRAM_SIZE          0x80000ULL

#define SOC_S5L8950_SECURE_ROM_BASE    0x3F000000ULL
#define SOC_S5L8950_SECURE_ROM_SIZE    0x10000ULL

/* ----------------------------------------------------------------------- */
/* Exploit geometry (checkm8)                                              */
/* ----------------------------------------------------------------------- */

#define SOC_S5L8950_DFU_IMAGE_BASE     0x10000000ULL
#define SOC_S5L8950_DFU_LOAD_BASE      0xBFF00000ULL
#define SOC_S5L8950_ROM_BASE           0x3F000000ULL
#define SOC_S5L8950_ROM_SIZE           0x10000ULL
#define SOC_S5L8950_ROM_SHA1           "50a8dd9863868c971aaf95a96e5152378784e4db"
#define SOC_S5L8950_DRAM_BASE          0x80000000ULL
#define SOC_S5L8950_RECOVERY_IMAGE_BASE 0xBFF00000ULL
#define SOC_S5L8950_RECOVERY_LOAD_BASE  0x80000000ULL
#define SOC_S5L8950_NONCE_LENGTH       20u
#define SOC_S5L8950_SEP_NONCE_LENGTH   0u
#define SOC_S5L8950_DEMOTION_REG       0x3F500000ULL

/* checkm8.py configures this CPID as requiring the DFU button hold, not a
 * DFU-loop re-entry. */
#define SOC_S5L8950_DFU_TRIGGER        SOC_DFU_TRIGGER_BUTTONS

#endif /* DR1ZZLE_SOC_S5L8950_H */
