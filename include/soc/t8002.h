#ifndef DR1ZZLE_SOC_T8002_H
#define DR1ZZLE_SOC_T8002_H

/*
 * T8002 SoC profile — 32-bit (ARMv7k), host tier.
 *
 * One of the ten CPIDs checkm8 supports (rpwn/rust/README.md, "current SoC
 * support"). Geometry from rpwn/rust/src/device_platform.rs; no peripheral map, and
 * an ARMv7k CPU — see include/soc/s5l8947.h.
 *
 * This one is worth recording for a reason beyond the CSID list: it shares
 * the 4 MiB SRAM window and the 0x48800000 SRAM base with the A8 generation,
 * so it is a useful placeholder if that family is ever mapped. That is a
 * note, not a value: nothing below was inferred from it.
 */

#define SOC_T8002_NAME         "t8002"

#define SOC_T8002_CPID         0x8002u
#define SOC_T8002_CPRV         0x10u
#define SOC_T8002_SCEP         0x01u
#define SOC_T8002_SRTG         "iBoot-2651.0.0.1.31"
#define SOC_T8002_ARCH         SOC_ARCH_ARMV7K

#define SOC_T8002_TIER         SOC_TIER_HOST
#define SOC_T8002_MAPPED_BLOCKS \
    (SOC_BLK_ROM | SOC_BLK_SRAM | SOC_BLK_DRAM)

/* ----------------------------------------------------------------------- */
/* Memory layout                                                           */
/* ----------------------------------------------------------------------- */

#define SOC_T8002_SRAM_BASE          0x48800000ULL
#define SOC_T8002_SRAM_SIZE          0x120000ULL

#define SOC_T8002_SECURE_ROM_BASE    0x40000000ULL
#define SOC_T8002_SECURE_ROM_SIZE    0x100000ULL

/* ----------------------------------------------------------------------- */
/* Exploit geometry (checkm8)                                              */
/* ----------------------------------------------------------------------- */

#define SOC_T8002_DFU_IMAGE_BASE     0x48818000ULL
#define SOC_T8002_DFU_LOAD_BASE      0x80000000ULL
#define SOC_T8002_ROM_BASE           0x40000000ULL
#define SOC_T8002_ROM_SIZE           0x100000ULL
#define SOC_T8002_ROM_SHA1           "46c14a17f54ec6079260e9253e813084ab1e634b"
#define SOC_T8002_DRAM_BASE          0x80000000ULL
#define SOC_T8002_RECOVERY_IMAGE_BASE 0x48818000ULL
#define SOC_T8002_RECOVERY_LOAD_BASE  0x80000000ULL
#define SOC_T8002_NONCE_LENGTH       32u
#define SOC_T8002_SEP_NONCE_LENGTH   20u
#define SOC_T8002_DEMOTION_REG       0x481BC000ULL

#define SOC_T8002_DFU_TRIGGER        SOC_DFU_TRIGGER_LOOP

#define SOC_T8002_EXPLOIT  SOC_EXPLOIT_CHECKM8

#endif /* DR1ZZLE_SOC_T8002_H */
