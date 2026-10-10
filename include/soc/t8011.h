#ifndef DR1ZZLE_SOC_T8011_H
#define DR1ZZLE_SOC_T8011_H

/*
 * T8011 (A10X) SoC profile — AArch64, host tier.
 *
 * The A10's larger sibling, and the odd one out in the A10 pair where it
 * counts: identical SRAM, DRAM, DFU placement and demotion register, but a
 * 1 MiB SecureROM window against the A10's 128 KiB, and a different iBoot
 * (and therefore a different SRTG string, which is how a device identifies
 * itself on the wire).
 *
 * That last point is the load-bearing one. SRTG is what the host matches a
 * device against, so a profile with a sibling's SRTG silently attaches to
 * nothing. Everything below is per-part, from ipwndfu/device_platform.py.
 */

#define SOC_T8011_NAME         "t8011"

#define SOC_T8011_CPID         0x8011u
#define SOC_T8011_CPRV         0x10u
#define SOC_T8011_SCEP         0x01u
#define SOC_T8011_SRTG         "iBoot-3135.0.0.2.3"
#define SOC_T8011_ARCH         SOC_ARCH_AARCH64

/* AArch64, but no peripheral map: the geometry cannot place a console. */
#define SOC_T8011_TIER         SOC_TIER_HOST
#define SOC_T8011_MAPPED_BLOCKS \
    (SOC_BLK_ROM | SOC_BLK_SRAM | SOC_BLK_DRAM)

/* ----------------------------------------------------------------------- */
/* Memory layout                                                           */
/* ----------------------------------------------------------------------- */

#define SOC_T8011_SRAM_BASE          0x180000000ULL
#define SOC_T8011_SRAM_SIZE          0x200000ULL

#define SOC_T8011_SECURE_ROM_BASE    0x100000000ULL
#define SOC_T8011_SECURE_ROM_SIZE    0x100000ULL

/* ----------------------------------------------------------------------- */
/* Exploit geometry (checkm8)                                              */
/* ----------------------------------------------------------------------- */

#define SOC_T8011_DFU_IMAGE_BASE     0x1800B0000ULL
#define SOC_T8011_DFU_LOAD_BASE      0x800000000ULL
#define SOC_T8011_ROM_BASE           0x100000000ULL
#define SOC_T8011_ROM_SIZE           0x100000ULL
#define SOC_T8011_ROM_SHA1           "2fae20a11860b0e3ce1d8a6df7d3961f610ab70d"
#define SOC_T8011_DRAM_BASE          0x800000000ULL
#define SOC_T8011_RECOVERY_IMAGE_BASE 0x1800B0000ULL
#define SOC_T8011_RECOVERY_LOAD_BASE  0x800000000ULL
#define SOC_T8011_NONCE_LENGTH       32u
#define SOC_T8011_SEP_NONCE_LENGTH   20u
#define SOC_T8011_DEMOTION_REG       0x2102BC000ULL

#define SOC_T8011_DFU_TRIGGER        SOC_DFU_TRIGGER_BUTTONS

#endif /* DR1ZZLE_SOC_T8011_H */
