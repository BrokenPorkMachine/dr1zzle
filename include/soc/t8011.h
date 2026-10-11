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
 * nothing. Everything below is per-part, from rpwn/rust/src/device_platform.rs.
 *
 * TIER: host, and for the same reason as the A10 — no peripheral register
 * map for this part exists in this tree, and it is not derived from the A10's
 * (there is no A10 map to derive from) nor from the A11's. A first draft of
 * this header copied the A11's 0x20A0xxxxx / 0x20E1xxxxx peripheral band
 * here; that copy is withdrawn and every peripheral base is SOC_UNRECORDED.
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
/* Memory layout — from rpwn/rust/src/device_platform.rs                        */
/* ----------------------------------------------------------------------- */

#define SOC_T8011_SRAM_BASE          0x180000000ULL
#define SOC_T8011_SRAM_SIZE          0x200000ULL

#define SOC_T8011_SECURE_ROM_BASE    0x100000000ULL
#define SOC_T8011_SECURE_ROM_SIZE    0x100000ULL   /* A10: 0x20000 */

#define SOC_T8011_DRAM_BASE          0x800000000ULL

/* ----------------------------------------------------------------------- */
/* Exploit geometry — from rpwn/rust/src/device_platform.rs                     */
/* ----------------------------------------------------------------------- */

#define SOC_T8011_DFU_IMAGE_BASE     0x1800B0000ULL
#define SOC_T8011_DFU_LOAD_BASE      0x800000000ULL
#define SOC_T8011_ROM_BASE           0x100000000ULL
#define SOC_T8011_ROM_SIZE           0x100000ULL
#define SOC_T8011_ROM_SHA1           "2fae20a11860b0e3ce1d8a6df7d3961f610ab70d"
#define SOC_T8011_RECOVERY_IMAGE_BASE 0x1800B0000ULL
#define SOC_T8011_RECOVERY_LOAD_BASE  0x800000000ULL
#define SOC_T8011_NONCE_LENGTH       32u
#define SOC_T8011_SEP_NONCE_LENGTH   20u
#define SOC_T8011_DEMOTION_REG       0x2102BC000ULL
#define SOC_T8011_DFU_TRIGGER        SOC_DFU_TRIGGER_BUTTONS

#define SOC_T8011_EXPLOIT  SOC_EXPLOIT_CHECKM8

/* ----------------------------------------------------------------------- */
/* No peripheral map                                                        */
/* ----------------------------------------------------------------------- */

/* The A10X's SEP power word, DRAM work window and zero-fill spans are not
 * recorded. device_platform.py gives no peripheral band for this part and
 * the reference project carries no T8011 config, so nothing here supplies
 * one. Sharing the A10's would also be wrong on its own terms: the A10X is a
 * separate CPID and the pair already differ in ROM size and SRTG. */

#define SOC_T8011_UART_BASE          SOC_UNRECORDED
#define SOC_T8011_TIMER_BASE         SOC_UNRECORDED
#define SOC_T8011_AIC_BASE           SOC_UNRECORDED
#define SOC_T8011_PMGR_BASE          SOC_UNRECORDED
#define SOC_T8011_GPIO_BASE          SOC_UNRECORDED
#define SOC_T8011_I2C_BASE           SOC_UNRECORDED
#define SOC_T8011_SPI_BASE           SOC_UNRECORDED
#define SOC_T8011_USB_BASE           SOC_UNRECORDED
#define SOC_T8011_NAND_BASE          SOC_UNRECORDED
#define SOC_T8011_NOR_BASE           SOC_UNRECORDED
#define SOC_T8011_WATCHDOG_BASE      SOC_UNRECORDED
#define SOC_T8011_DCP_BASE           SOC_UNRECORDED
#define SOC_T8011_MAILBOX_BASE       SOC_UNRECORDED
#define SOC_T8011_SEP_BASE           SOC_UNRECORDED
#define SOC_T8011_SEP_SIZE           SOC_UNRECORDED
#define SOC_T8011_SEP_POWER_WORD     SOC_UNRECORDED
#define SOC_T8011_ACE2_BASE          SOC_UNRECORDED
#define SOC_T8011_ACE2_SIZE          SOC_UNRECORDED
#define SOC_T8011_BLOCK_BASE         SOC_UNRECORDED
#define SOC_T8011_PMU_BASE           SOC_UNRECORDED
#define SOC_T8011_SPMI_BASE          SOC_UNRECORDED
#define SOC_T8011_THERMAL_BASE       SOC_UNRECORDED

#endif /* DR1ZZLE_SOC_T8011_H */