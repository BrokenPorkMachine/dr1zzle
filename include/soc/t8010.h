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
 *
 * TIER: host. ipwndfu/device_platform.py gives the geometry and identity
 * above, and iphem-soc records two A10-specific memory measurements below.
 * There is no A10 peripheral register map in this tree: the reference
 * project's SoC configs cover T8015/T8020/T8027/T8030/T8101/S8000/A7/A8 and
 * have no T8010 entry at all, so nothing here supplies a peripheral band.
 *
 * A first draft of this header carried one anyway, by copying the A11's
 * 0x20A0xxxxx/0x20E1xxxxx band onto the A10. That was the copy-across error
 * this registry exists to prevent and it is withdrawn: every peripheral base
 * below is SOC_UNRECORDED, and the block that was fabricated has been
 * replaced by the two addresses that are actually this part's.
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
/* Memory layout — from ipwndfu/device_platform.py                        */
/* ----------------------------------------------------------------------- */

#define SOC_T8010_SRAM_BASE          0x180000000ULL
#define SOC_T8010_SRAM_SIZE          0x200000ULL

#define SOC_T8010_SECURE_ROM_BASE    0x100000000ULL
#define SOC_T8010_SECURE_ROM_SIZE    0x20000ULL

#define SOC_T8010_DRAM_BASE          0x800000000ULL

/* ----------------------------------------------------------------------- */
/* A10-specific memory measurements (iphem-soc, T8010_* constants)         */
/* ----------------------------------------------------------------------- */

/* The A10's second zero-fill span, disjoint from the SRAM window above and
 * therefore mapped separately rather than by widening that one. Measured
 * from SecureROM_t8010si_iBoot-2696.0.0.1.33: the base is the u64 at file
 * offset 0x378 and the length is a `movz x11, #0x4000` immediate at file
 * offset 0x120 — which is why the size cannot be read out of the data block
 * the way the first span's can. */
#define SOC_T8010_FAR_ZERO_BASE      0x1801B0000ULL
#define SOC_T8010_FAR_ZERO_SIZE      0x4000ULL

/* The A10's DRAM window as its ROM actually uses it. The image carries
 * 0x200000000 as a bare 64-bit literal sixteen times, and the run stores at
 * 0x202f8000 / 0x202f20020 / 0x202f22020 / 0x202f80000 and reads
 * 0x202f20020 back unchanged. A NAND controller answers none of those, so
 * this is RAM. Note this is in addition to the device_platform DRAM base
 * above; the two are different windows for different purposes. */
#define SOC_T8010_DRAM_WORK_BASE     0x200000000ULL

/* ----------------------------------------------------------------------- */
/* Exploit geometry — from ipwndfu/device_platform.py                     */
/* ----------------------------------------------------------------------- */

#define SOC_T8010_DFU_IMAGE_BASE     0x1800B0000ULL
#define SOC_T8010_DFU_LOAD_BASE      0x800000000ULL
#define SOC_T8010_ROM_BASE           0x100000000ULL
#define SOC_T8010_ROM_SIZE           0x20000ULL
#define SOC_T8010_ROM_SHA1           "41a488b3c46ff06c1a2376f3405b079fb0f15316"
#define SOC_T8010_RECOVERY_IMAGE_BASE 0x1800B0000ULL
#define SOC_T8010_RECOVERY_LOAD_BASE  0x800000000ULL
#define SOC_T8010_NONCE_LENGTH       32u
#define SOC_T8010_SEP_NONCE_LENGTH   20u
#define SOC_T8010_DEMOTION_REG       0x2102BC000ULL
#define SOC_T8010_DFU_TRIGGER        SOC_DFU_TRIGGER_BUTTONS

#define SOC_T8010_EXPLOIT  SOC_EXPLOIT_CHECKM8

/* ----------------------------------------------------------------------- */
/* No peripheral map                                                        */
/* ----------------------------------------------------------------------- */

/* Every register base is SOC_UNRECORDED, not 0 and not a sibling's value.
 * A host-tier profile that leaves a field the payload needs as this value is
 * refused by the payload gate rather than linked against it. The names are
 * defined so the registry contract in include/soc.h stays complete. */

#define SOC_T8010_UART_BASE          SOC_UNRECORDED
#define SOC_T8010_TIMER_BASE         SOC_UNRECORDED
#define SOC_T8010_AIC_BASE           SOC_UNRECORDED
#define SOC_T8010_PMGR_BASE          SOC_UNRECORDED
#define SOC_T8010_GPIO_BASE          SOC_UNRECORDED
#define SOC_T8010_I2C_BASE           SOC_UNRECORDED
#define SOC_T8010_SPI_BASE           SOC_UNRECORDED
#define SOC_T8010_USB_BASE           SOC_UNRECORDED
#define SOC_T8010_NAND_BASE          SOC_UNRECORDED
#define SOC_T8010_NOR_BASE           SOC_UNRECORDED
#define SOC_T8010_WATCHDOG_BASE      SOC_UNRECORDED
#define SOC_T8010_DCP_BASE           SOC_UNRECORDED
#define SOC_T8010_MAILBOX_BASE       SOC_UNRECORDED
#define SOC_T8010_SEP_BASE           SOC_UNRECORDED
#define SOC_T8010_SEP_SIZE           SOC_UNRECORDED
#define SOC_T8010_SEP_POWER_WORD     SOC_UNRECORDED
#define SOC_T8010_ACE2_BASE          SOC_UNRECORDED
#define SOC_T8010_ACE2_SIZE          SOC_UNRECORDED
#define SOC_T8010_BLOCK_BASE         SOC_UNRECORDED
#define SOC_T8010_PMU_BASE           SOC_UNRECORDED
#define SOC_T8010_SPMI_BASE          SOC_UNRECORDED
#define SOC_T8010_THERMAL_BASE       SOC_UNRECORDED

#endif /* DR1ZZLE_SOC_T8010_H */