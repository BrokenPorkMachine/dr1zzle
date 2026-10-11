#ifndef DR1ZZLE_SOC_S5L8960_H
#define DR1ZZLE_SOC_S5L8960_H

/*
 * S5L8960 (A7) SoC profile — AArch64, host tier.
 *
 * The first AArch64 part in the checkm8 list, and the reason the tiers exist:
 * it *could* take a dr1zzle image, because the CPU, the vectors and the MMU
 * setup are the ones this tree already speaks. It cannot take one yet, because
 * this tree has no peripheral map for it.
 *
 * What is here is the geometry, from rpwn/rust/src/device_platform.rs: ROM, SRAM,
 * DRAM, DFU placement, the demotion register and the published SecureROM
 * SHA-1. That is enough for the host side to be *correct* — `goat pwn`
 * exploits this CPID today, `goat pull securerom` reads the right window and
 * verifies against the right digest — and it is not enough to build an image,
 * because a payload must know where the console is before it can say
 * anything.
 *
 * Promoting this profile to SOC_TIER_PAYLOAD means adding the register bases
 * (UART, TIMER, AIC, PMGR, GPIO, I2C, SPI, watchdog, NAND, USB, DCP) and
 * checking each driver against this part's block differences, then flipping
 * the tier define. Until then the build refuses, loudly, instead of linking
 * an image that would write to address 0.
 */

#define SOC_S5L8960_NAME       "s5l8960x"

#define SOC_S5L8960_CPID       0x8960u
#define SOC_S5L8960_CPRV       0x11u
#define SOC_S5L8960_SCEP       0x01u
#define SOC_S5L8960_SRTG       "iBoot-1704.10"
#define SOC_S5L8960_ARCH       SOC_ARCH_AARCH64

/* AArch64, so the architecture is not the blocker — the missing peripheral
 * map is. */
#define SOC_S5L8960_TIER       SOC_TIER_HOST
#define SOC_S5L8960_MAPPED_BLOCKS \
    (SOC_BLK_ROM | SOC_BLK_SRAM | SOC_BLK_DRAM)

/* ----------------------------------------------------------------------- */
/* Memory layout                                                           */
/* ----------------------------------------------------------------------- */

/* SRAM is 0x400000 here against the A11's 0x1E8000, which is the single
 * biggest difference between the two layouts: the placement bound below is
 * derived from it, so getting it wrong silently changes how much image fits
 * before the pwndfu command area. */
#define SOC_S5L8960_SRAM_BASE          0x180000000ULL
#define SOC_S5L8960_SRAM_SIZE          0x400000ULL

#define SOC_S5L8960_SECURE_ROM_BASE    0x100000000ULL
#define SOC_S5L8960_SECURE_ROM_SIZE    0x80000ULL

/* ----------------------------------------------------------------------- */
/* Exploit geometry (checkm8)                                              */
/* ----------------------------------------------------------------------- */

/* device_platform.py notes that this part's dfu_load_base "varies". The A11
 * loads at 0x800000000, the far side of the address space; on the A7 the
 * exploit places at the SRAM base instead. A placement rule written for one
 * does not transfer, which is why this is read from the profile rather than
 * assumed. */
#define SOC_S5L8960_DFU_IMAGE_BASE     0x180380000ULL
#define SOC_S5L8960_DFU_LOAD_BASE      0x180000000ULL
#define SOC_S5L8960_ROM_BASE           0x100000000ULL
#define SOC_S5L8960_ROM_SIZE           0x80000ULL
#define SOC_S5L8960_ROM_SHA1           "2ae035c46e02ca40ae777f89a6637be694558f0a"
#define SOC_S5L8960_DRAM_BASE          0x800000000ULL
#define SOC_S5L8960_RECOVERY_IMAGE_BASE 0x83D7F7000ULL
#define SOC_S5L8960_RECOVERY_LOAD_BASE  0x800000000ULL
#define SOC_S5L8960_NONCE_LENGTH       20u
#define SOC_S5L8960_SEP_NONCE_LENGTH   20u
#define SOC_S5L8960_DEMOTION_REG       0x20E02A000ULL

#define SOC_S5L8960_DFU_TRIGGER        SOC_DFU_TRIGGER_BUTTONS

#define SOC_S5L8960_EXPLOIT  SOC_EXPLOIT_CHECKM8

#endif /* DR1ZZLE_SOC_S5L8960_H */
