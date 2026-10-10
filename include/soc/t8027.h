#ifndef DR1ZZLE_SOC_T8027_H
#define DR1ZZLE_SOC_T8027_H

/*
 * T8027 (A12Z) SoC profile — AArch64, host tier.
 *
 * The larger A12 sibling. This is the interesting one, and the reason the
 * exploit field is per-profile rather than per-family: its geometry IS
 * measured -- iphemeral carries a t8027 platform config, and the IORegistry
 * dump and a restore-and-boot script for it are checked in next to it -- but
 * usbliter8's own CPID switch has no case for it. Its README names A12X/Z as
 * "theoretically supported as well, but it's not implemented yet".
 *
 * So this profile records a part this tree can describe and cannot reach,
 * which is a different state from both the A12 (described and reachable) and
 * the A12X (neither). Marking it usbliter8 would have been the family-level
 * assumption the registry stopped making, and tests/test_socs.py checks the
 * claim against usbliter8's switch for exactly that reason.
 *
 * Why it is not just t8020.h with different comments: these are separate parts
 * with separate CPIDs, and a registry that models two CPIDs with one profile
 * cannot tell a device which one it found apart. The values are this part's
 * own, read from its own platform config -- which is why they agree with the
 * A12's and are still written out.
 */

#define SOC_T8027_NAME         "t8027"

#define SOC_T8027_CPID         0x8027u
#define SOC_T8027_CPRV         SOC_UNRECORDED
#define SOC_T8027_SCEP         SOC_UNRECORDED
#define SOC_T8027_SRTG         ""
#define SOC_T8027_ARCH         SOC_ARCH_AARCH64

/* The bug reaches this part's family, but no shellcode target for it exists in
 * usbliter8, so nothing can be run here yet. */
#define SOC_T8027_EXPLOIT      SOC_EXPLOIT_NONE

#define SOC_T8027_TIER         SOC_TIER_HOST
#define SOC_T8027_MAPPED_BLOCKS \
    (SOC_BLK_ROM | SOC_BLK_UART | SOC_BLK_TIMER | SOC_BLK_AIC | SOC_BLK_PMGR)

/* ----------------------------------------------------------------------- */
/* Geometry (iphemeral config/soc/t8027.yaml, family T802x)                */
/* ----------------------------------------------------------------------- */

#define SOC_T8027_ROM_BASE            0x100000000ULL
#define SOC_T8027_ROM_SIZE            0x100000ULL
#define SOC_T8027_SECURE_ROM_BASE     0x100000000ULL
#define SOC_T8027_SECURE_ROM_SIZE     0x100000ULL

#define SOC_T8027_UART_BASE           0x20A0C0000ULL
#define SOC_T8027_TIMER_BASE          0x20E100000ULL
#define SOC_T8027_AIC_BASE            0x23B100000ULL
#define SOC_T8027_PMGR_BASE           0x20E000000ULL

#define SOC_T8027_SRAM_BASE           0x19C000000ULL
#define SOC_T8027_SRAM_SIZE           SOC_UNRECORDED

/* ----------------------------------------------------------------------- */
/* Not recorded                                                            */
/* ----------------------------------------------------------------------- */

#define SOC_T8027_DRAM_BASE           SOC_UNRECORDED
#define SOC_T8027_DFU_IMAGE_BASE      SOC_UNRECORDED
#define SOC_T8027_DFU_LOAD_BASE       SOC_UNRECORDED
#define SOC_T8027_RECOVERY_IMAGE_BASE SOC_UNRECORDED
#define SOC_T8027_RECOVERY_LOAD_BASE  SOC_UNRECORDED
#define SOC_T8027_ROM_SHA1            ""
#define SOC_T8027_NONCE_LENGTH        SOC_UNRECORDED
#define SOC_T8027_SEP_NONCE_LENGTH    SOC_UNRECORDED
#define SOC_T8027_DEMOTION_REG        SOC_UNRECORDED
#define SOC_T8027_DFU_TRIGGER         SOC_UNRECORDED

#endif /* DR1ZZLE_SOC_T8027_H */
