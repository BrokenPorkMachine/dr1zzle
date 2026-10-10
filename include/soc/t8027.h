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

/* Same correction as the T8020, and the same reason for recording it: the
 * T802x yaml's pmgr: 0x20e000000 is the wrong band for this part too. The
 * A12X measurement names the 0x23b0 band outright -- 0x23b000000, the six
 * ways it is composed, and 0x23b080600 among them -- and its first plane is
 * 0x30000, ten 16 KiB entries at 0x4000 stride, not one page. */
#define SOC_T8027_PMGR_BASE           0x23B000000ULL
#define SOC_T8027_PMGR_FIRST_PLANE    0x30000ULL

/* The A12X's SEP power-state word, the same d321ap ps-reg[5] entry (0x00080600,
 * flags 1) at the same physical address the A12 uses, independently confirmed
 * by its own ioreg dump. Same significance as the T8020's: this is the word
 * that decides whether the enclave is powered. */
#define SOC_T8027_SEP_POWER_WORD      0x23B080600ULL

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
