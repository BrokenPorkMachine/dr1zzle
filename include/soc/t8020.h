#ifndef DR1ZZLE_SOC_T8020_H
#define DR1ZZLE_SOC_T8020_H

/*
 * T8020 (A12) SoC profile — AArch64, host tier.
 *
 * The first part in this registry that checkm8 does *not* reach. The bug the
 * vendored ipwndfu implements was fixed in the A12's SecureROM, so the ten
 * checkm8 profiles above end here and this one begins.
 *
 * It is not unreachable, though: usbliter8 (a 2025 bootrom exploit against a
 * different, lower-level USB bug) covers it, and its shellcode tree records
 * exploit-specific offsets for this CPID. That is why the exploit is a field
 * on a profile rather than a property of the registry — the host tool needs to
 * know that `goat pwn` has no path here, and says so, instead of pointing the
 * checkm8 tooling at a part it cannot touch.
 *
 * Geometry below is from iphemeral's measured t8020 platform config; only
 * fields a named source states outright are recorded, and the rest are
 * SOC_UNRECORDED rather than inherited from the A11, because this part's map
 * differs from the A11's in the places that matter (AIC and PMGR below are
 * the proof: they are not the A11's).
 */

#define SOC_T8020_NAME         "t8020"

#define SOC_T8020_CPID         0x8020u
#define SOC_T8020_CPRV         SOC_UNRECORDED
#define SOC_T8020_SCEP         SOC_UNRECORDED
#define SOC_T8020_SRTG         ""
#define SOC_T8020_ARCH         SOC_ARCH_AARCH64

/* A real exploit reaches this part, but not the one this tree drives. */
#define SOC_T8020_EXPLOIT      SOC_EXPLOIT_USBLITER8

/* No peripheral map, and an exploit that needs an RP2350 in the middle of the
 * cable, so nothing to build here either. */
#define SOC_T8020_TIER         SOC_TIER_HOST
#define SOC_T8020_MAPPED_BLOCKS \
    (SOC_BLK_ROM | SOC_BLK_UART | SOC_BLK_TIMER | SOC_BLK_AIC | SOC_BLK_PMGR)

/* ----------------------------------------------------------------------- */
/* Geometry (iphemeral config/soc/t8020.yaml, family T802x)                */
/* ----------------------------------------------------------------------- */

#define SOC_T8020_ROM_BASE            0x100000000ULL
#define SOC_T8020_ROM_SIZE            0x100000ULL
#define SOC_T8020_SECURE_ROM_BASE     0x100000000ULL
#define SOC_T8020_SECURE_ROM_SIZE     0x100000ULL

#define SOC_T8020_UART_BASE           0x20A0C0000ULL
#define SOC_T8020_TIMER_BASE          0x20E100000ULL
#define SOC_T8020_AIC_BASE            0x23B100000ULL
#define SOC_T8020_PMGR_BASE           0x20E000000ULL

/* usbliter8's t8020 shellcode places its trampoline and DMA targets in this
 * window, which is how the SRAM base is established for the part. The extent
 * of the window is not documented anywhere this tree can cite, so the size is
 * left unrecorded rather than rounded up to a round number. */
#define SOC_T8020_SRAM_BASE           0x19C000000ULL
#define SOC_T8020_SRAM_SIZE           SOC_UNRECORDED

/* ----------------------------------------------------------------------- */
/* Not recorded                                                            */
/* ----------------------------------------------------------------------- */

/* Every remaining geometry field is deliberately SOC_UNRECORDED. In
 * particular the A11's DRAM, DFU and recovery bases are NOT carried over:
 * the A12's DRAM base is not established by the corpus, and its DFU image
 * area is part of the exploit rather than a documented platform fact.
 *
 * The A12X (T8021) and A12Z (T8027) share this family, which is why those
 * profiles exist separately with their own values rather than as aliases. */
#define SOC_T8020_DRAM_BASE           SOC_UNRECORDED
#define SOC_T8020_DFU_IMAGE_BASE      SOC_UNRECORDED
#define SOC_T8020_DFU_LOAD_BASE       SOC_UNRECORDED
#define SOC_T8020_RECOVERY_IMAGE_BASE SOC_UNRECORDED
#define SOC_T8020_RECOVERY_LOAD_BASE  SOC_UNRECORDED
#define SOC_T8020_ROM_SHA1            ""
#define SOC_T8020_NONCE_LENGTH        SOC_UNRECORDED
#define SOC_T8020_SEP_NONCE_LENGTH    SOC_UNRECORDED
#define SOC_T8020_DEMOTION_REG        SOC_UNRECORDED
#define SOC_T8020_DFU_TRIGGER         SOC_UNRECORDED

#endif /* DR1ZZLE_SOC_T8020_H */
