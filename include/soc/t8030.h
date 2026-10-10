#ifndef DR1ZZLE_SOC_T8030_H
#define DR1ZZLE_SOC_T8030_H

/*
 * T8030 (A13) SoC profile — AArch64, host tier.
 *
 * The best-attested profile in this registry after the A11, and the only one
 * with a hardware-verified exploit run: a pwndfu log records a T8030 device
 * (CPID:8030 CPRV:11 SCEP:01 BDID:06) enumerated in DFU, run usbliter8, and
 * re-enumerated with PWND:[usbliter8] in the serial string. That is evidence
 * for the addresses below, not for this tree's ability to use them — the
 * payload still cannot be built here, for the reason given under the tier.
 *
 * Geometry is from usbliter8's t8030 shellcode header, which states SRAM,
 * ROM and the ARMv8 VM constants the exploit depends on. Those constants are
 * shared with the A11 rather than assumed: the record behind them notes that
 * both the A11 and A13 compute their own TCR/SCTLR/MAIR/TTBR0 rather than
 * inheriting them, so the equality is a measurement and not a carry-over.
 *
 * Two things are deliberately *not* recorded. The ROM digest recorded for this
 * part is a SHA-256 and the registry field is a SHA-1, so the field stays empty
 * rather than being filled with a digest of a different width; and the SRTG
 * string in the run log is this device's, not the part's, because different A13
 * units run different iBoot builds.
 */

#define SOC_T8030_NAME         "t8030"

#define SOC_T8030_CPID         0x8030u

/* Read off the device's own DFU descriptor in the pwndfu run. */
#define SOC_T8030_CPRV         0x11u
#define SOC_T8030_SCEP         0x01u
#define SOC_T8030_SRTG         ""
#define SOC_T8030_ARCH         SOC_ARCH_AARCH64

#define SOC_T8030_EXPLOIT      SOC_EXPLOIT_USBLITER8

#define SOC_T8030_TIER         SOC_TIER_HOST
#define SOC_T8030_MAPPED_BLOCKS \
    (SOC_BLK_ROM | SOC_BLK_SRAM)

/* ----------------------------------------------------------------------- */
/* Geometry (usbliter8 t8030 shellcode offsets)                            */
/* ----------------------------------------------------------------------- */

#define SOC_T8030_SRAM_BASE           0x19C000000ULL
#define SOC_T8030_SRAM_SIZE           SOC_UNRECORDED

#define SOC_T8030_ROM_BASE            0x100000000ULL
#define SOC_T8030_ROM_SIZE            0x30000ULL
#define SOC_T8030_SECURE_ROM_BASE     0x100000000ULL
#define SOC_T8030_SECURE_ROM_SIZE     0x30000ULL

/* The A13's PMGR is in the 0x23b0 band like its siblings, not the 0x20e
 * band the T802x yaml defaults to. Its power-state word is at plane 8
 * +0xc00, which is a *different offset* from the A12/A12X's +0x600 -- the
 * A13 doc is explicit that copying the A12's word here would be wrong, and
 * that the neighbour at +0xc08 is not polled and is left cold. 733,007 reads
 * and exactly one write, of value 0, so this is a hardware-owned readiness
 * word the guest cannot drive. */
#define SOC_T8030_PMGR_BASE           0x23B000000ULL
#define SOC_T8030_SEP_POWER_WORD      0x23B080C00ULL

/* The exploit's own addressing, kept because the next measurement for this
 * part is an exploit measurement. These are the A13's SRAM-side scratch, the
 * relocated ROM copy the shellcode builds, and the page-table root it
 * installs -- not platform windows an image could be linked against. */
#define SOC_T8030_EXPLOIT_SRAM_NEW_SP   0x19C01E000ULL
#define SOC_T8030_EXPLOIT_ROM_NEW_PA   0x19C390000ULL
#define SOC_T8030_EXPLOIT_TTBR_BASE    0x19C388000ULL

/* ----------------------------------------------------------------------- */
/* Not recorded                                                            */
/* ----------------------------------------------------------------------- */

#define SOC_T8030_DRAM_BASE           SOC_UNRECORDED
#define SOC_T8030_DFU_IMAGE_BASE      SOC_UNRECORDED
#define SOC_T8030_DFU_LOAD_BASE       SOC_UNRECORDED
#define SOC_T8030_RECOVERY_IMAGE_BASE SOC_UNRECORDED
#define SOC_T8030_RECOVERY_LOAD_BASE  SOC_UNRECORDED
#define SOC_T8030_ROM_SHA1            ""
#define SOC_T8030_NONCE_LENGTH        SOC_UNRECORDED
#define SOC_T8030_SEP_NONCE_LENGTH    SOC_UNRECORDED
#define SOC_T8030_DEMOTION_REG        SOC_UNRECORDED
#define SOC_T8030_DFU_TRIGGER         SOC_UNRECORDED

#endif /* DR1ZZLE_SOC_T8030_H */
