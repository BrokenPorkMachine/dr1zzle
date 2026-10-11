#ifndef DR1ZZLE_SOC_T8021_H
#define DR1ZZLE_SOC_T8021_H

/*
 * T8021 (A12X) SoC profile — AArch64, host tier, an identity stub.
 *
 * This profile exists because the part does, not because this tree can
 * describe it. Nobody's reference tree has a T8021 platform record: it is
 * absent from rpwn's device table, from pongoOS's per-SoC drivers, and from
 * iphemeral's SoC configs, and usbliter8's README names A12X/A12Z as
 * theoretically reachable but not implemented. So every field below is either
 * an identity fact or SOC_UNRECORDED.
 *
 * The CPID is the one thing that is carried here with no measurement behind
 * it. It is the public A12X part number, not something this tree read from a
 * device; that is the only reason it is written down at all — the alternative
 * is a device in DFU whose CPID the tool cannot name, which is the state this
 * registry is supposed to remove.
 *
 * What it buys: `goat pwn` on an A12X reports that no public exploit reaches
 * it, instead of running checkm8 and failing in a way that implicates the
 * cable. When a source establishes its geometry, the fields get filled in and
 * the comment above them goes away.
 */

#define SOC_T8021_NAME         "t8021"

#define SOC_T8021_CPID         0x8021u
#define SOC_T8021_CPRV         SOC_UNRECORDED
#define SOC_T8021_SCEP         SOC_UNRECORDED
#define SOC_T8021_SRTG         ""
#define SOC_T8021_ARCH         SOC_ARCH_AARCH64

#define SOC_T8021_EXPLOIT      SOC_EXPLOIT_NONE

#define SOC_T8021_TIER         SOC_TIER_HOST
#define SOC_T8021_MAPPED_BLOCKS (0u)

/* ----------------------------------------------------------------------- */
/* Not recorded                                                            */
/* ----------------------------------------------------------------------- */

/* Nothing below has a source in this tree. The A12's values are NOT carried
 * over as a guess, and the test suite asserts exactly that: this profile
 * records identity and nothing else, so a filled-in field means somebody
 * found a source and needs to say where. */

#define SOC_T8021_SRAM_BASE           SOC_UNRECORDED
#define SOC_T8021_SRAM_SIZE           SOC_UNRECORDED
#define SOC_T8021_ROM_BASE            SOC_UNRECORDED
#define SOC_T8021_ROM_SIZE            SOC_UNRECORDED
#define SOC_T8021_SECURE_ROM_BASE     SOC_UNRECORDED
#define SOC_T8021_SECURE_ROM_SIZE     SOC_UNRECORDED
#define SOC_T8021_DRAM_BASE           SOC_UNRECORDED
#define SOC_T8021_DFU_IMAGE_BASE      SOC_UNRECORDED
#define SOC_T8021_DFU_LOAD_BASE       SOC_UNRECORDED
#define SOC_T8021_RECOVERY_IMAGE_BASE SOC_UNRECORDED
#define SOC_T8021_RECOVERY_LOAD_BASE  SOC_UNRECORDED
#define SOC_T8021_ROM_SHA1            ""
#define SOC_T8021_NONCE_LENGTH        SOC_UNRECORDED
#define SOC_T8021_SEP_NONCE_LENGTH    SOC_UNRECORDED
#define SOC_T8021_DEMOTION_REG        SOC_UNRECORDED
#define SOC_T8021_DFU_TRIGGER         SOC_UNRECORDED

#endif /* DR1ZZLE_SOC_T8021_H */
