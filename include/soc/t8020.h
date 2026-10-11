#ifndef DR1ZZLE_SOC_T8020_H
#define DR1ZZLE_SOC_T8020_H

/*
 * T8020 (A12) SoC profile — AArch64, host tier.
 *
 * The first part in this registry that checkm8 does *not* reach. The bug the
 * vendored rpwn implements was fixed in the A12's SecureROM, so the ten
 * checkm8 profiles above end here and this one begins.
 *
 * It is not unreachable, though: usbliter8 (a 2025 bootrom exploit against a
 * different, lower-level USB bug) covers it, and its shellcode tree records
 * exploit-specific offsets for this CPID. That is why the exploit is a field
 * on a profile rather than a property of the registry — the host tool needs to
 * know that `goat pwn` has no path here, and says so, instead of pointing the
 * checkm8 tooling at a part it cannot touch and leaving an operator guessing at
 * the cable.
 *
 * Geometry below is from the reference project's measured t8020 platform
 * config. Only fields that project states outright are recorded, and the rest
 * are SOC_UNRECORDED rather than inherited from the A11, because this part's
 * map differs from the A11's in the places that matter (AIC and PMGR are the
 * proof: they are not the A11's).
 *
 * TIER: host, for two reasons and they are separate. There is a peripheral map
 * (recorded below, and it is this part's own), but no payload can be built:
 * the exploit that reaches it needs an RP2350 as the USB host, which this
 * tree can neither substitute for nor emulate.
 */

#define SOC_T8020_NAME         "t8020"

#define SOC_T8020_CPID         0x8020u
#define SOC_T8020_CPRV         SOC_UNRECORDED
#define SOC_T8020_SCEP         SOC_UNRECORDED
#define SOC_T8020_SRTG         ""
#define SOC_T8020_ARCH         SOC_ARCH_AARCH64

/* A real exploit reaches this part, but not the one this tree drives. */
#define SOC_T8020_EXPLOIT      SOC_EXPLOIT_USBLITER8

#define SOC_T8020_TIER         SOC_TIER_HOST
#define SOC_T8020_MAPPED_BLOCKS \
    (SOC_BLK_ROM | SOC_BLK_UART | SOC_BLK_TIMER | SOC_BLK_AIC | SOC_BLK_PMGR | \
     SOC_BLK_USB | SOC_BLK_WATCHDOG | SOC_BLK_CHIPCTL | SOC_BLK_NAND | SOC_BLK_NOR)

/* ----------------------------------------------------------------------- */
/* Memory geometry                                                          */
/* ----------------------------------------------------------------------- */

#define SOC_T8020_ROM_BASE            0x100000000ULL
#define SOC_T8020_ROM_SIZE            0x100000ULL
#define SOC_T8020_SECURE_ROM_BASE     0x100000000ULL
#define SOC_T8020_SECURE_ROM_SIZE     0x100000ULL

/* usbliter8's t8020 shellcode places its trampoline and DMA targets in this
 * window, which is how the SRAM base is established for the part. The extent
 * of the window is not documented anywhere this tree can cite, so the size is
 * left unrecorded rather than rounded to a round number. */
#define SOC_T8020_SRAM_BASE           0x19C000000ULL
#define SOC_T8020_SRAM_SIZE           SOC_UNRECORDED

/* ----------------------------------------------------------------------- */
/* Peripheral register bases (reference project's measured t8020 config)    */
/* ----------------------------------------------------------------------- */

#define SOC_T8020_UART_BASE           0x20A0C0000ULL
#define SOC_T8020_TIMER_BASE          0x20E100000ULL

/* The A12's AIC is 512 SPIs wide and in the 0x23b1 band, not the A11's
 * 0x2321 band. Its own SecureROM init sweeps 16 full MASK_SET words. */
#define SOC_T8020_AIC_BASE            0x23B100000ULL
#define SOC_T8020_AIC_SIZE            0x30000ULL

/* The PMGR is in the 0x23b0 band for this part, and its first plane is
 * 0x30000 wide — ten 16 KiB entries at 0x4000 stride — not one page.
 *
 * This is recorded as a correction rather than an edit, because the shared
 * T802x config's pmgr: 0x20e000000 is the wrong band for this part: the
 * census that follows it is explicit, "The shared pmgr_base: 0x20e000000 is
 * therefore the wrong band for this part." A platform config that is right
 * for one part and one generation can be wrong for a sibling, and copying
 * the sibling's file is how that survives review. */
#define SOC_T8020_PMGR_BASE           0x23B000000ULL
#define SOC_T8020_PMGR_FIRST_PLANE    0x30000ULL

/* The SEP power-state word: the d321ap ps-reg[5] = 0x00080600 (flags 1)
 * entry, in the PMGR band above. It is the word the A12's SecureROM polls
 * with (w & 0xf0) == 0xf0 before it will bring the SEP up, so it gates the
 * whole SEP path exactly as the equivalent entry does on the A11/A12X/A13. */
#define SOC_T8020_SEP_POWER_WORD      0x23B080600ULL

/* AppleMcc calibration, 0x23b2 band. This is one of the two calibration
 * blocks the part names; the shared second one is at 0x210e70000. */
#define SOC_T8020_MCC_BASE            0x23B288000ULL
#define SOC_T8020_MCC_SIZE            0x20000ULL

/* The shared T803x calibration block, common to the A12/A12X/A13. Neither
 * this part nor its siblings reach it through an immediate-offset access,
 * so it is absent from an inventory built from that form alone. */
#define SOC_T8020_MCC2_BASE           0x210E70000ULL
#define SOC_T8020_MCC2_SIZE           0x80000ULL

/* The display/crypto pipe and the DART-SIO window that sits inside it. The
 * size stops at +0x4000 so the synthetic DCP aperture does not claim the
 * independent hardware window the device tree places there. */
#define SOC_T8020_DCP_BASE            0x235000000ULL
#define SOC_T8020_DCP_SIZE            0x4000ULL

/* The AES engine the A12's SecureROM touches, same arm-io band as the DCP. */
#define SOC_T8020_AES_BASE            0x235008000ULL

/* The USB device controller: d321ap /arm-io/usb-complex maps to 0x239000000
 * and its usb-device child has reg base +0x100000. */
#define SOC_T8020_USB_BASE            0x239100000ULL
#define SOC_T8020_USB_SIZE            0x10000ULL

/* DART-USB, the IOMMU stream 7 the USB controller's DMA runs through. */
#define SOC_T8020_DART_USB_BASE       0x239900000ULL

/* The watchdog aperture, split so the four-word boot-event descriptor at
 * +0x8030 is its own device. Leaving it inside the Watchdog window is this
 * project's recurring silent-drop shape: the model answers an unknown offset
 * with zero and discards the write, so the ROM publishes all four words,
 * every write reports success, and the census records 6 writes, 0 reads.
 *
 * Which parts this applies to is measured, not assumed: the composition
 * count for 0x23d2b8030 in each checked-in image is 16 in the A12 and 0 in
 * the A11, and the +0x8020 word stays with the watchdog on purpose because
 * the device tree declares a four-byte watchdog register at exactly that
 * offset. */
#define SOC_T8020_WDT_BASE            0x23D2B0000ULL
#define SOC_T8020_WDT_SIZE            0xC000ULL
#define SOC_T8020_WDT_BOOT_EVENT_OFF  0x8030ULL
#define SOC_T8020_WDT_BOOT_EVENT_SIZE 0x10ULL
#define SOC_T8020_BOOT_EVENT_BASE     0x23D2B8030ULL

/* The chip-control / fuse block, which the part reads at +0x30. */
#define SOC_T8020_CHIPCTL_BASE        0x23D2BC000ULL
#define SOC_T8020_CHIPCTL_SIZE        0x4000ULL

#define SOC_T8020_NAND_BASE           0x200000000ULL
#define SOC_T8020_NAND_SIZE           0x8000000ULL

#define SOC_T8020_NOR_BASE            0x240000000ULL
#define SOC_T8020_NOR_SIZE            0x1000000ULL
#define SOC_T8020_BLOCK_BASE          0x241000000ULL
#define SOC_T8020_BLOCK_SIZE          0x400000ULL

/* The ASC mailbox aperture the reference project maps for this part and
 * drives in its paired-view tests. This is the config-carried value; the
 * d321ap /arm-io/sep reg has not been re-read in this tree, so it is
 * recorded as carried rather than measured here. */
#define SOC_T8020_MAILBOX_BASE        0x23C000000ULL

/* ----------------------------------------------------------------------- */
/* Not recorded                                                             */
/* ----------------------------------------------------------------------- */

/* The A11's SEP window is NOT carried over, and in particular this part's
 * SEP window is not 0x240000000 — that is the part's NOR base, and a first
 * draft of this header recorded it as the SEP window because the reference
 * config has no separate sep_base field. The d321ap /arm-io/sep reg is what
 * would answer it and has not been read here. */
#define SOC_T8020_SEP_BASE            SOC_UNRECORDED
#define SOC_T8020_SEP_SIZE            SOC_UNRECORDED

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