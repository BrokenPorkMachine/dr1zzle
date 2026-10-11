#ifndef DR1ZZLE_SOC_T8027_H
#define DR1ZZLE_SOC_T8027_H

/*
 * T8027 (A12Z) SoC profile — AArch64, host tier.
 *
 * The larger A12 sibling. This is the interesting one, and the reason the
 * exploit field is per-profile rather than per-family: its geometry IS
 * measured — the reference project carries a t8027 platform config, and the
 * IORegistry dump and a restore-and-boot script for it are checked in next
 * to it — but usbliter8's own CPID switch has no case for it. Its README
 * names A12X/Z as "theoretically supported as well, but it's not implemented
 * yet".
 *
 * So this profile records a part this tree can describe and cannot reach,
 * which is a different state from both the A12 (described and reachable) and
 * the A12X (neither). Marking it usbliter8 would have been the family-level
 * assumption the registry stopped making, and the registry test checks the
 * claim against usbliter8's switch for exactly that reason.
 *
 * Why it is not just t8020.h with different comments: these are separate parts
 * with separate CPIDs, and a registry that models two CPIDs with one profile
 * cannot tell a device which one it found apart. The values are this part's
 * own, read from its own platform config — which is why they agree with the
 * A12's and are still written out.
 *
 * TIER: host. The map below is this part's own, but no payload can be built
 * for it while no public exploit reaches it.
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
    (SOC_BLK_ROM | SOC_BLK_UART | SOC_BLK_TIMER | SOC_BLK_AIC | SOC_BLK_PMGR | \
     SOC_BLK_USB | SOC_BLK_WATCHDOG | SOC_BLK_CHIPCTL | SOC_BLK_NAND | SOC_BLK_NOR)

/* ----------------------------------------------------------------------- */
/* Memory geometry                                                          */
/* ----------------------------------------------------------------------- */

#define SOC_T8027_ROM_BASE            0x100000000ULL
#define SOC_T8027_ROM_SIZE            0x100000ULL
#define SOC_T8027_SECURE_ROM_BASE     0x100000000ULL
#define SOC_T8027_SECURE_ROM_SIZE     0x100000ULL

#define SOC_T8027_SRAM_BASE           0x19C000000ULL
#define SOC_T8027_SRAM_SIZE           SOC_UNRECORDED

/* ----------------------------------------------------------------------- */
/* Peripheral register bases (reference project's measured t8027 config)    */
/* ----------------------------------------------------------------------- */

#define SOC_T8027_UART_BASE           0x20A0C0000ULL
#define SOC_T8027_TIMER_BASE          0x20E100000ULL
#define SOC_T8027_AIC_BASE            0x23B100000ULL
#define SOC_T8027_AIC_SIZE            0x30000ULL

/* Same correction as the A12, and the same reason for recording it: the
 * shared T802x config's pmgr: 0x20e000000 is the wrong band for this part
 * too. The A12X measurement names the 0x23b0 band outright — 0x23b000000,
 * the six ways it is composed, and 0x23b080600 among them — and its first
 * plane is 0x30000, ten 16 KiB entries at 0x4000 stride, not one page. */
#define SOC_T8027_PMGR_BASE           0x23B000000ULL
#define SOC_T8027_PMGR_FIRST_PLANE    0x30000ULL
#define SOC_T8027_PMGR_PLANE0_SIZE    0x30000ULL

/* The eleven PMGR planes this part names, listed individually rather than
 * as one aperture because the 0x23b0802xx power-state registers and the
 * 0x23b080600 SEP word live inside the range, so a single 0xc0000 window
 * would overlap them. 0x23b080000 is deliberately absent for that reason.
 * Planes 8-10 are this part's second calibration block, 0x210e2xxxx. */
#define SOC_T8027_PMGR_PLANES \
    0x23B000000ULL, 0x23B014000ULL, 0x23B02C000ULL, 0x23B040000ULL, \
    0x23B068000ULL, 0x23B0A0000ULL, 0x23B0B8000ULL, \
    0x210E20000ULL, 0x210E21000ULL, 0x210E40000ULL, 0x21C000000ULL

/* The A12X's SEP power-state word, the same d321ap ps-reg[5] entry
 * (0x00080600, flags 1) at the same physical address the A12 uses,
 * independently confirmed by its own ioreg dump. Same significance as the
 * A12's: this is the word that decides whether the enclave is powered. */
#define SOC_T8027_SEP_POWER_WORD      0x23B080600ULL

/* AppleMcc calibration, this part's own block, plus the shared T803x one.
 * The A12X's block is 0x20000 because its two descriptor-selected planes
 * say so; the shared one is 0x80000, the sixteen-entry stride the loop
 * bound establishes. */
#define SOC_T8027_MCC_BASE            0x23B288000ULL
#define SOC_T8027_MCC_SIZE            0x20000ULL
#define SOC_T8027_MCC2_BASE           0x210E70000ULL
#define SOC_T8027_MCC2_SIZE           0x80000ULL

#define SOC_T8027_DCP_BASE            0x235000000ULL
#define SOC_T8027_DCP_SIZE            0x4000ULL
#define SOC_T8027_AES_BASE            0x235008000ULL

/* The USB device controller, measured rather than inherited.
 *
 * This field held the A12's 0x239100000, and the reasoning recorded for it
 * was "it uses the same USB complex layout as the T8020". That is a carried
 * assumption and it is wrong. The A12X's own ROM constant pool says
 * otherwise: the USB task at 0x10000CCB4 loads a 64-bit literal at
 * 0x100021BB8 that is 0x000000025d100000, byte-identical in both checked-in
 * builds, and the maintainer-supplied ioreg dump corroborates it with
 * usb3-phy@5D880014 and usb-drd0's IODeviceMemory at physical
 * 0x25d010000..0x25d020000 — the 0x25d0_0000 block, nothing near 0x2391.
 *
 * So this is the USB *device* controller at host+0x100000, the same
 * relationship 0x239100000 has on the A12, at a different host base. */
#define SOC_T8027_USB_BASE            0x25D100000ULL
#define SOC_T8027_USB_SIZE            0x10000ULL

/* The watchdog aperture, split so the four-word boot-event descriptor at
 * +0x8030 is its own device — same measured split as the A12 and the A13,
 * and the same reason for splitting it wherever the composition count is
 * non-zero. */
#define SOC_T8027_WDT_BASE            0x23D2B0000ULL
#define SOC_T8027_WDT_SIZE            0xC000ULL
#define SOC_T8027_WDT_BOOT_EVENT_OFF  0x8030ULL
#define SOC_T8027_WDT_BOOT_EVENT_SIZE 0x10ULL
#define SOC_T8027_BOOT_EVENT_BASE     0x23D2B8030ULL

/* The chip-control / fuse block, which it reads at 0x23d2bc030 — the +0x30
 * revision word. With this window unmapped the census faults at instruction
 * 31,378 with a bus error and esr1 = 0x0, i.e. the address is absent from
 * the bus rather than merely untranslatable. */
#define SOC_T8027_CHIPCTL_BASE        0x23D2BC000ULL
#define SOC_T8027_CHIPCTL_SIZE        0x4000ULL

#define SOC_T8027_NAND_BASE           0x200000000ULL
#define SOC_T8027_NAND_SIZE           0x8000000ULL
#define SOC_T8027_NOR_BASE            0x240000000ULL
#define SOC_T8027_NOR_SIZE            0x1000000ULL
#define SOC_T8027_BLOCK_BASE          0x241000000ULL
#define SOC_T8027_BLOCK_SIZE          0x400000ULL

/* The user-peripheral and USB-host band, this part's own. The panel, DSI
 * PHY, raster compositor, touch, audio, BT, WiFi, camera and sensor hub
 * sit at 0x20A1x0000, and the USB host stack (PHY, MUX, PD) at 0x20A1A0000
 * — the same band the A12's config carries. */
#define SOC_T8027_PANEL_BASE          0x20A110000ULL
#define SOC_T8027_DSI_PHY_BASE        0x20A120000ULL
#define SOC_T8027_RASTER_BASE         0x20A130000ULL
#define SOC_T8027_TOUCH_BASE          0x20A140000ULL
#define SOC_T8027_AUDIO_BASE          0x20A150000ULL
#define SOC_T8027_BT_BASE             0x20A160000ULL
#define SOC_T8027_WIFI_BASE           0x20A170000ULL
#define SOC_T8027_CAMERA_BASE         0x20A180000ULL
#define SOC_T8027_SENSORHUB_BASE      0x20A190000ULL
#define SOC_T8027_USBPHY_BASE         0x20A1A0000ULL
#define SOC_T8027_USBMUX_BASE         0x20A1A1000ULL
#define SOC_T8027_USBPD_BASE          0x20A1A2000ULL

#define SOC_T8027_MAILBOX_BASE        0x23C000000ULL

/* ----------------------------------------------------------------------- */
/* Not recorded                                                             */
/* ----------------------------------------------------------------------- */

/* The SEP window is NOT 0x240000000 — that is this part's NOR base, and a
 * first draft recorded it as the SEP window because the reference config has
 * no separate sep_base field. The A12X's own ioreg dump is what would
 * answer it. */
#define SOC_T8027_SEP_BASE            SOC_UNRECORDED
#define SOC_T8027_SEP_SIZE            SOC_UNRECORDED

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