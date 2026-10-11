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
 *
 * TIER: host. There is a peripheral map (below, this part's own) but no
 * payload can be built: the exploit needs an RP2350 as the USB host.
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
    (SOC_BLK_ROM | SOC_BLK_UART | SOC_BLK_TIMER | SOC_BLK_AIC | SOC_BLK_PMGR | \
     SOC_BLK_USB | SOC_BLK_WATCHDOG | SOC_BLK_CHIPCTL | SOC_BLK_NAND | SOC_BLK_NOR)

/* ----------------------------------------------------------------------- */
/* Memory geometry — usbliter8 t8030 shellcode offsets                     */
/* ----------------------------------------------------------------------- */

#define SOC_T8030_SRAM_BASE           0x19C000000ULL
#define SOC_T8030_SRAM_SIZE           SOC_UNRECORDED

#define SOC_T8030_ROM_BASE            0x100000000ULL
#define SOC_T8030_ROM_SIZE            0x30000ULL
#define SOC_T8030_SECURE_ROM_BASE     0x100000000ULL
#define SOC_T8030_SECURE_ROM_SIZE     0x30000ULL

/* The exploit's own addressing, kept because the next measurement for this
 * part is an exploit measurement. These are the A13's SRAM-side scratch, the
 * relocated ROM copy the shellcode builds, and the page-table root it
 * installs — not platform windows an image could be linked against. */
#define SOC_T8030_EXPLOIT_SRAM_NEW_SP   0x19C01E000ULL
#define SOC_T8030_EXPLOIT_ROM_NEW_PA   0x19C390000ULL
#define SOC_T8030_EXPLOIT_TTBR_BASE    0x19C388000ULL

/* ----------------------------------------------------------------------- */
/* Peripheral register bases (reference project's measured t8030 config)    */
/* ----------------------------------------------------------------------- */

#define SOC_T8030_UART_BASE           0x20A0C0000ULL
#define SOC_T8030_TIMER_BASE          0x20E100000ULL
#define SOC_T8030_AIC_BASE            0x23B100000ULL
#define SOC_T8030_AIC_SIZE            0x30000ULL

/* The A13's PMGR is in the 0x23b0 band like its siblings, not the 0x20e
 * band the shared T802x config defaults to. Its power-state word is at
 * plane 8 +0xc00, which is a *different offset* from the A12/A12X's +0x600
 * — the A13 record is explicit that copying the A12's word here would be
 * wrong, and that the neighbour at +0xc08 is not polled and is left cold.
 * 733,007 reads and exactly one write, of value 0, so this is a
 * hardware-owned readiness word the guest cannot drive.
 *
 * Note the base is in the same band as the power word and as the MCC and
 * PMGR-tail windows below, which is what the registry test asserts. The
 * shared config's 0x20e000000 is the default this part's own comment has
 * always said is wrong for it, and the header used to carry both the
 * comment and the wrong value. */
#define SOC_T8030_PMGR_BASE           0x23B000000ULL
#define SOC_T8030_SEP_POWER_WORD      0x23B080C00ULL

/* AppleMcc calibration, one page. This is the measurement rather than a
 * copy: the A13 builds exactly five addresses in this range — 0x23b058000,
 * +0x18, +0x350, +0x488, +0x900 — all inside 0x1000. Copying the A12X's
 * 0x20000 would reach 0x23b078000 and collide with the shared PMGR page at
 * 0x23b068000. */
#define SOC_T8030_MCC_BASE            0x23B058000ULL
#define SOC_T8030_MCC_SIZE            0x1000ULL

/* The single PMGR page the A13 names above its calibration block, from the
 * same inventory (0x23b09c040). It is separate from the MCC block so
 * neither window has to span the other. */
#define SOC_T8030_PMGR_TAIL_BASE      0x23B09C000ULL

#define SOC_T8030_MCC2_BASE           0x210E70000ULL
#define SOC_T8030_MCC2_SIZE           0x80000ULL

/* The AES engine the A13's SecureROM accesses at 0x235008000, same arm-io
 * band as the DCP, which is why it uses the same USB complex layout as the
 * A12/A12X. */
#define SOC_T8030_DCP_BASE            0x235000000ULL
#define SOC_T8030_DCP_SIZE            0x4000ULL
#define SOC_T8030_AES_BASE            0x235008000ULL

/* d321ap ADT: /arm-io/usb-complex maps to 0x239000000 and its usb-device
 * child has reg base +0x100000. */
#define SOC_T8030_USB_BASE            0x239100000ULL
#define SOC_T8030_USB_SIZE            0x10000ULL

/* The watchdog aperture and its boot-event descriptor split, the same
 * measured split the A12 and A12X carry. */
#define SOC_T8030_WDT_BASE            0x23D2B0000ULL
#define SOC_T8030_WDT_SIZE            0xC000ULL
#define SOC_T8030_WDT_BOOT_EVENT_OFF  0x8030ULL
#define SOC_T8030_WDT_BOOT_EVENT_SIZE 0x10ULL
#define SOC_T8030_BOOT_EVENT_BASE     0x23D2B8030ULL

#define SOC_T8030_CHIPCTL_BASE        0x23D2BC000ULL
#define SOC_T8030_CHIPCTL_SIZE        0x4000ULL

#define SOC_T8030_NAND_BASE           0x200000000ULL
#define SOC_T8030_NAND_SIZE           0x8000000ULL
#define SOC_T8030_NOR_BASE            0x240000000ULL
#define SOC_T8030_NOR_SIZE            0x1000000ULL
#define SOC_T8030_BLOCK_BASE          0x241000000ULL
#define SOC_T8030_BLOCK_SIZE          0x400000ULL

/* The user-peripheral and USB-host band, same layout as the A12 family. */
#define SOC_T8030_PANEL_BASE          0x20A110000ULL
#define SOC_T8030_DSI_PHY_BASE        0x20A120000ULL
#define SOC_T8030_RASTER_BASE         0x20A130000ULL
#define SOC_T8030_TOUCH_BASE          0x20A140000ULL
#define SOC_T8030_AUDIO_BASE          0x20A150000ULL
#define SOC_T8030_BT_BASE             0x20A160000ULL
#define SOC_T8030_WIFI_BASE           0x20A170000ULL
#define SOC_T8030_CAMERA_BASE         0x20A180000ULL
#define SOC_T8030_SENSORHUB_BASE      0x20A190000ULL
#define SOC_T8030_USBPHY_BASE         0x20A1A0000ULL
#define SOC_T8030_USBMUX_BASE         0x20A1A1000ULL
#define SOC_T8030_USBPD_BASE          0x20A1A2000ULL

#define SOC_T8030_MAILBOX_BASE        0x23C000000ULL
#define SOC_T8030_PMGR_FIRST_PLANE    0x30000ULL

/* ----------------------------------------------------------------------- */
/* Not recorded                                                             */
/* ----------------------------------------------------------------------- */

/* The SEP window is NOT 0x240000000 — that is this part's NOR base, and a
 * first draft recorded it as the SEP window because the reference config has
 * no separate sep_base field. The A13's pairing is in fact recorded as
 * CannotDiscriminate: sixteen SEPROMs share the A12's 0x23c1 gate band, so
 * naming one here would be a coin flip presented as a measurement. */
#define SOC_T8030_SEP_BASE            SOC_UNRECORDED
#define SOC_T8030_SEP_SIZE            SOC_UNRECORDED

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