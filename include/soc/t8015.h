#ifndef DR1ZZLE_SOC_T8015_H
#define DR1ZZLE_SOC_T8015_H

/*
 * A11 (T8015) SoC profile.
 *
 * All values reverse-engineered from A11 silicon. Sources: iphem-soc memory
 * map, published Apple device-tree bindings, and checkm8's device_platform.
 *
 * This is the reference profile — the one the rest of the tree was built
 * against, and the only one with a peripheral register map. New SoCs should
 * copy this file, change the values, and add a matching #elif in
 * include/soc.h.
 *
 * It is also the contract every profile must satisfy. The fields are grouped
 * as they are for the other profiles under include/soc/:
 *
 *   identity    what the chip is, in the words the vendored tool uses
 *   tier        whether this tree can build an AArch64 payload for it
 *   blocks      which register blocks this tree has mapped (SOC_BLK_*)
 *   geometry    ROM/SRAM/DRAM/DFU/recovery geometry, from device_platform.py
 *   map         peripheral register bases, reverse-engineered from silicon
 *
 * A profile that is missing a block leaves the corresponding SOC_<name>_*
 * constants undefined rather than defining them as 0: a missing base then
 * fails the compile that uses it instead of quietly writing to address 0.
 */

/* ----------------------------------------------------------------------- */
/* Identity                                                                */
/* ----------------------------------------------------------------------- */

#define SOC_T8015_NAME         "t8015"

#define SOC_T8015_CPID         0x8015u
#define SOC_T8015_CPRV         0x11u
#define SOC_T8015_SCEP         0x01u
#define SOC_T8015_SRTG         "iBoot-3332.0.0.1.23"
#define SOC_T8015_ARCH         SOC_ARCH_AARCH64

/* ----------------------------------------------------------------------- */
/* Tier                                                                    */
/* ----------------------------------------------------------------------- */

/* The only payload-tier profile today: every block the core and the firmware
 * need is mapped below, so `make SOC=t8015` links and runs. */
#define SOC_T8015_TIER         SOC_TIER_PAYLOAD
#define SOC_T8015_MAPPED_BLOCKS \
    (SOC_BLK_ROM   | SOC_BLK_SRAM   | SOC_BLK_DRAM  | SOC_BLK_UART | \
     SOC_BLK_TIMER | SOC_BLK_AIC    | SOC_BLK_PMGR  | SOC_BLK_GPIO | \
     SOC_BLK_I2C   | SOC_BLK_SPI    | SOC_BLK_WDT   | SOC_BLK_NAND | \
     SOC_BLK_USB   | SOC_BLK_DCP    | SOC_BLK_MAILBOX | \
     SOC_BLK_ACE2  | SOC_BLK_RECFG  | SOC_BLK_WIFI  | SOC_BLK_DISPLAY)

/* ----------------------------------------------------------------------- */
/* Memory map (from iphem-soc)                                             */
/* ----------------------------------------------------------------------- */

#define SOC_T8015_SRAM_BASE          0x180000000ULL
#define SOC_T8015_SRAM_SIZE          0x1E8000ULL

#define SOC_T8015_SECURE_ROM_BASE    0x100000000ULL
#define SOC_T8015_SECURE_ROM_SIZE    0x100000ULL

#define SOC_T8015_UART_BASE          0x20A0C0000ULL
#define SOC_T8015_TIMER_BASE         0x20E100000ULL
#define SOC_T8015_AIC_BASE           0x232100000ULL
#define SOC_T8015_PMGR_BASE          0x232000000ULL
#define SOC_T8015_MAILBOX_BASE       0x23C000000ULL
#define SOC_T8015_DCP_BASE           0x235000000ULL
#define SOC_T8015_NOR_BASE           0x240000000ULL
#define SOC_T8015_BLOCK_BASE         0x241000000ULL
#define SOC_T8015_NAND_BASE          0x200000000ULL
#define SOC_T8015_USB_BASE           0x250000000ULL
#define SOC_T8015_WATCHDOG_BASE      0x2352B0000ULL
#define SOC_T8015_GPIO_BASE          0x20A100000ULL
#define SOC_T8015_I2C_BASE           0x20A200000ULL
#define SOC_T8015_SPI_BASE           0x20A400000ULL
#define SOC_T8015_PMU_BASE           0x20A000000ULL
#define SOC_T8015_SPMI_BASE          0x20A300000ULL
#define SOC_T8015_THERMAL_BASE       0x20A700000ULL
#define SOC_T8015_USB_PHY_BASE       0x20A1A0000ULL
#define SOC_T8015_USB_MUX_BASE       0x20A1A1000ULL
#define SOC_T8015_USB_PD_BASE        0x20A1A2000ULL
#define SOC_T8015_PANEL_BASE         0x20A110000ULL
#define SOC_T8015_DSI_PHY_BASE       0x20A120000ULL
#define SOC_T8015_RASTER_BASE        0x20A130000ULL
#define SOC_T8015_TOUCH_BASE         0x20A140000ULL
#define SOC_T8015_AUDIO_BASE         0x20A150000ULL
#define SOC_T8015_BT_BASE            0x20A160000ULL
#define SOC_T8015_WIFI_BASE          0x20A170000ULL
#define SOC_T8015_CAMERA_BASE        0x20A180000ULL
#define SOC_T8015_SENSORHUB_BASE     0x20A190000ULL
#define SOC_T8015_ACE2_BASE          0x230000000ULL
#define SOC_T8015_ACE2_SIZE          0x10000ULL

/* ----------------------------------------------------------------------- */
/* Interrupt map                                                           */
/* ----------------------------------------------------------------------- */

/* DWC2 OTG controller IRQ line on A11 (from apple,t8015-usb node). */
#define SOC_T8015_IRQ_USB_OTG 324u

/* ----------------------------------------------------------------------- */
/* NAND geometry                                                           */
/* ----------------------------------------------------------------------- */

/* Default geometry; overridden at runtime by nand_init() ID reads. */
#define SOC_T8015_NAND_PAGE_SIZE     4096u
#define SOC_T8015_NAND_OOB_SIZE      128u
#define SOC_T8015_NAND_PAGES_PER_BLOCK 64u
#define SOC_T8015_NAND_BLOCK_COUNT   4096u

/* ----------------------------------------------------------------------- */
/* AES engine (DCP pipe on A11)                                           */
/* ----------------------------------------------------------------------- */

#define SOC_T8015_DCP_AES_OFFSET     0x8000ULL
#define SOC_T8015_DCP_AES_PIPE_OFFSET 0x200
#define SOC_T8015_AES_CLK_GATE       0x240080240ULL

/* ----------------------------------------------------------------------- */
/* Recfg (A11)                                                             */
/* ----------------------------------------------------------------------- */

#define SOC_T8015_RECFG_SRAM_BASE    0x235F00000ULL
#define SOC_T8015_RECFG_SRAM_END     0x235F10000ULL
#define SOC_T8015_AOP_CFG_TABLE      0x2352C0200ULL
#define SOC_T8015_RECFG_AES_ADDR     0x2352D0000ULL
#define SOC_T8015_AOP_SRAM_LOCK_RANGE 0x235000200ULL
#define SOC_T8015_AOP_SRAM_LOCK_SET    0x235000204ULL
#define SOC_T8015_AOP_CFG_LOCK         0x2352C0214ULL

/* IORVBAR addresses for A11 recfg patching. */
#define SOC_T8015_IORVBAR_0  0x208450000ULL
#define SOC_T8015_IORVBAR_1  0x208550000ULL
#define SOC_T8015_IORVBAR_2  0x208050000ULL
#define SOC_T8015_IORVBAR_3  0x208150000ULL
#define SOC_T8015_IORVBAR_4  0x208250000ULL
#define SOC_T8015_IORVBAR_5  0x208350000ULL

/* ----------------------------------------------------------------------- */
/* Exploit geometry (checkm8)                                              */
/* ----------------------------------------------------------------------- */

/* From ipwndfu/device_platform.py for cpid 0x8015, cross-checked against
 * checkm8.py's device configuration. Everything in this block is a *host*
 * value: it is what places an image and what `goat pull` reads, and it is
 * independent of the peripheral map above. */
#define SOC_T8015_DFU_IMAGE_BASE     0x18001C000ULL
#define SOC_T8015_DFU_LOAD_BASE      0x800000000ULL
#define SOC_T8015_ROM_BASE           0x100000000ULL
#define SOC_T8015_ROM_SIZE           0x100000ULL
#define SOC_T8015_ROM_SHA1           "96fccb1a63de1a2d50ff14555d3898a5af46e9b1"
#define SOC_T8015_DRAM_BASE          0x800000000ULL
#define SOC_T8015_RECOVERY_IMAGE_BASE 0x18001C000ULL
#define SOC_T8015_RECOVERY_LOAD_BASE  0x800000000ULL
#define SOC_T8015_NONCE_LENGTH       32u
#define SOC_T8015_SEP_NONCE_LENGTH   20u
#define SOC_T8015_DEMOTION_REG       0x2352BC000ULL

/* checkm8.py's device configuration for this CPID. Two of the ten configs
 * enter DFU in a loop instead of needing the button hold, which changes the
 * instructions the host prints and nothing in the payload. */
#define SOC_T8015_DFU_TRIGGER        SOC_DFU_TRIGGER_LOOP

#define SOC_T8015_EXPLOIT  SOC_EXPLOIT_CHECKM8

/* ----------------------------------------------------------------------- */
/* Peripheral IP bindings                                                  */
/* ----------------------------------------------------------------------- */

#define SOC_T8015_I2C_BLOCK          "pwrfficent-smbus"
#define SOC_T8015_SPI_BLOCK          "apple-spi"
#define SOC_T8015_NAND_BLOCK         "apple-nand"

#endif /* DR1ZZLE_SOC_T8015_H */
