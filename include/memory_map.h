#ifndef MEMORY_MAP_H
#define MEMORY_MAP_H

#include <stdint.h>

/*
 * SoC memory map.
 *
 * The base addresses below are provided by the selected SoC profile
 * (include/soc.h -> include/soc/<soc>.h); they keep their historical names so
 * every existing #include "memory_map.h" site works unchanged. The profile
 * is chosen at build time (-DSOC_<name>, see include/soc.h) and a different
 * SOC= build supplies different values without this file changing.
 */
#include "soc.h"

/* The names the drivers use, defined from the selected profile in one place.
 * There is no per-SoC #ifdef here: the profile is the only thing that varies,
 * and the mapping below is the same for all of them. The namespaced form
 * (SOC_<soc>_<NAME>) stays available too — it is what the profile defines and
 * what the registry tests read. */
#define SRAM_BASE           DR1ZZLE_SOC_SRAM_BASE
#define SRAM_SIZE           DR1ZZLE_SOC_SRAM_SIZE

#define SECURE_ROM_BASE     DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _SECURE_ROM_BASE)
#define SECURE_ROM_SIZE     DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _SECURE_ROM_SIZE)

#define UART_BASE           DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _UART_BASE)
#define TIMER_BASE          DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _TIMER_BASE)
#define AIC_BASE            DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _AIC_BASE)
#define PMGR_BASE           DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _PMGR_BASE)
#define MAILBOX_BASE        DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _MAILBOX_BASE)
#define DCP_BASE            DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _DCP_BASE)
#define NOR_BASE            DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _NOR_BASE)
#define BLOCK_BASE          DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _BLOCK_BASE)
#define NAND_BASE           DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _NAND_BASE)
#define USB_BASE            DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _USB_BASE)
#define WATCHDOG_BASE       DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _WATCHDOG_BASE)
#define GPIO_BASE           DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _GPIO_BASE)
#define I2C_BASE            DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _I2C_BASE)
#define SPI_BASE            DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _SPI_BASE)
#define PMU_BASE            DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _PMU_BASE)
#define SPMI_BASE           DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _SPMI_BASE)
#define THERMAL_BASE        DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _THERMAL_BASE)
#define USB_PHY_BASE        DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _USB_PHY_BASE)
#define USB_MUX_BASE        DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _USB_MUX_BASE)
#define USB_PD_BASE         DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _USB_PD_BASE)
#define PANEL_BASE          DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _PANEL_BASE)
#define DSI_PHY_BASE        DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _DSI_PHY_BASE)
#define RASTER_BASE         DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _RASTER_BASE)
#define TOUCH_BASE          DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _TOUCH_BASE)
#define AUDIO_BASE          DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _AUDIO_BASE)
#define BT_BASE             DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _BT_BASE)
#define WIFI_BASE           DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _WIFI_BASE)
#define CAMERA_BASE         DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _CAMERA_BASE)
#define SENSORHUB_BASE      DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _SENSORHUB_BASE)
#define ACE2_BASE           DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _ACE2_BASE)
#define ACE2_SIZE           DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _ACE2_SIZE)

/* SoC profile selectors, aliased to the names the drivers use. */
#define SOC_IRQ_USB_OTG     DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _IRQ_USB_OTG)
#define SOC_NAND_PAGE_SIZE  DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _NAND_PAGE_SIZE)
#define SOC_NAND_OOB_SIZE   DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _NAND_OOB_SIZE)
#define SOC_NAND_PAGES_PER_BLOCK DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _NAND_PAGES_PER_BLOCK)
#define SOC_NAND_BLOCK_COUNT DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _NAND_BLOCK_COUNT)
#define SOC_DCP_AES_OFFSET  DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _DCP_AES_OFFSET)
#define SOC_DCP_AES_PIPE_OFFSET DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _DCP_AES_PIPE_OFFSET)
#define SOC_AES_CLK_GATE    DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _AES_CLK_GATE)
#define SOC_RECFG_AES_ADDR  DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _RECFG_AES_ADDR)
#define SOC_IORVBAR_0       DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _IORVBAR_0)
#define SOC_IORVBAR_1       DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _IORVBAR_1)
#define SOC_IORVBAR_2       DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _IORVBAR_2)
#define SOC_IORVBAR_3       DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _IORVBAR_3)
#define SOC_IORVBAR_4       DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _IORVBAR_4)
#define SOC_IORVBAR_5       DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _IORVBAR_5)
#define SOC_RECFG_SRAM_BASE DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _RECFG_SRAM_BASE)
#define SOC_RECFG_SRAM_END  DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _RECFG_SRAM_END)
#define SOC_AOP_CFG_TABLE   DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _AOP_CFG_TABLE)
#define SOC_AOP_SRAM_LOCK_RANGE DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _AOP_SRAM_LOCK_RANGE)
#define SOC_AOP_SRAM_LOCK_SET   DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _AOP_SRAM_LOCK_SET)
#define SOC_AOP_CFG_LOCK    DR1ZZLE_CAT(DR1ZZLE_SOC_PREFIX, _AOP_CFG_LOCK)

/* Page table constants (ARMv8-A, identical on every SoC) */
#define PAGE_SIZE           0x1000      /* 4KB */
#define BLOCK_SIZE          0x200000    /* 2MB */
#define L3_TABLE_SIZE       0x1000      /* 512 entries * 8 bytes */

/* IO base address for peripheral registers */
#define IO_BASE             0x200000000ULL

/* MAIR attributes */
#define MAIR_ATTR_NORMAL    0xFF        /* AttrIdx=0: Normal, WBWA */
#define MAIR_ATTR_DEVICE    0x04        /* AttrIdx=1: Device-nGnRnE */

/* Descriptor bits */
#define DESC_VALID          (1ULL << 0)
#define DESC_TABLE          (1ULL << 1)
#define DESC_BLOCK          (0ULL << 1)
#define DESC_AF             (1ULL << 10)
#define DESC_NG             (1ULL << 11)
#define DESC_AP_RO          (2ULL << 6)   /* AP=10: EL1 read-only */
#define DESC_AP_RW          (0ULL << 6)   /* AP=00: EL1 read-write */
#define DESC_NS             (1ULL << 5)
#define DESC_ATTR_IDX(x)    (((x) & 7) << 2)
#define DESC_PXN            (1ULL << 53)
#define DESC_UXN            (1ULL << 54)

/* External symbols from linker */
extern char _heap_start[];
extern char _heap_end[];
extern char _stack_top[];
extern char _stack_bottom[];

/* Device tree pointer the bootloader passed in x0, published by start.S.
 * Zero if the entry point did not supply one. Only a small subset of the
 * tree is parsed (see display_attach.c), but it is the authoritative source
 * for platform geometry such as the framebuffer. */
extern uint64_t g_boot_dtb;

/* Boot arguments string, set by the bootloader or modified at runtime. */
extern char *g_boot_args;

#endif /* MEMORY_MAP_H */
