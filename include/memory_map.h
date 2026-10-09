#ifndef MEMORY_MAP_H
#define MEMORY_MAP_H

#include <stdint.h>

/* A11 (T8015) Memory Map - from iphem-soc */
#define SRAM_BASE           0x180000000ULL
#define SRAM_SIZE           0x1E8000ULL

#define SECURE_ROM_BASE     0x100000000ULL
#define SECURE_ROM_SIZE     0x100000ULL

#define UART_BASE           0x20A0C0000ULL
#define TIMER_BASE          0x20E100000ULL
#define AIC_BASE            0x232100000ULL
#define PMGR_BASE           0x232000000ULL
#define MAILBOX_BASE        0x23C000000ULL
#define DCP_BASE            0x235000000ULL
#define NOR_BASE            0x240000000ULL
#define BLOCK_BASE          0x241000000ULL
#define NAND_BASE           0x200000000ULL
#define USB_BASE            0x250000000ULL
#define WATCHDOG_BASE       0x2352B0000ULL
#define GPIO_BASE           0x20A100000ULL
#define I2C_BASE            0x20A200000ULL
#define SPI_BASE            0x20A400000ULL
#define PMU_BASE            0x20A000000ULL
#define SPMI_BASE           0x20A300000ULL
#define THERMAL_BASE        0x20A700000ULL
#define USB_PHY_BASE        0x20A1A0000ULL
#define USB_MUX_BASE        0x20A1A1000ULL
#define USB_PD_BASE         0x20A1A2000ULL
#define PANEL_BASE          0x20A110000ULL
#define DSI_PHY_BASE        0x20A120000ULL
#define RASTER_BASE         0x20A130000ULL
#define TOUCH_BASE          0x20A140000ULL
#define AUDIO_BASE          0x20A150000ULL
#define BT_BASE             0x20A160000ULL
#define WIFI_BASE           0x20A170000ULL
#define CAMERA_BASE         0x20A180000ULL
#define SENSORHUB_BASE      0x20A190000ULL
#define ACE2_BASE           0x230000000ULL
#define ACE2_SIZE           0x10000ULL

/* Page table constants */
#define PAGE_SIZE           0x1000      /* 4KB */
#define BLOCK_SIZE          0x200000    /* 2MB */
#define L3_TABLE_SIZE       0x1000      /* 512 entries * 8 bytes */

/* MAIR attributes */
#define MAIR_ATTR_NORMAL    0xFF        /* AttrIdx=0: Normal, WBWA */
#define MAIR_ATTR_DEVICE    0x04        /* AttrIdx=1: Device-nGnRnE */

/* Descriptor bits */
#define DESC_VALID          (1ULL << 0)
#define DESC_TABLE          (1ULL << 1)
#define DESC_BLOCK          (0ULL << 1)
#define DESC_AF             (1ULL << 10)
#define DESC_NG             (1ULL << 11)
#define DESC_AP_RO          (1ULL << 6)   /* AP=01: Read-only */
#define DESC_AP_RW          (0ULL << 6)   /* AP=00: Read-write */
#define DESC_NS             (1ULL << 5)
#define DESC_ATTR_IDX(x)    (((x) & 7) << 2)
#define DESC_PXN            (1ULL << 53)
#define DESC_UXN            (1ULL << 54)

/* External symbols from linker */
extern char _heap_start[];
extern char _heap_end[];
extern char _stack_top[];
extern char _stack_bottom[];

#endif /* MEMORY_MAP_H */
