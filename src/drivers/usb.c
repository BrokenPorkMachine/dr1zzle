#include "memory_map.h"
#include "timer.h"
#include "usb.h"
#include "tcp.h"

/* DWC2 Register Offsets */
#define DWC2_GOTGCTL      0x000
#define DWC2_GOTGINT      0x004
#define DWC2_GAHBCFG      0x008
#define DWC2_GUSBCFG      0x00C
#define DWC2_GRSTCTL      0x010
#define DWC2_GINTSTS      0x014
#define DWC2_GINTMSK      0x018
#define DWC2_GRXFSIZ      0x024
#define DWC2_GNPTXFSIZ    0x028
#define DWC2_GRXSTSP      0x020
#define DWC2_GDFIFO0      0x1000
#define DWC2_DCFG         0x800
#define DWC2_DCTL         0x804
#define DWC2_DSTS         0x808
#define DWC2_DIEPMSK      0x810
#define DWC2_DOEPMSK      0x814
#define DWC2_DAINT        0x818
#define DWC2_DAINTMSK     0x81C
#define DWC2_DIEPCTL0     0x900
#define DWC2_DOEPCTL0     0xB00
#define DWC2_DIEPTSIZ0    0x910
#define DWC2_DOEPTSIZ0    0xB10
#define DWC2_DIEPCTL1     0x920
#define DWC2_DOEPCTL1     0xB20
#define DWC2_DIEPTSIZ1    0x930
#define DWC2_DOEPTSIZ1    0xB30
#define DWC2_DIEPCTL2     0x940
#define DWC2_DOEPCTL2     0xB40
#define DWC2_DIEPTSIZ2    0x950
#define DWC2_DOEPTSIZ2    0xB50
#define DWC2_DIEPINT0     0x908
#define DWC2_DOEPINT0     0xB08
#define DWC2_DIEPINT1     0x928
#define DWC2_DOEPINT1     0xB28
#define DWC2_DIEPINT2     0x948
#define DWC2_DOEPINT2     0xB48
#define DWC2_GRXSTSP      0x020
#define DWC2_GDFIFO0      0x1000

/* Register bit definitions */
#define GRSTCTL_CSRST     (1 << 0)
#define GRSTCTL_AHBIDLE   (1 << 31)

#define GAHBCFG_GLBL_INTR_EN  (1 << 0)
#define GAHBCFG_HBSTLEN_INCR16 (5 << 1)

#define GUSBCFG_PHY_UTMI      (1 << 13)
#define GUSBCFG_TOUTCAL_7     (7 << 10)
#define GUSBCFG_USBTRDTIM_5   (5 << 10)
#define GUSBCFG_PHY_IF_16BIT  (1 << 12)

#define DCFG_DESCDMA          (1 << 23)
#define DCFG_DEVSPD_HS        (0 << 0)

#define DCTL_SGINAK           (1 << 7)
#define DCTL_CGINAK           (1 << 6)

#define EPCTL_EPENA           (1 << 31)
#define EPCTL_EPDIS           (1 << 30)
#define EPCTL_SODDFRM         (1 << 29)
#define EPCTL_SD0PID          (1 << 28)
#define EPCTL_SNAK            (1 << 27)
#define EPCTL_CNAK            (1 << 26)
#define EPCTL_STALL           (1 << 21)
#define EPCTL_USB_ACTEP       (1 << 15)
#define EPCTL_EPTYPE_CTRL     (0 << 18)
#define EPCTL_EPTYPE_BULK     (2 << 18)
#define EPCTL_EPTYPE_INTR     (3 << 18)
#define EPCTL_MPS_64          (64 << 0)
#define EPCTL_MPS_512         (512 << 0)
#define EPCTL_MPS_16          (16 << 0)

#define DOEPTSIZ_SUPCNT_3     (3 << 29)
#define DOEPTSIZ_PKTCNT_1     (1 << 19)
#define DOEPTSIZ_XFERSIZE_64  (64 << 0)

#define DIEPTSIZ_PKTCNT_1     (1 << 19)

#define GINTSTS_USBRST        (1 << 12)
#define GINTSTS_ENUMDNE       (1 << 13)
#define GINTSTS_RXFLVL        (1 << 4)
#define GINTSTS_IEPINT        (1 << 18)
#define GINTSTS_OEPINT        (1 << 19)

#define DAINT_IEP0            (1 << 0)
#define DAINT_OEP0            (1 << 16)
#define DAINT_IEP1            (1 << 1)
#define DAINT_OEP1            (1 << 17)
#define DAINT_IEP2            (1 << 2)
#define DAINT_OEP2            (1 << 18)

#define DOEPINT_XFERCOMPL     (1 << 0)
#define DOEPINT_EPDISBLD      (1 << 1)
#define DOEPINT_SETUP         (1 << 3)
#define DOEPINT_STUP          (1 << 6)

#define DIEPINT_XFERCOMPL     (1 << 0)
#define DIEPINT_TXFE          (1 << 7)

#define DOEPTSIZ_SUPCNT_3     (3 << 29)
#define DOEPTSIZ_PKTCNT_1     (1 << 19)
#define DOEPTSIZ_XFERSIZE_64  (64 << 0)

#define DIEPTSIZ_PKTCNT_1     (1 << 19)

#define GINTSTS_USBRST        (1 << 12)
#define GINTSTS_ENUMDNE       (1 << 13)
#define GINTSTS_RXFLVL        (1 << 4)
#define GINTSTS_IEPINT        (1 << 18)
#define GINTSTS_OEPINT        (1 << 19)

#define DAINT_IEP0            (1 << 0)
#define DAINT_OEP0            (1 << 16)
#define DAINT_IEP1            (1 << 1)
#define DAINT_OEP1            (1 << 17)
#define DAINT_IEP2            (1 << 2)
#define DAINT_OEP2            (1 << 18)

#define DOEPINT_XFERCOMPL     (1 << 0)
#define DOEPINT_EPDISBLD      (1 << 1)
#define DOEPINT_SETUP         (1 << 3)
#define DOEPINT_STUP          (1 << 6)

#define DIEPINT_XFERCOMPL     (1 << 0)
#define DIEPINT_TXFE          (1 << 7)

#define DOEPTSIZ_SUPCNT_3     (3 << 29)
#define DOEPTSIZ_PKTCNT_1     (1 << 19)
#define DOEPTSIZ_XFERSIZE_64  (64 << 0)

#define DIEPTSIZ_PKTCNT_1     (1 << 19)

#define GINTSTS_USBRST        (1 << 12)
#define GINTSTS_ENUMDNE       (1 << 13)
#define GINTSTS_RXFLVL        (1 << 4)
#define GINTSTS_IEPINT        (1 << 18)
#define GINTSTS_OEPINT        (1 << 19)

#define DAINT_IEP0            (1 << 0)
#define DAINT_OEP0            (1 << 16)
#define DAINT_IEP1            (1 << 1)
#define DAINT_OEP1            (1 << 17)
#define DAINT_IEP2            (1 << 2)
#define DAINT_OEP2            (1 << 18)

#define DOEPINT_XFERCOMPL     (1 << 0)
#define DOEPINT_EPDISBLD      (1 << 1)
#define DOEPINT_SETUP         (1 << 3)
#define DOEPINT_STUP          (1 << 6)

#define DIEPINT_XFERCOMPL     (1 << 0)
#define DIEPINT_TXFE          (1 << 7)

#define DOEPTSIZ_SUPCNT_3     (3 << 29)
#define DOEPTSIZ_PKTCNT_1     (1 << 19)
#define DOEPTSIZ_XFERSIZE_64  (64 << 0)

#define DIEPTSIZ_PKTCNT_1     (1 << 19)

#define GINTSTS_USBRST        (1 << 12)
#define GINTSTS_ENUMDNE       (1 << 13)
#define GINTSTS_RXFLVL        (1 << 4)
#define GINTSTS_IEPINT        (1 << 18)
#define GINTSTS_OEPINT        (1 << 19)

#define DAINT_IEP0            (1 << 0)
#define DAINT_OEP0            (1 << 16)
#define DAINT_IEP1            (1 << 1)
#define DAINT_OEP1            (1 << 17)
#define DAINT_IEP2            (1 << 2)
#define DAINT_OEP2            (1 << 18)

#define DOEPINT_XFERCOMPL     (1 << 0)
#define DOEPINT_EPDISBLD      (1 << 1)
#define DOEPINT_SETUP         (1 << 3)
#define DOEPINT_STUP          (1 << 6)

#define DIEPINT_XFERCOMPL     (1 << 0)
#define DIEPINT_TXFE          (1 << 7)

#define DOEPTSIZ_SUPCNT_3     (3 << 29)
#define DOEPTSIZ_PKTCNT_1     (1 << 19)
#define DOEPTSIZ_XFERSIZE_64  (64 << 0)

#define DIEPTSIZ_PKTCNT_1     (1 << 19)

#define GINTSTS_USBRST        (1 << 12)
#define GINTSTS_ENUMDNE       (1 << 13)
#define GINTSTS_RXFLVL        (1 << 4)
#define GINTSTS_IEPINT        (1 << 18)
#define GINTSTS_OEPINT        (1 << 19)

#define DAINT_IEP0            (1 << 0)
#define DAINT_OEP0            (1 << 16)
#define DAINT_IEP1            (1 << 1)
#define DAINT_OEP1            (1 << 17)
#define DAINT_IEP2            (1 << 2)
#define DAINT_OEP2            (1 << 18)

#define DOEPINT_XFERCOMPL     (1 << 0)
#define DOEPINT_EPDISBLD      (1 << 1)
#define DOEPINT_SETUP         (1 << 3)
#define DOEPINT_STUP          (1 << 6)

#define DIEPINT_XFERCOMPL     (1 << 0)
#define DIEPINT_TXFE          (1 << 7)

static volatile uint32_t *dwc2 = (volatile uint32_t *)USB_BASE;

static inline void write_reg(uint32_t offset, uint32_t val) {
    dwc2[offset / 4] = val;
}

static inline uint32_t read_reg(uint32_t offset) {
    return dwc2[offset / 4];
}

/* Forward declarations */
static void ep0_init(void);
static void ep1_init(void);
static void ep2_init(void);
static void handle_rx_fifo(void);
static void handle_setup_packet(void);
static void handle_get_descriptor(uint16_t wValue, uint16_t wLength);
static void handle_set_address(uint16_t addr);
static void handle_set_configuration(uint16_t cfg);
static void ep0_data_in(const uint8_t *data, uint16_t len);
static void ep0_stall(void);
static void handle_iep0(void);
static void handle_oep0(void);
static void handle_iep1(void);
static void handle_iep2(void);
static void handle_oep1(void);
static void handle_oep2(void);

static uint8_t ep0_setup_data[8];

static void ep0_init(void) {
    /* EP0 OUT */
    write_reg(DWC2_DOEPCTL0, EPCTL_EPENA | EPCTL_CNAK | EPCTL_USB_ACTEP | EPCTL_MPS_64 | 0);
    write_reg(DWC2_DOEPTSIZ0, (3 << 29) | (1 << 19) | 64);
    
    /* EP0 IN */
    write_reg(DWC2_DIEPCTL0, EPCTL_EPENA | EPCTL_CNAK | EPCTL_USB_ACTEP | EPCTL_MPS_64 | 0);
}

static void ep1_init(void) {
    write_reg(DWC2_DIEPCTL1, EPCTL_EPENA | EPCTL_CNAK | EPCTL_USB_ACTEP | EPCTL_MPS_16 | (3 << 18));
    write_reg(DWC2_DIEPTSIZ1, (1 << 19) | (16 << 0));
    write_reg(DWC2_DAINTMSK, read_reg(DWC2_DAINTMSK) | (1 << 1));
}

static void ep2_init(void) {
    write_reg(DWC2_DOEPCTL2, EPCTL_EPENA | EPCTL_CNAK | EPCTL_USB_ACTEP | EPCTL_MPS_512 | (2 << 18));
    write_reg(DWC2_DOEPTSIZ2, (1 << 19) | (512 << 0));
    write_reg(DWC2_DAINTMSK, read_reg(DWC2_DAINTMSK) | (1 << 18));
    
    write_reg(DWC2_DIEPCTL2, EPCTL_EPENA | EPCTL_CNAK | EPCTL_USB_ACTEP | EPCTL_MPS_512 | (2 << 18));
    write_reg(DWC2_DIEPTSIZ2, (1 << 19) | (512 << 0));
    write_reg(DWC2_DAINTMSK, read_reg(DWC2_DAINTMSK) | (1 << 2));
}

void usb_init(void) {
    /* 1. Soft reset */
    write_reg(DWC2_GRSTCTL, GRSTCTL_CSRST);
    while (read_reg(DWC2_GRSTCTL) & GRSTCTL_CSRST) {}
    while ((read_reg(DWC2_GRSTCTL) & GRSTCTL_AHBIDLE) == 0) {}

    /* 2. GAHBCFG */
    write_reg(DWC2_GAHBCFG, GAHBCFG_GLBL_INTR_EN | GAHBCFG_HBSTLEN_INCR16);
    
    /* 3. GUSBCFG */
    write_reg(DWC2_GUSBCFG, GUSBCFG_PHY_UTMI | GUSBCFG_TOUTCAL_7 | GUSBCFG_USBTRDTIM_5 | GUSBCFG_PHY_IF_16BIT);
    
    /* 4. DCFG */
    write_reg(DWC2_DCFG, DCFG_DESCDMA | DCFG_DEVSPD_HS);
    
    /* 5. Clear NAKs */
    write_reg(DWC2_DCTL, DCTL_SGINAK | DCTL_CGINAK);
    
    /* 6. EP0 */
    ep0_init();
    
    /* 7. EP1 (interrupt) + EP2 (bulk) for CDC-ECM */
    ep1_init();
    ep2_init();
    
    /* 8. Interrupts */
    write_reg(DWC2_GINTMSK, GINTSTS_USBRST | GINTSTS_ENUMDNE | GINTSTS_RXFLVL | GINTSTS_IEPINT | GINTSTS_OEPINT);
    write_reg(DWC2_DAINTMSK, DAINT_IEP0 | DAINT_OEP0 | DAINT_IEP1 | DAINT_OEP1 | DAINT_IEP2 | DAINT_OEP2);
    write_reg(DWC2_DIEPMSK, DIEPINT_XFERCOMPL | DIEPINT_TXFE);
    write_reg(DWC2_DOEPMSK, DOEPINT_XFERCOMPL | DOEPINT_EPDISBLD | DOEPINT_SETUP | DOEPINT_STUP);
}

/* USB interrupt handler - call from irq_handler */
void usb_irq_handler(void) {
    uint32_t gintsts = read_reg(DWC2_GINTSTS);
    
    /* USB Reset */
    if (gintsts & GINTSTS_USBRST) {
        write_reg(DWC2_GINTSTS, GINTSTS_USBRST);
        ep0_init();
    }
    
    /* Enumeration Done */
    if (gintsts & GINTSTS_ENUMDNE) {
        write_reg(DWC2_GINTSTS, GINTSTS_ENUMDNE);
    }
    
    /* RX FIFO non-empty */
    if (gintsts & GINTSTS_RXFLVL) {
        handle_rx_fifo();
    }
    
    /* IN EP interrupt */
    if (gintsts & GINTSTS_IEPINT) {
        uint32_t daint = read_reg(DWC2_DAINT);
        if (daint & (1 << 0)) handle_iep0();
        if (daint & (1 << 1)) handle_iep1();
        if (daint & (1 << 2)) handle_iep2();
    }
    
    /* OUT EP interrupt */
    if (gintsts & GINTSTS_OEPINT) {
        uint32_t daint = read_reg(DWC2_DAINT);
        if (daint & (1 << 16)) handle_oep0();
        if (daint & (1 << 17)) handle_oep1();
        if (daint & (1 << 18)) handle_oep2();
    }
}

static void handle_rx_fifo(void) {
    uint32_t status = read_reg(DWC2_GRXSTSP);
    uint32_t ep_num = status & 0xF;
    (void)ep_num;
    uint32_t pkt_sts = (status >> 17) & 0xF;
    uint32_t byte_cnt = (status >> 4) & 0x7FF;
    
    if (pkt_sts == 6) { /* SETUP packet */
        for (int i = 0; i < 2; i++) {
            uint32_t word = read_reg(DWC2_GDFIFO0);
            ((uint32_t *)ep0_setup_data)[i] = word;
        }
        handle_setup_packet();
    } else if (pkt_sts == 2) { /* OUT data */
        for (uint32_t i = 0; i < byte_cnt; i += 4) {
            read_reg(DWC2_GDFIFO0);
        }
    }
}

static void handle_setup_packet(void) {
    uint8_t bmRequestType = ep0_setup_data[0];
    uint8_t bRequest = ep0_setup_data[1];
    uint16_t wValue = ep0_setup_data[2] | (ep0_setup_data[3] << 8);
    uint16_t wIndex = ep0_setup_data[4] | (ep0_setup_data[5] << 8);
    uint16_t wLength = ep0_setup_data[6] | (ep0_setup_data[7] << 8);
    (void)wIndex;
    
    if ((bmRequestType & 0x60) == 0x00) {
        switch (bRequest) {
            case 0x06: handle_get_descriptor(wValue, wLength); break;
            case 0x05: handle_set_address(wValue); break;
            case 0x09: handle_set_configuration(wValue); break;
            default: ep0_stall(); break;
        }
    } else if ((bmRequestType & 0x60) == 0x20) {
        switch (bRequest) {
            case 0x00: ep0_data_in(0, 0); break;
            case 0x01: ep0_data_in(0, 0); break;
            case 0x40: ep0_data_in(0, 0); break;
            case 0x41: ep0_data_in(0, 0); break;
            case 0x42: ep0_data_in(0, 0); break;
            case 0x43: ep0_data_in(0, 0); break;
            default: ep0_stall(); break;
        }
    } else {
        ep0_stall();
    }
}

static void handle_get_descriptor(uint16_t wValue, uint16_t wLength) {
    uint8_t desc_type = wValue >> 8;
    uint8_t desc_index = wValue & 0xFF;
    const uint8_t *desc = 0;
    uint16_t desc_len = 0;
    
    extern const uint8_t device_desc[];
    extern const uint8_t config_desc[];
    extern const uint8_t string_lang[];
    extern const uint8_t string_manuf[];
    extern const uint8_t string_product[];
    extern const uint8_t string_serial[];
    extern const uint32_t config_desc_size;
    
    switch (desc_type) {
        case 1: 
            desc = device_desc; 
            desc_len = 18; 
            break;
        case 2:
            desc = config_desc;
            desc_len = config_desc_size;
            break;
        case 3: {
            static uint8_t desc_buf[64];
            const uint8_t *str = 0;
            int len = 0;
            switch (desc_index) {
                case 0: desc = string_lang; desc_len = 4; break;
                case 1: str = string_manuf; len = 18; break;
                case 2: str = string_product; len = 26; break;
                case 3: str = string_serial; len = 12; break;
                default: 
                    ep0_stall(); 
                    return;
            }
            if (desc) break;
            desc_buf[0] = (uint8_t)(len * 2 + 2);
            desc_buf[1] = 3;
            for (int i = 0; i < len; i++) {
                desc_buf[2 + i * 2] = str[i];
                desc_buf[3 + i * 2] = 0;
            }
            desc = desc_buf;
            desc_len = desc_buf[0];
            break;
        }
        default: 
            ep0_stall(); 
            return;
    }
    
    uint16_t len = wLength < desc_len ? wLength : desc_len;
    ep0_data_in(desc, len);
}

static void handle_set_address(uint16_t addr) {
    ep0_data_in(0, 0);
    write_reg(DWC2_DCFG, (read_reg(DWC2_DCFG) & ~0x7F) | ((addr & 0x7F) << 4));
}

static void handle_set_configuration(uint16_t cfg) {
    (void)cfg;
    ep0_data_in(0, 0);
}

static void ep0_data_in(const uint8_t *data, uint16_t len) {
    uint16_t max_pkt = 64;
    uint16_t send_len = len < max_pkt ? len : max_pkt;
    
    for (int i = 0; i < send_len; i += 4) {
        uint32_t word = 0;
        for (int j = 0; j < 4 && i + j < send_len; j++) {
            word |= ((uint32_t)data[i + j]) << (j * 8);
        }
        write_reg(DWC2_GDFIFO0, word);
    }
    
    write_reg(DWC2_DIEPCTL0, EPCTL_EPENA | EPCTL_CNAK);
    write_reg(DWC2_DIEPTSIZ0, DIEPTSIZ_PKTCNT_1 | (send_len << 0));
}

static void ep0_stall(void) {
    write_reg(DWC2_DIEPCTL0, (1 << 21));
    write_reg(DWC2_DOEPCTL0, (1 << 21));
}

static void handle_iep0(void) {
    uint32_t diepint = read_reg(DWC2_DIEPINT0);
    write_reg(DWC2_DIEPINT0, diepint);
}

static void handle_oep0(void) {
    uint32_t doepint = read_reg(DWC2_DOEPINT0);
    write_reg(DWC2_DOEPINT0, doepint);
}

static void handle_iep1(void) {
    write_reg(DWC2_DIEPINT1, read_reg(DWC2_DIEPINT1));
}

static void handle_iep2(void) {
    write_reg(DWC2_DIEPINT2, read_reg(DWC2_DIEPINT2));
}

static void handle_oep1(void) {
    write_reg(DWC2_DOEPINT1, read_reg(DWC2_DOEPINT1));
}

static void handle_oep2(void) {
    write_reg(DWC2_DOEPINT2, read_reg(DWC2_DOEPINT2));
    write_reg(DWC2_DOEPTSIZ2, (1 << 19) | (1500 << 0));
    write_reg(DWC2_DOEPCTL2, (1 << 31) | (1 << 26) | (1 << 15) | 512 | (2 << 18));
}
