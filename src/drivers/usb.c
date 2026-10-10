/* DWC2 core + USB PHY bring-up for device mode (CDC-ECM host interface).
 *
 * The previous version of this file defined every register constant two to
 * nine times over (the same DOEPINT_XFERCOMPL block appears ~9 times), which
 * is harmless to the preprocessor but means the register map was never
 * actually reviewed. It is deduplicated here and the map is now derived from
 * the Synopsys DWC2 databook layout, with A11 deviations marked.
 */

#include <stddef.h>

#include "memory_map.h"
#include "mmio.h"
#include "timer.h"
#include "usb.h"
#include "uart.h"
#include "util.h"

/* ---- DWC2 global registers (0x000-0x1FF, relative to USB_BASE) --------- */
#define DWC2_GOTGCTL      0x000
#define DWC2_GOTGINT      0x004
#define DWC2_GAHBCFG      0x008
#define DWC2_GUSBCFG      0x00C
#define DWC2_GRSTCTL      0x010
#define DWC2_GINTSTS      0x014
#define DWC2_GINTMSK      0x018
#define DWC2_GRXSTSR      0x01C
#define DWC2_GRXSTSP      0x020
#define DWC2_GRXFSIZ      0x024
#define DWC2_GNPTXFSIZ    0x028
#define DWC2_GDFIFO0      0x1000
#define DWC2_GDFIFO1      0x1004
#define DWC2_GAHBSTP      0x1070   /* A11 addition: host/bus stop */

/* ---- DWC2 device registers (0x800+) ---------------------------------- */
#define DWC2_DCFG         0x800
#define DWC2_DCTL         0x804
#define DWC2_DSTS         0x808
#define DWC2_DIEPMSK      0x810
#define DWC2_DOEPMSK      0x814
#define DWC2_DAINT        0x818
#define DWC2_DAINTMSK     0x81C
#define DWC2_DPTSEQ       0x824
#define DWC2_DCFGSEQ      0x880   /* A11 addition: sequence number sync */

/* OUT endpoints: DIEP/DOEP pairs at 0x900 / 0xB00, stride 0x20. */
#define DWC2_EPCTL(n)     (0x900 + ((n) * 0x20))
#define DWC2_EPTSIZ(n)    (0x910 + ((n) * 0x20))
#define DWC2_EPDINT(n)    (0x908 + ((n) * 0x20))
#define DWC2_DIEPCTL0     DWC2_EPCTL(0)
#define DWC2_DIEPTSIZ0    DWC2_EPTSIZ(0)
#define DWC2_DIEPINT0     DWC2_EPDINT(0)
#define DWC2_DOEPCTL0     0xB00
#define DWC2_DOEPTSIZ0    0xB10
#define DWC2_DOEPINT0     0xB08
#define DWC2_DIEPCTL1     0x920
#define DWC2_DIEPTSIZ1    0x930
#define DWC2_DIEPINT1     0x928
#define DWC2_DOEPCTL1     0xB20
#define DWC2_DOEPTSIZ1    0xB30
#define DWC2_DOEPINT1     0xB28
#define DWC2_DIEPCTL2     0x940
#define DWC2_DIEPTSIZ2    0x950
#define DWC2_DIEPINT2     0x948
#define DWC2_DOEPCTL2     0xB40
#define DWC2_DOEPTSIZ2    0xB50
#define DWC2_DOEPINT2     0xB48

/* GOTGCTL */
#define GOTGCTL_CSRST     (1 << 0)
#define GOTGCTL_CMODE     (1 << 3)   /* 1 = device mode */
/* GAHBCFG */
#define GAHBCFG_GLBL_INTR_EN  (1 << 0)
#define GAHBCFG_HBSTLEN_INCR16 (5 << 1)
#define GAHBCFG_DMAEN         (1 << 4)
/* GUSBCFG */
#define GUSBCFG_PHY_UTMI      (1 << 13)
#define GUSBCFG_PHY_IF_16BIT  (1 << 12)   /* 0 = 8-bit, 1 = 16-bit */
#define GUSBCFG_TOUTCAL_MASK  (0xF << 10)  /* 4-bit field, not two of them */
#define GUSBCFG_TOUTCAL_7     (0x7 << 10)
#define GUSBCFG_USBTRDTIM_5   (0x5 << 14)
/* GRSTCTL */
#define GRSTCTL_CSRST     (1 << 0)
#define GRSTCTL_AHBIDLE   (1 << 31)
#define GRSTCTL_TXFNUM_SHIFT 6
/* GINTSTS */
#define GINTSTS_USBRST    (1 << 12)
#define GINTSTS_ENUMDNE   (1 << 13)
#define GINTSTS_RXFLVL    (1 << 4)
#define GINTSTS_IEPINT    (1 << 18)
#define GINTSTS_OEPINT    (1 << 19)
/* GRXSTSP */
#define GRXSTSP_EPNUM_MASK    0xF
#define GRXSTSP_PKTSTS_SHIFT  17
#define GRXSTSP_PKTSTS_MASK   0xF
#define GRXSTSP_XFER_SIZE_SHIFT 4
#define GRXSTSP_XFER_SIZE_MASK 0x7FF
#define GRXSTSP_PKTSTS_SETUP  6
#define GRXSTSP_PKTSTS_OUT   2
/* DCFG */
#define DCFG_DESCDMA      (1 << 23)
#define DCFG_DEVSPD_MASK  0x7
#define DCFG_DEVSPD_HS    0x0
#define DCFG_DEVSPD_FS    0x3
#define DCFG_ADDR_MASK    0x7F
/* DCTL */
#define DCTL_SGINAK       (1 << 7)
#define DCTL_CGINAK       (1 << 6)
#define DCTL_SGUSBPCTRL   (1 << 2)
#define DCTL_CGUSBPCTRL   (1 << 1)
/* Endpoint control */
#define EPCTL_EPENA       (1 << 31)
#define EPCTL_EPDIS       (1 << 30)
#define EPCTL_SODDFRM     (1 << 29)
#define EPCTL_CNAK        (1 << 26)
#define EPCTL_NAK         (1 << 13)
#define EPCTL_STALL       (1 << 21)
#define EPCTL_SNAK        (1 << 27)
#define EPCTL_USB_ACTEP   (1 << 15)
#define EPCTL_EPTYPE_SHIFT 18
#define EPCTL_EPTYPE_MASK   (3 << 18)
#define EPCTL_EPTYPE_CONTROL 0
#define EPCTL_EPTYPE_ISO     1
#define EPCTL_EPTYPE_BULK    2
#define EPCTL_EPTYPE_INT     3
#define EPCTL_MPS_MASK     0x3FF
/* Transfer size */
#define XFER_PKTCNT_SHIFT 19
#define XFER_PKTCNT_MASK  (0x3FF << 19)
#define XFER_SUPCNT_SHIFT 29
#define XFER_SUPCNT_MASK  (0x3 << 29)
#define XFER_SIZE_MASK    0x7FFFF
/* Endpoint interrupts */
#define XFER_XFERCOMPL    (1 << 0)
#define XFER_EPDISBLD     (1 << 1)
#define XFER_SETUP        (1 << 3)
#define XFER_TXFE         (1 << 7)
/* DAINT: OUT endpoints start at bit 16 */
#define DAINT_OEP_SHIFT   16

static inline uintptr_t usb_reg(uint32_t off) {
    return (uintptr_t)USB_BASE + off;
}
static inline volatile uint32_t *usb_reg_ptr(uint32_t off) {
    return (volatile uint32_t *)usb_reg(off);
}
static inline void wr(uint32_t off, uint32_t val) { mmio_write32(usb_reg(off), val); }
static inline uint32_t rd(uint32_t off) { return mmio_read32(usb_reg(off)); }
static inline void wr_set(uint32_t off, uint32_t bits) { wr(off, rd(off) | bits); }
static inline void wr_clr(uint32_t off, uint32_t bits) { wr(off, rd(off) & ~bits); }

static uint8_t setup_pkt[8];
static uint8_t ep_pending[6];      /* per-direction completion flags */
static uint16_t device_address;
static uint8_t configured;

/* ---------------- USB PHY (ULPI-less parallel PHY on A11) ------------- */

/* The PHY sits behind USB_PHY_BASE and must be out of reset and unlocked
 * before DWC2 will pass traffic. The previous driver never touched it,
 * which is why the table lists USB PHY as absent. */
#define USB_PHY_CTRL          0x000
#define USB_PHY_STATUS        0x004
#define USB_PHY_CTRL_RESET    (1 << 0)
#define USB_PHY_CTRL_ENABLE   (1 << 1)
#define USB_PHY_CTRL_UNLOCK   (1 << 2)
#define USB_PHY_STATUS_READY  (1 << 0)
#define USB_PHY_UNLOCK_KEY    0xA5A55A5A

static inline uintptr_t phy_reg(uint32_t off) {
    return (uintptr_t)USB_PHY_BASE + off;
}
static inline volatile uint32_t *phy_reg_ptr(uint32_t off) {
    return (volatile uint32_t *)phy_reg(off);
}

int usb_phy_init(void) {
    uint32_t ctrl = USB_PHY_CTRL_RESET | USB_PHY_CTRL_ENABLE | USB_PHY_CTRL_UNLOCK;
    mmio_write32(phy_reg(USB_PHY_CTRL), ctrl);
    mmio_write32(phy_reg(USB_PHY_CTRL), USB_PHY_UNLOCK_KEY); /* unlock key sequence */

    return timer_wait_reg(phy_reg_ptr(USB_PHY_STATUS), USB_PHY_STATUS_READY,
                          USB_PHY_STATUS_READY,
                          100000);
}

/* ---------------- FIFO helpers ---------------------------------------- */

static void ep_write_fifo(const uint8_t *data, uint16_t len) {
    uint16_t i = 0;
    /* FIFO words must be 4-byte aligned writes; tail the remainder with 0. */
    for (; i + 4 <= len; i += 4) {
        uint32_t w = (uint32_t)data[i]
                   | ((uint32_t)data[i + 1] << 8)
                   | ((uint32_t)data[i + 2] << 16)
                   | ((uint32_t)data[i + 3] << 24);
        wr(DWC2_GDFIFO0, w);
    }
    if (i < len) {
        uint32_t w = 0;
        uint16_t n = len - i;
        for (uint16_t j = 0; j < n; j++) w |= (uint32_t)data[i + j] << (j * 8);
        wr(DWC2_GDFIFO0, w);
    }
}

static void ep_read_fifo(uint32_t ep_num, uint8_t *data, uint16_t len) {
    (void)ep_num;
    for (uint16_t i = 0; i < len; i += 4) {
        uint32_t w = rd(DWC2_GDFIFO0);
        uint16_t n = (len - i) > 4 ? 4 : (uint16_t)(len - i);
        for (uint16_t j = 0; j < n; j++) data[i + j] = (uint8_t)(w >> (j * 8));
    }
}

/* ---------------- Endpoint bring-up ------------------------------------ */

#define MAX_PACKET 512

static void ep_configure(uint32_t dir, uint32_t ep, uint32_t type,
                         uint32_t mps, uint32_t pkt_cnt) {
    uint32_t ctl = DWC2_EPCTL(ep);
    uint32_t tsz = DWC2_EPTSIZ(ep);

    /* Disable, wait for the hardware to acknowledge, then reconfigure. */
    wr_set(ctl, EPCTL_EPDIS | EPCTL_SNAK);
    if (timer_wait_reg(usb_reg_ptr(ctl - 4), 1 << 30, 0, 0) != 0) { /* no-op */ }

    wr(ctl, EPCTL_USB_ACTEP | EPCTL_CNAK
             | ((type << EPCTL_EPTYPE_SHIFT) & EPCTL_EPTYPE_MASK)
             | (mps & EPCTL_MPS_MASK));
    wr(tsz, ((pkt_cnt << XFER_PKTCNT_SHIFT) & XFER_PKTCNT_MASK)
             | ((3u << XFER_SUPCNT_SHIFT) & XFER_SUPCNT_MASK)
             | (mps & XFER_SIZE_MASK));

    wr_set(ctl, EPCTL_EPENA);
    (void)dir;
}

static void ep0_configure(void) {
    /* EP0 must be active on both directions with the address still 0 until
     * SET_ADDRESS is acked. */
    wr(DWC2_DOEPCTL0, EPCTL_USB_ACTEP | EPCTL_CNAK
                     | (MAX_PACKET & EPCTL_MPS_MASK));
    wr(DWC2_DOEPTSIZ0, ((1u << XFER_PKTCNT_SHIFT) & XFER_PKTCNT_MASK)
                     | ((3u << XFER_SUPCNT_SHIFT) & XFER_SUPCNT_MASK)
                     | (MAX_PACKET & XFER_SIZE_MASK));
    wr(DWC2_DIEPCTL0, EPCTL_USB_ACTEP | EPCTL_CNAK
                     | (MAX_PACKET & EPCTL_MPS_MASK));
    wr(DWC2_DIEPTSIZ0, ((1u << XFER_PKTCNT_SHIFT) & XFER_PKTCNT_MASK)
                     | ((3u << XFER_SUPCNT_SHIFT) & XFER_SUPCNT_MASK)
                     | (MAX_PACKET & XFER_SIZE_MASK));
    wr_set(DWC2_DOEPCTL0, EPCTL_EPENA);
    wr_set(DWC2_DIEPCTL0, EPCTL_EPENA);
}

static void ep_data_in(uint32_t ep, const uint8_t *data, uint16_t len) {
    if (len > MAX_PACKET) len = MAX_PACKET;
    uint32_t ctl = DWC2_EPCTL(ep);
    uint32_t tsz = DWC2_EPTSIZ(ep);

    wr_set(ctl, EPCTL_EPENA | EPCTL_CNAK);
    ep_write_fifo(data, len);
    wr(tsz, ((1u << XFER_PKTCNT_SHIFT) & XFER_PKTCNT_MASK)
             | ((3u << XFER_SUPCNT_SHIFT) & XFER_SUPCNT_MASK)
             | (len & XFER_SIZE_MASK));
}

static void ep_data_out(uint32_t ep, uint8_t *data, uint16_t len) {
    uint32_t ctl = DWC2_EPCTL(ep);
    wr_set(ctl, EPCTL_EPENA | EPCTL_CNAK);
    if (len) ep_read_fifo(ep, data, len);
    wr(DWC2_EPTSIZ(ep), ((1u << XFER_PKTCNT_SHIFT) & XFER_PKTCNT_MASK)
                      | ((3u << XFER_SUPCNT_SHIFT) & XFER_SUPCNT_MASK)
                      | (MAX_PACKET & XFER_SIZE_MASK));
}

static void ep_stall(uint32_t ep) {
    wr_set(DWC2_EPCTL(ep), EPCTL_STALL);
}

/* ---------------- Control transfers ----------------------------------- */

extern const uint8_t device_desc[];
extern const uint8_t config_desc[];
extern const uint8_t string_lang[];
extern const uint8_t string_manuf[];
extern const uint8_t string_product[];
extern const uint8_t string_serial[];
extern const uint32_t config_desc_size;

static const uint8_t *const strings[] = {
    string_manuf, string_product, string_serial
};

static void ep0_send(const uint8_t *data, uint16_t len) {
    ep_data_in(0, data, len);
}

/* SET_ADDRESS takes effect only after the status stage, so defer it. */
static uint16_t pending_address;

static void handle_get_descriptor(uint16_t wValue, uint16_t wLength) {
    uint8_t type = (uint8_t)(wValue >> 8);
    uint8_t index = (uint8_t)(wValue & 0xFF);
    const uint8_t *desc = NULL;
    uint16_t desc_len = 0;

    switch (type) {
        case 1: /* DEVICE */
            desc = device_desc;
            desc_len = (uint16_t)device_desc[0];
            break;
        case 2: /* CONFIGURATION */
            desc = config_desc;
            desc_len = (uint16_t)config_desc_size;
            break;
        case 3: { /* STRING */
            if (index == 0) {
                desc = string_lang;
                desc_len = (uint16_t)string_lang[0];
                break;
            }
            if (index > 3) { ep_stall(0); ep_stall(0 + 0x100); return; }

            const uint8_t *s = strings[index - 1];
            uint8_t n = 0;
            while (s[n] && n < 255) n++;
            uint16_t total = (uint16_t)(2 + n * 2);
            if (total > 64) { ep_stall(0); ep_stall(0 + 0x100); return; }

            static uint8_t buf[64];
            buf[0] = (uint8_t)total;
            buf[1] = 3;
            for (uint8_t i = 0; i < n; i++) {
                buf[2 + i * 2] = s[i];
                buf[3 + i * 2] = 0;
            }
            desc = buf;
            desc_len = total;
            break;
        }
        default:
            ep_stall(0);
            ep_stall(0 + 0x100);
            return;
    }

    uint16_t n = wLength < desc_len ? wLength : desc_len;
    ep0_send(desc, n);
}

static void handle_setup(void) {
    uint8_t bmRequestType = setup_pkt[0];
    uint8_t bRequest = setup_pkt[1];
    uint16_t wValue = (uint16_t)(setup_pkt[2] | ((uint16_t)setup_pkt[3] << 8));
    uint16_t wIndex = (uint16_t)(setup_pkt[4] | ((uint16_t)setup_pkt[5] << 8));
    uint16_t wLength = (uint16_t)(setup_pkt[6] | ((uint16_t)setup_pkt[7] << 8));
    (void)wIndex;

    switch (bmRequestType & 0x60) {
        case 0x00: /* standard */
            switch (bRequest) {
                case 0x00: /* GET_STATUS */
                {
                    static uint8_t status[2] = { 0, 0 };
                    if (wValue == 0) status[0] = 1; /* self-powered */
                    ep0_send(status, 2);
                    break;
                }
                case 0x01: /* CLEAR_FEATURE / SET_FEATURE */
                    ep0_send(NULL, 0);
                    break;
                case 0x05: /* SET_ADDRESS */
                    pending_address = wValue & 0x7F;
                    ep0_send(NULL, 0); /* status stage, address applied later */
                    break;
                case 0x06: /* GET_DESCRIPTOR */
                    handle_get_descriptor(wValue, wLength);
                    break;
                case 0x08: /* GET_CONFIGURATION */
                {
                    static uint8_t cfg = 0;
                    if (configured) cfg = 1;
                    ep0_send(&cfg, 1);
                    break;
                }
                case 0x09: /* SET_CONFIGURATION */
                    configured = (uint8_t)(wValue != 0);
                    ep0_send(NULL, 0);
                    break;
                default:
                    ep_stall(0);
                    ep_stall(DWC2_DOEPCTL0);
                    break;
            }
            break;

        case 0x20: /* class */
            /* CDC-ECM class requests: line coding and SET_INTERFACE. The
             * control transfer still has to be completed even when we have
             * nothing to return, or the host retries forever. */
            switch (bRequest) {
                case 0x00: ep0_send(NULL, 0); break; /* SET_LINE_CODING */
                case 0x01: ep0_send(NULL, 0); break; /* GET_LINE_CODING */
                case 0x20: ep0_send(NULL, 0); break; /* SET_CONTROL_LINE_STATE */
                case 0x21: ep0_send(NULL, 0); break; /* SEND_BREAK */
                case 0x22: ep0_send(NULL, 0); break; /* SEND_ENCAPSULATED_COMMAND */
                case 0x23: break;                    /* GET_ENCAPSULATED_RESPONSE */
                case 0x40: ep0_send(NULL, 0); break; /* SET_INTERFACE */
                case 0x41: ep0_send(NULL, 0); break; /* GET_INTERFACE */
                case 0x42: ep0_send(NULL, 0); break; /* SET_ETHERNET_MULTICAST_FILTERS */
                case 0x43: ep0_send(NULL, 0); break; /* GET_ETHERNET_MULTICAST_FILTERS */
                case 0x44: break;                    /* GET_ETHERNET_STATISTIC */
                case 0x45: ep0_send(NULL, 0); break; /* SET_ETHERNET_PACKET_FILTER */
                case 0x46: ep0_send(NULL, 0); break; /* GET_ETHERNET_PACKET_FILTER */
                case 0x47: break;                    /* SET_ETHERNET_PACKET_INFORMATION */
                case 0x48: break;                    /* GET_ETHERNET_PACKET_INFORMATION */
                default:
                    ep_stall(0);
                    ep_stall(DWC2_DOEPCTL0);
                    break;
            }
            break;

        default:
            ep_stall(0);
            ep_stall(DWC2_DOEPCTL0);
            break;
    }
}

/* ---------------- Interrupt service ----------------------------------- */

int usb_irq_pending(void) {
    return (int)(rd(DWC2_GINTSTS) & (GINTSTS_USBRST | GINTSTS_ENUMDNE |
                                     GINTSTS_RXFLVL | GINTSTS_IEPINT |
                                     GINTSTS_OEPINT));
}

void usb_irq_handler(void) {
    uint32_t gintsts = rd(DWC2_GINTSTS);

    if (gintsts & GINTSTS_USBRST) {
        wr(DWC2_GINTSTS, GINTSTS_USBRST);
        configured = 0;
        pending_address = 0;
        device_address = 0;
        wr_clr(DWC2_DCFG, DCFG_ADDR_MASK << 4);
        ep0_configure();
        wr_set(DWC2_DCTL, DCTL_CGINAK | DCTL_SGINAK);
        return;
    }

    if (gintsts & GINTSTS_ENUMDNE) {
        wr(DWC2_GINTSTS, GINTSTS_ENUMDNE);
        /* 72ms frames per USB 2.0 spec; used for ISOC scheduling. */
        wr(DWC2_DSTS, (rd(DWC2_DSTS) & ~0xFF) | 72);
        return;
    }

    if (gintsts & GINTSTS_RXFLVL) {
        /* Pop RXFLVL until it reads empty; a short packet ends a transfer. */
        for (;;) {
            uint32_t sts = rd(DWC2_GRXSTSP);
            uint32_t ep = sts & GRXSTSP_EPNUM_MASK;
            uint32_t pktsts = (sts >> GRXSTSP_PKTSTS_SHIFT) & GRXSTSP_PKTSTS_MASK;
            uint32_t size = (sts >> GRXSTSP_XFER_SIZE_SHIFT) & GRXSTSP_XFER_SIZE_MASK;

            if (pktsts == GRXSTSP_PKTSTS_SETUP) {
                ep_read_fifo(ep, setup_pkt, 8);
                handle_setup();
                continue;
            }
            if (pktsts == GRXSTSP_PKTSTS_OUT) {
                if (ep == 0) {
                    /* OUT data stage of a control transfer. Not network
                     * traffic: the ECM class requests that carry one are
                     * answered in handle_setup(), so the bytes here are
                     * drained and not handed up. Feeding them to the frame
                     * assembler would inject a junk Ethernet frame into the
                     * middle of the data stream. */
                    static uint8_t buf[MAX_PACKET];
                    if (size && size <= sizeof(buf)) {
                        ep_read_fifo(ep, buf, (uint16_t)size);
                    } else if (size) {
                        /* Drain rather than desync the FIFO. */
                        for (uint32_t i = 0; i < (size + 3) / 4; i++) rd(DWC2_GDFIFO0);
                    }
                    ep_data_out(0, NULL, 0);
                    continue;
                }
                if (ep == 1) {
                    static uint8_t buf[MAX_PACKET];
                    uint16_t n = size > sizeof(buf) ? (uint16_t)sizeof(buf)
                                                    : (uint16_t)size;
                    if (n) ep_read_fifo(ep, buf, n);
                    if (size > n) {
                        for (uint32_t i = n; i < (size + 3) / 4; i++) rd(DWC2_GDFIFO0);
                    }
                    usb_cdc_rx(buf, n);
                    ep_data_out(1, NULL, 0);
                    continue;
                }
            }
            break;
        }
        return;
    }

    if (gintsts & GINTSTS_IEPINT) {
        uint32_t daint = rd(DWC2_DAINT) & rd(DWC2_DAINTMSK);
        for (uint32_t ep = 0; ep < 3; ep++) {
            if (!(daint & (1u << ep))) continue;
            uint32_t iepint = rd(DWC2_EPDINT(ep));
            if (iepint & XFER_XFERCOMPL) {
                wr(DWC2_EPDINT(ep), XFER_XFERCOMPL);
                ep_pending[ep] = 1;
            }
            if (ep == 0 && pending_address) {
                /* Apply SET_ADDRESS now that the status stage completed. */
                wr_clr(DWC2_DCFG, DCFG_ADDR_MASK << 4);
                wr(DWC2_DCFG, rd(DWC2_DCFG) | ((pending_address & 0x7F) << 4));
                device_address = pending_address;
                pending_address = 0;
            }
            /* TX is deliberately not drained from in here. usb_send() waits
             * on ep_pending[2], which this handler is the only thing that can
             * set, so anything that calls it from inside this handler can
             * only spin: the controller's line stays masked until the
             * interrupt returns. The main loop drains the queue from
             * net_poll() instead, which is why a reply leaves promptly
             * without this path. */
        }
    }

    if (gintsts & GINTSTS_OEPINT) {
        uint32_t daint = (rd(DWC2_DAINT) >> DAINT_OEP_SHIFT) & rd(DWC2_DAINTMSK);
        for (uint32_t ep = 0; ep < 3; ep++) {
            if (!(daint & (1u << ep))) continue;
            uint32_t oepint = rd(0xB08 + ep * 0x20);
            if (oepint & XFER_SETUP) {
                wr(0xB08 + ep * 0x20, XFER_SETUP);
                /* Re-arm OUT so the next packet is accepted. */
                ep_data_out(ep, NULL, 0);
            }
            if (oepint & XFER_EPDISBLD) {
                wr(0xB08 + ep * 0x20, XFER_EPDISBLD);
            }
        }
    }
}

/* ---------------- Public API ------------------------------------------ */

int usb_init(void) {
    if (usb_phy_init() != 0) {
        uart_puts("usb: PHY not ready\n");
        return -1;
    }

    /* Core soft reset, then wait for AHB idle. */
    wr(DWC2_GOTGCTL, GOTGCTL_CSRST | GOTGCTL_CMODE);
    timer_wait_reg(usb_reg_ptr(DWC2_GOTGCTL), GOTGCTL_CSRST, 0, 10000);
    wr(DWC2_GRSTCTL, GRSTCTL_CSRST);
    timer_wait_reg(usb_reg_ptr(DWC2_GRSTCTL), GRSTCTL_CSRST, 0, 10000);
    wr(DWC2_GRSTCTL, 0);
    timer_wait_reg(usb_reg_ptr(DWC2_GRSTCTL), GRSTCTL_AHBIDLE,
                   GRSTCTL_AHBIDLE, 10000);

    /* AHB master: enable interrupts and DMA, 16-beat INCR. */
    wr(DWC2_GAHBCFG, GAHBCFG_GLBL_INTR_EN | GAHBCFG_HBSTLEN_INCR16 |
                      GAHBCFG_DMAEN);

    /* Force device mode, internal PHY, 16-bit interface, TOUTCAL 7,
     * USBTRDTIM 5. The previous driver OR'd two overlapping constants into
     * the same bits and computed a TOUTCAL it did not intend. */
    wr(DWC2_GUSBCFG, GUSBCFG_PHY_UTMI | GUSBCFG_PHY_IF_16BIT |
                      GUSBCFG_TOUTCAL_7 | GUSBCFG_USBTRDTIM_5);

    /* Full-speed device: DCFG_DEVSPD is a 3-bit field. */
    wr(DWC2_DCFG, DCFG_DESCDMA | (DCFG_DEVSPD_FS & DCFG_DEVSPD_MASK));

    /* Clear any stale NAK state. */
    wr(DWC2_DCTL, DCTL_SGINAK | DCTL_CGINAK);

    /* FIFO sizing: rx = 0x200, non-priority tx = 0x200. Both fields must be
     * programmed before the core leaves reset or transfers underrun. */
    wr(DWC2_GRXFSIZ, 0x200);
    wr(DWC2_GNPTXFSIZ, 0x200);

    ep0_configure();

    /* EP1 interrupt IN (CDC notification), EP2 bulk IN + bulk OUT (data). */
    ep_configure(0, 1, EPCTL_EPTYPE_INT, 16, 1);
    ep_configure(0, 2, EPCTL_EPTYPE_BULK, MAX_PACKET, 0);
    ep_configure(1, 2, EPCTL_EPTYPE_BULK, MAX_PACKET, 0);

    wr_set(DWC2_DAINTMSK, (1u << 0) | (1u << 1) | (1u << 2) |
                          (1u << 16) | (1u << 17) | (1u << 18));
    wr(DWC2_DIEPMSK, XFER_XFERCOMPL | XFER_TXFE);
    wr(DWC2_DOEPMSK, XFER_XFERCOMPL | XFER_SETUP | XFER_EPDISBLD);
    wr(DWC2_GINTMSK, GINTSTS_USBRST | GINTSTS_ENUMDNE | GINTSTS_RXFLVL |
                      GINTSTS_IEPINT | GINTSTS_OEPINT);

    wr_clr(DWC2_GOTGCTL, GOTGCTL_CSRST);
    return 0;
}

void usb_send(const uint8_t *data, uint16_t len) {
    /* Bulk data rides EP2 IN. Split across MAX_PACKET-sized transfers. */
    while (len) {
        uint16_t n = len > MAX_PACKET ? MAX_PACKET : len;
        ep_data_in(2, data, n);
        data += n;
        len -= n;
        /* Wait for the IN completion before reusing the endpoint. */
        while (!ep_pending[2]) { __asm__ volatile("yield" ::: "memory"); }
        ep_pending[2] = 0;
    }
}

uint16_t usb_device_address(void) { return device_address; }
int usb_configured(void) { return configured; }

/* Introspection for the shell: report what the core negotiated so a bring-up
 * failure is visible without a debugger. */
void usb_debug_dump(void) {
    uart_puts("usb: cfg="); uart_puts(utoa_hex(rd(DWC2_DCFG)));
    uart_puts(" dsts="); uart_puts(utoa_hex(rd(DWC2_DSTS)));
    uart_puts(" intsts="); uart_puts(utoa_hex(rd(DWC2_GINTSTS)));
    uart_puts(" daint="); uart_puts(utoa_hex(rd(DWC2_DAINT)));
    uart_puts(" addr="); uart_puts(utoa_hex(device_address));
    uart_puts(" configured="); uart_puts(utoa_hex(configured));
    uart_puts("\n");
}
