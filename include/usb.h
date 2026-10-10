#ifndef USB_H
#define USB_H

#include <stdint.h>

#define USB_MAX_PACKET 512

/* AIC line the AP side routes the DWC2 core to. Supplied by the SoC profile
 * (apple,t8015-usb gives otg_irq = 324 on A11). A wrong line costs an
 * unclaimed IRQ, not a crash. */
#define AIC_IRQ_USB_OTG SOC_IRQ_USB_OTG

int  usb_init(void);
void usb_irq_handler(void);

/* Non-zero when the core has an unmasked condition waiting. */
int  usb_irq_pending(void);

/* Bulk OUT frames from the host (CDC-ECM). Implemented by the protocol
 * layer, not the core. */
void usb_cdc_rx(const uint8_t *data, uint16_t len);

/* Hands buffered frames to the network stack. Main-loop only: the stack's
 * segment buffers are statics, and the interrupt path must not reach them. */
void usb_cdc_service(void);

/* Called from the IN-complete path so the protocol layer can push queued
 * frames. */
void usb_cdc_tx_pending(void);

void usb_send(const uint8_t *data, uint16_t len);

uint16_t usb_device_address(void);
int  usb_configured(void);

/* Core register dump for bring-up debugging. */
void usb_debug_dump(void);

/* CDC-ECM protocol layer (cdc_ecm.c) */
void usb_cdc_tx_queue(const uint8_t *data, uint16_t len);
uint16_t usb_cdc_last_frame(uint8_t *out, uint16_t max);
uint32_t usb_cdc_rx_dropped(void);

#endif /* USB_H */