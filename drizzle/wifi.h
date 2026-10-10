#ifndef DRIZZLE_WIFI_H
#define DRIZZLE_WIFI_H

#include <stddef.h>
#include <stdint.h>
#include <drizzle/net.h>

/*
 * Wi-Fi is deliberately split into a small policy/state layer and a
 * chip-specific transport.  The latter is where an SDIO, PCIe, or SPI radio
 * driver belongs.  Keeping that contract here prevents the IP stack from
 * depending on a particular Broadcom/Apple register map.
 */

#define DR1ZZLE_WIFI_SSID_MAX 32u
#define DR1ZZLE_WIFI_PASSPHRASE_MAX 63u
#define DR1ZZLE_WIFI_BSSID_LEN 6u
#define DR1ZZLE_WIFI_MAX_SCAN_RESULTS 16u

typedef enum {
    DR1ZZLE_WIFI_DOWN = 0,
    DR1ZZLE_WIFI_READY,
    DR1ZZLE_WIFI_SCANNING,
    DR1ZZLE_WIFI_ASSOCIATING,
    DR1ZZLE_WIFI_ASSOCIATED,
    DR1ZZLE_WIFI_ERROR
} drizzle_wifi_state_t;

typedef struct {
    char ssid[DR1ZZLE_WIFI_SSID_MAX + 1u];
    uint8_t bssid[DR1ZZLE_WIFI_BSSID_LEN];
    uint8_t channel;
    int8_t rssi_dbm;
    uint8_t security; /* backend-defined; zero means open */
} drizzle_wifi_scan_result_t;

typedef struct drizzle_wifi_backend {
    const char *name;
    /* Start/stop own the radio and return zero on success.  start() must fill
     * a stable locally-administered MAC address in `mac`. */
    int (*start)(void *context, uint8_t mac[DR1ZZLE_MAC_LEN]);
    void (*stop)(void *context);
    int (*scan)(void *context, drizzle_wifi_scan_result_t *results,
                size_t capacity, size_t *count);
    int (*connect)(void *context, const char *ssid, const char *passphrase);
    int (*disconnect)(void *context);
    int (*transmit)(void *context, const uint8_t *frame, size_t length);
    void (*poll)(void *context);
} drizzle_wifi_backend_t;

void drizzle_wifi_reset(void);
int drizzle_wifi_bind(const drizzle_wifi_backend_t *backend, void *context);
int drizzle_wifi_start(void);
int drizzle_wifi_scan(drizzle_wifi_scan_result_t *results, size_t capacity,
                      size_t *count);
int drizzle_wifi_connect(const char *ssid, const char *passphrase);
int drizzle_wifi_disconnect(void);
void drizzle_wifi_poll(void);

drizzle_wifi_state_t drizzle_wifi_state(void);
const char *drizzle_wifi_backend_name(void);
const uint8_t *drizzle_wifi_mac(void);
const drizzle_link_t *drizzle_wifi_link(void);

/* Called by a hardware backend from its poll/interrupt path. */
void drizzle_wifi_receive_frame(const uint8_t *frame, size_t length);

#endif
