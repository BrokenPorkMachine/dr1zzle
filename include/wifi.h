#ifndef WIFI_H
#define WIFI_H

#include <stdint.h>
#include <stddef.h>

typedef enum {
    WIFI_DOWN = 0,
    WIFI_NO_TRANSPORT,
    WIFI_READY,
    WIFI_SCANNING,
    WIFI_ASSOCIATING,
    WIFI_ASSOCIATED,
    WIFI_ERROR
} wifi_state_t;

typedef struct {
    char ssid[33];
    uint8_t bssid[6];
    uint8_t channel;
    int8_t rssi;
    uint8_t security;
} wifi_ap_t;

void wifi_init(void);
void wifi_scan(int noauto);
void wifi_display_networks(void);
void wifi_select(uint8_t index);
void wifi_connect(const char *ssid, const char *pass);
void wifi_disconnect(void);
void wifi_dhcp(void);
void wifi_status(void);
wifi_state_t wifi_state(void);
const char *wifi_backend_name(void);
void wifi_auto_connect(const char *mode);  /* "on" or "off" */
void wifi_auto_connect_open(void);

/* Helper functions for shell integration */
uint8_t wifi_get_scan_count(void);
const wifi_ap_t *wifi_get_ap(uint8_t index);

#endif
