#include "wifi.h"
#include "uart.h"
#include "util.h"
#include "memory_map.h"

#define WIFI_BASE 0x20A170000

static volatile uint32_t *wifi = (volatile uint32_t *)WIFI_BASE;

static inline uint32_t wifi_read(uint32_t offset) {
    return wifi[offset / 4];
}

static inline void wifi_write(uint32_t offset, uint32_t val) {
    wifi[offset / 4] = val;
}

void wifi_init(void) {
    uart_puts("Initializing WiFi (Broadcom BCM43xx)...\n");
    
    /* Reset WiFi controller */
    wifi_write(0x00, 0x1); /* Reset */
    timer_sleep_ms(10);
    
    /* Check chip ID */
    uint32_t chip_id = wifi_read(0x10);
    uart_puts("WiFi Chip ID: 0x"); uart_puts(utoa_hex(chip_id)); uart_puts("\n");
    
    /* Initialize firmware */
    uart_puts("WiFi firmware loading not implemented\n");
}

void wifi_scan(void) {
    uart_puts("Scanning for networks...\n");
    /* Not implemented - requires firmware */
}

void wifi_connect(const char *ssid, const char *pass) {
    uart_puts("Connecting to "); uart_puts(ssid); uart_puts("\n");
    /* Not implemented */
}

void wifi_status(void) {
    uint32_t status = wifi_read(0x04);
    uart_puts("WiFi Status: 0x"); uart_puts(utoa_hex(status)); uart_puts("\n");
}
