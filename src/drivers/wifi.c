#include "wifi.h"
#include "uart.h"
#include "util.h"
#include "timer.h"
#include "memory_map.h"
#include "string.h"

/*
 * WiFi driver for Broadcom BCM4357 on A11.
 * This implementation provides a functional WiFi menu system.
 * When real BCM4357 firmware/backend is available, the scan/connect functions
 * will be replaced with actual hardware operations.
 */

static wifi_state_t state = WIFI_DOWN;
static wifi_ap_t scan_results[16];
static uint8_t scan_count = 0;
static uint8_t current_ap = 0;
static int auto_connect_enabled = 1;  /* Auto-connect to strongest open network by default */

/* Simulated AP list for demonstration - replaced by real scan when backend available */
static const wifi_ap_t demo_aps[] = {
    {"AppleStore", {0x00,0x11,0x22,0x33,0x44,0x55}, 1, -45, 3},
    {"HomeWiFi", {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF}, 6, -52, 3},
    {"GuestNetwork", {0x11,0x22,0x33,0x44,0x55,0x66}, 11, -67, 0},
    {"CorporateWiFi", {0x22,0x33,0x44,0x55,0x66,0x77}, 36, -58, 4},
    {"IoT_Network", {0x33,0x44,0x55,0x66,0x77,0x88}, 44, -71, 2},
    {"TestAP", {0x44,0x55,0x66,0x77,0x88,0x99}, 149, -79, 3},
};

void wifi_init(void) {
    state = WIFI_READY;
    scan_count = 0;
    current_ap = 0;
    uart_puts("wifi: WiFi subsystem initialized\n");
    uart_puts("wifi: Type 'wifi scan' to discover networks\n");
}

void wifi_scan(int noauto) {
    if (state == WIFI_DOWN) {
        uart_puts("wifi: not initialized - run 'wifi init' first\n");
        return;
    }
    
    state = WIFI_SCANNING;
    uart_puts("wifi: scanning for networks...\n");
    
    /* In real implementation, this would trigger hardware scan via BCM4357 firmware */
    /* For now, populate with demo APs to show menu functionality */
    scan_count = sizeof(demo_aps) / sizeof(demo_aps[0]);
    for (uint8_t i = 0; i < scan_count; i++) {
        scan_results[i] = demo_aps[i];
    }
    
    state = WIFI_READY;
    uart_puts("wifi: scan complete - ");
    uart_puts(utoa(scan_count));
    uart_puts(" networks found\n");
    
    /* Auto-display results */
    wifi_display_networks();
    
    /* Auto-connect to strongest open network unless disabled or noauto requested */
    if (auto_connect_enabled && !noauto) {
        wifi_auto_connect_open();
    }
}

void wifi_auto_connect(const char *mode) {
    if (strcmp(mode, "on") == 0) {
        auto_connect_enabled = 1;
        uart_puts("wifi: auto-connect enabled\n");
    } else if (strcmp(mode, "off") == 0) {
        auto_connect_enabled = 0;
        uart_puts("wifi: auto-connect disabled\n");
    } else {
        uart_puts("wifi: auto-connect is ");
        uart_puts(auto_connect_enabled ? "enabled" : "disabled");
        uart_puts("\n");
    }
}

void wifi_auto_connect_open(void) {
    if (state != WIFI_READY || scan_count == 0) return;
    
    /* Find strongest open network (security == 0, highest RSSI) */
    int8_t best_rssi = -128;
    uint8_t best_idx = 0;
    int found_open = 0;
    
    for (uint8_t i = 0; i < scan_count; i++) {
        if (scan_results[i].security == 0 && scan_results[i].rssi > best_rssi) {
            best_rssi = scan_results[i].rssi;
            best_idx = i;
            found_open = 1;
        }
    }
    
    if (found_open) {
        uart_puts("wifi: auto-connecting to strongest open network: ");
        uart_puts(scan_results[best_idx].ssid);
        uart_puts(" (RSSI: ");
        uart_puts(utoa(best_rssi < 0 ? -best_rssi : best_rssi));
        uart_puts("dBm)\n");
        
        current_ap = best_idx;
        wifi_connect(scan_results[best_idx].ssid, "");
    }
}

void wifi_display_networks(void) {
    if (scan_count == 0) {
        uart_puts("wifi: no networks scanned yet - run 'wifi scan'\n");
        return;
    }
    
    uart_puts("\n=== Available WiFi Networks ===\n");
    uart_puts(" #  SSID                 BSSID              CH  RSSI  SEC\n");
    uart_puts("---- -------------------- ----------------- -- ----- ----\n");
    
    for (uint8_t i = 0; i < scan_count; i++) {
        const wifi_ap_t *ap = &scan_results[i];
        
        uart_puts(i == current_ap ? "> " : "  ");
        if (i < 10) uart_puts(" ");
        uart_puts(utoa(i));
        uart_puts(" ");
        
        /* SSID (padded to 20 chars) */
        uart_puts(ap->ssid);
        for (uint8_t j = strlen(ap->ssid); j < 20; j++) uart_puts(" ");
        
        /* BSSID */
        for (uint8_t j = 0; j < 6; j++) {
            uart_puts(utoa_hex(ap->bssid[j]));
            if (j < 5) uart_puts(":");
        }
        uart_puts("  ");
        
        /* Channel */
        uart_puts(utoa(ap->channel));
        uart_puts(ap->channel < 10 ? "   " : "  ");
        
        /* RSSI */
        if (ap->rssi < 0) uart_puts("-");
        uart_puts(utoa(ap->rssi < 0 ? -ap->rssi : ap->rssi));
        uart_puts("dBm ");
        
        /* Security */
        const char *sec_str[] = {"OPEN", "WEP ", "WPA ", "WPA2", "WPA3"};
        uart_puts(sec_str[ap->security > 4 ? 0 : ap->security]);
        uart_puts("\n");
    }
    uart_puts("================================\n");
    uart_puts("Use 'wifi select <num>' to choose, 'wifi connect <pass>' to join\n\n");
}

void wifi_select(uint8_t index) {
    if (index >= scan_count) {
        uart_puts("wifi: invalid selection\n");
        return;
    }
    current_ap = index;
    uart_puts("wifi: selected ");
    uart_puts(scan_results[index].ssid);
    uart_puts("\n");
}

void wifi_connect(const char *ssid, const char *pass) {
    (void)pass;
    
    if (state == WIFI_DOWN) {
        uart_puts("wifi: not initialized - run 'wifi init' first\n");
        return;
    }
    
    if (scan_count == 0) {
        uart_puts("wifi: no networks available - run 'wifi scan' first\n");
        return;
    }
    
    /* Find AP by SSID if provided, otherwise use selected */
    wifi_ap_t *target = NULL;
    if (ssid && *ssid) {
        for (uint8_t i = 0; i < scan_count; i++) {
            if (strcmp(scan_results[i].ssid, ssid) == 0) {
                target = &scan_results[i];
                current_ap = i;
                break;
            }
        }
        if (!target) {
            uart_puts("wifi: network not found in scan results\n");
            return;
        }
    } else {
        target = &scan_results[current_ap];
    }
    
    state = WIFI_ASSOCIATING;
    uart_puts("wifi: connecting to ");
    uart_puts(target->ssid);
    uart_puts("...\n");
    
    /* In real implementation: 
     * 1. Send association request via BCM4357 firmware
     * 2. Perform 4-way handshake for WPA2/WPA3
     * 3. Configure encryption keys
     * 4. Set up data path
     */
    
    /* Simulate connection */
    timer_sleep_ms(500);
    
    state = WIFI_ASSOCIATED;
    uart_puts("wifi: connected to ");
    uart_puts(target->ssid);
    uart_puts(" (BSSID: ");
    for (uint8_t i = 0; i < 6; i++) {
        uart_puts(utoa_hex(target->bssid[i]));
        if (i < 5) uart_puts(":");
    }
    uart_puts(")\n");
    uart_puts("wifi: Use 'wifi dhcp' to obtain IP address\n");
}

void wifi_disconnect(void) {
    if (state != WIFI_ASSOCIATED) {
        uart_puts("wifi: not connected\n");
        return;
    }
    
    uart_puts("wifi: disconnecting...\n");
    state = WIFI_READY;
    uart_puts("wifi: disconnected\n");
}

void wifi_dhcp(void) {
    if (state != WIFI_ASSOCIATED) {
        uart_puts("wifi: not connected - run 'wifi connect' first\n");
        return;
    }
    
    uart_puts("wifi: requesting DHCP lease...\n");
    
    /* In real implementation: send DHCP discover, handle offer/request/ack */
    /* For demo, assign a static IP in WiFi subnet */
    timer_sleep_ms(300);
    
    uart_puts("wifi: DHCP lease obtained\n");
    uart_puts("wifi: IP: 192.168.1.100\n");
    uart_puts("wifi: Netmask: 255.255.255.0\n");
    uart_puts("wifi: Gateway: 192.168.1.1\n");
    uart_puts("wifi: DNS: 192.168.1.1\n");
}

void wifi_status(void) {
    const char *state_str[] = {
        "DOWN", "NO_TRANSPORT", "READY", "SCANNING", 
        "ASSOCIATING", "ASSOCIATED", "ERROR"
    };
    
    uart_puts("wifi: state=");
    uart_puts(state_str[state]);
    
    if (state == WIFI_ASSOCIATED && scan_count > 0) {
        uart_puts(" ssid=");
        uart_puts(scan_results[current_ap].ssid);
        uart_puts(" rssi=");
        uart_puts(utoa(scan_results[current_ap].rssi));
        uart_puts("dBm");
    }
    uart_puts("\n");
    
    if (scan_count > 0) {
        uart_puts("wifi: ");
        uart_puts(utoa(scan_count));
        uart_puts(" networks in scan cache\n");
    }
}

wifi_state_t wifi_state(void) { return state; }
const char *wifi_backend_name(void) { return "bcm4357-stub"; }

/* Helper for shell */
uint8_t wifi_get_scan_count(void) { return scan_count; }
const wifi_ap_t *wifi_get_ap(uint8_t index) { 
    if (index < scan_count) return &scan_results[index];
    return 0;
}