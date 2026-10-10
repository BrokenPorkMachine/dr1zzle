#include <drizzle/wifi.h>
#include <string.h>

static const drizzle_link_t *bound_link;
static uint8_t bound_mac[DR1ZZLE_MAC_LEN];
static size_t received_length;

void drizzle_net_set_link(const drizzle_link_t *link) { bound_link = link; }
void drizzle_net_set_mac(const uint8_t mac[DR1ZZLE_MAC_LEN]) {
    memcpy(bound_mac, mac, DR1ZZLE_MAC_LEN);
}
void drizzle_net_receive(const uint8_t *frame, size_t length) {
    (void)frame;
    received_length = length;
}

typedef struct {
    int started;
    int associated;
    size_t tx_length;
    uint8_t mac[DR1ZZLE_MAC_LEN];
} fake_radio_t;

static int fake_start(void *context, uint8_t mac[DR1ZZLE_MAC_LEN]) {
    fake_radio_t *radio = context;
    radio->started = 1;
    memcpy(mac, radio->mac, DR1ZZLE_MAC_LEN);
    return 0;
}
static void fake_stop(void *context) { ((fake_radio_t *)context)->started = 0; }
static int fake_scan(void *context, drizzle_wifi_scan_result_t *results,
                     size_t capacity, size_t *count) {
    (void)context;
    if (capacity == 0u) return 0;
    memcpy(results[0].ssid, "dr1zzle-test", sizeof "dr1zzle-test");
    results[0].channel = 6u;
    results[0].rssi_dbm = -42;
    results[0].security = 1u;
    *count = 1u;
    return 0;
}
static int fake_connect(void *context, const char *ssid, const char *passphrase) {
    fake_radio_t *radio = context;
    if (strcmp(ssid, "dr1zzle-test") || strcmp(passphrase, "correct horse")) return -1;
    radio->associated = 1;
    return 0;
}
static int fake_disconnect(void *context) {
    ((fake_radio_t *)context)->associated = 0;
    return 0;
}
static int fake_transmit(void *context, const uint8_t *frame, size_t length) {
    fake_radio_t *radio = context;
    if (!radio->associated || !frame || !length) return -1;
    radio->tx_length = length;
    return 0;
}
static void fake_poll(void *context) {
    static const uint8_t frame[64] = {0};
    if (((fake_radio_t *)context)->associated) drizzle_wifi_receive_frame(frame, sizeof frame);
}

static const drizzle_wifi_backend_t fake_backend = {
    "fake-sdio", fake_start, fake_stop, fake_scan, fake_connect,
    fake_disconnect, fake_transmit, fake_poll
};

int main(void) {
    fake_radio_t radio = {0, 0, 0, {0x02u, 0xd1u, 0x7au, 0x01u, 0x02u, 0x03u}};
    drizzle_wifi_scan_result_t result[1];
    size_t count = 0u;
    const uint8_t frame[60] = {0};

    drizzle_wifi_reset();
    if (drizzle_wifi_bind(&fake_backend, &radio) != 0) return 1;
    if (drizzle_wifi_start() != 0 || drizzle_wifi_state() != DR1ZZLE_WIFI_READY) return 2;
    if (bound_link != 0 || drizzle_wifi_link() != 0 || strcmp(drizzle_wifi_backend_name(), "fake-sdio")) return 3;
    if (memcmp(bound_mac, radio.mac, DR1ZZLE_MAC_LEN) != 0) return 4;
    if (drizzle_wifi_scan(result, 1u, &count) != 0 || count != 1u ||
        strcmp(result[0].ssid, "dr1zzle-test")) return 5;
    if (drizzle_wifi_connect("dr1zzle-test", "correct horse") != 0 ||
        drizzle_wifi_state() != DR1ZZLE_WIFI_ASSOCIATED) return 6;
    if (!bound_link || bound_link != drizzle_wifi_link()) return 7;
    bound_link->transmit(frame, sizeof frame);
    if (radio.tx_length != sizeof frame) return 8;
    drizzle_wifi_poll();
    if (received_length != 64u) return 9;
    if (drizzle_wifi_disconnect() != 0 || drizzle_wifi_state() != DR1ZZLE_WIFI_READY || bound_link != 0) return 10;
    drizzle_wifi_reset();
    if (drizzle_wifi_state() != DR1ZZLE_WIFI_DOWN || drizzle_wifi_link() != 0) return 11;
    return 0;
}
