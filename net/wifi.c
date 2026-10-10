#include <drizzle/wifi.h>
#include <string.h>

static const drizzle_wifi_backend_t *active_backend;
static void *active_context;
static drizzle_wifi_state_t state = DR1ZZLE_WIFI_DOWN;
static uint8_t local_mac[DR1ZZLE_MAC_LEN];

static void wifi_transmit(const uint8_t *frame, size_t length) {
    if (!active_backend || !active_backend->transmit ||
        state != DR1ZZLE_WIFI_ASSOCIATED ||
        active_backend->transmit(active_context, frame, length) != 0) {
        /* A link with no backend is intentionally fail-closed. */
    }
}

static void wifi_receive(void) {
    if (active_backend && active_backend->poll &&
        state != DR1ZZLE_WIFI_DOWN && state != DR1ZZLE_WIFI_ERROR) {
        active_backend->poll(active_context);
    }
}

static const drizzle_link_t link = { wifi_transmit, wifi_receive, "wifi" };

void drizzle_wifi_reset(void) {
    if (active_backend && active_backend->stop && state != DR1ZZLE_WIFI_DOWN) {
        active_backend->stop(active_context);
    }
    active_backend = NULL;
    active_context = NULL;
    state = DR1ZZLE_WIFI_DOWN;
    memset(local_mac, 0, sizeof local_mac);
    drizzle_net_set_link(NULL);
}

int drizzle_wifi_bind(const drizzle_wifi_backend_t *backend, void *context) {
    if (!backend || !backend->start || !backend->stop || !backend->scan ||
        !backend->connect || !backend->disconnect || !backend->transmit) {
        return -1;
    }
    if (state != DR1ZZLE_WIFI_DOWN) return -1;
    active_backend = backend;
    active_context = context;
    return 0;
}

int drizzle_wifi_start(void) {
    if (!active_backend || state != DR1ZZLE_WIFI_DOWN) return -1;
    if (active_backend->start(active_context, local_mac) != 0) {
        state = DR1ZZLE_WIFI_ERROR;
        return -1;
    }
    state = DR1ZZLE_WIFI_READY;
    drizzle_net_set_mac(local_mac);
    return 0;
}

int drizzle_wifi_scan(drizzle_wifi_scan_result_t *results, size_t capacity,
                      size_t *count) {
    if (count) *count = 0u;
    if (!active_backend || state != DR1ZZLE_WIFI_READY ||
        (!results && capacity)) return -1;
    state = DR1ZZLE_WIFI_SCANNING;
    int result = active_backend->scan(active_context, results, capacity, count);
    state = result == 0 ? DR1ZZLE_WIFI_READY : DR1ZZLE_WIFI_ERROR;
    return result;
}

int drizzle_wifi_connect(const char *ssid, const char *passphrase) {
    size_t ssid_length;
    size_t pass_length;
    if (!active_backend || state != DR1ZZLE_WIFI_READY || !ssid || !passphrase) return -1;
    ssid_length = strlen(ssid);
    pass_length = strlen(passphrase);
    if (ssid_length == 0u || ssid_length > DR1ZZLE_WIFI_SSID_MAX ||
        pass_length > DR1ZZLE_WIFI_PASSPHRASE_MAX) return -1;
    state = DR1ZZLE_WIFI_ASSOCIATING;
    int result = active_backend->connect(active_context, ssid, passphrase);
    state = result == 0 ? DR1ZZLE_WIFI_ASSOCIATED : DR1ZZLE_WIFI_READY;
    if (result == 0) drizzle_net_set_link(&link);
    return result;
}

int drizzle_wifi_disconnect(void) {
    if (!active_backend ||
        (state != DR1ZZLE_WIFI_ASSOCIATED && state != DR1ZZLE_WIFI_READY)) return -1;
    int result = active_backend->disconnect(active_context);
    if (result == 0) {
        state = DR1ZZLE_WIFI_READY;
        drizzle_net_set_link(NULL);
    }
    return result;
}

void drizzle_wifi_poll(void) { wifi_receive(); }

drizzle_wifi_state_t drizzle_wifi_state(void) { return state; }

const char *drizzle_wifi_backend_name(void) {
    return active_backend && active_backend->name ? active_backend->name : "none";
}

const uint8_t *drizzle_wifi_mac(void) { return local_mac; }

const drizzle_link_t *drizzle_wifi_link(void) {
    return state == DR1ZZLE_WIFI_ASSOCIATED ? &link : NULL;
}

void drizzle_wifi_receive_frame(const uint8_t *frame, size_t length) {
    if (state == DR1ZZLE_WIFI_ASSOCIATED && frame && length) {
        drizzle_net_receive(frame, length);
    }
}
