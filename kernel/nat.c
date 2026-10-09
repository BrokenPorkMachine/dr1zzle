#include <drizzle/nat.h>
#include <string.h>

static int enabled;
static uint8_t public_v4[4];
static uint16_t public_base_port;

void drizzle_nat_enable(const uint8_t public_address[4], uint16_t public_port) { memcpy(public_v4, public_address, 4u); public_base_port = public_port; enabled = 1; }
void drizzle_nat_disable(void) { enabled = 0; public_base_port = 0u; memset(public_v4, 0, sizeof public_v4); }
int drizzle_nat_enabled(void) { return enabled; }
unsigned drizzle_nat_connection_count(void) { return 0u; }
uint32_t drizzle_nat_expired(void) { return 0u; }
