#include <stdint.h>
#include <mmio.h>

int main(void) {
    uint32_t word = 0;
    uint16_t half = 0;
    uint8_t byte = 0;

    mmio_write32((uintptr_t)&word, 0x12345678u);
    if (mmio_read32((uintptr_t)&word) != 0x12345678u) return 1;
    mmio_set32((uintptr_t)&word, 0x00000003u);
    if (mmio_read32((uintptr_t)&word) != 0x1234567bu) return 2;
    mmio_clear32((uintptr_t)&word, 0x00000070u);
    if (mmio_read32((uintptr_t)&word) != 0x1234560bu) return 3;

    mmio_write16((uintptr_t)&half, 0xabcdU);
    if (mmio_read16((uintptr_t)&half) != 0xabcdU) return 4;
    mmio_write8((uintptr_t)&byte, 0xefU);
    if (mmio_read8((uintptr_t)&byte) != 0xefU) return 5;
    return 0;
}
