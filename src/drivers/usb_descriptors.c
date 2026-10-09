#include <stdint.h>

const uint8_t device_desc[] = {
    18, 1, 0x00, 0x02, 0x02, 0x00, 0x00, 64,
    0x34, 0x12, 0x01, 0xd1, 0x00, 0x01,
    1, 2, 3, 1
};

const uint8_t config_desc[] = {
    9, 2, 80, 0, 2, 1, 0, 0x80, 50,
    9, 4, 0, 0, 1, 0x02, 0x06, 0x00, 0,
    5, 0x24, 0x00, 0x10, 0x01,
    5, 0x24, 0x06, 0, 1,
    13, 0x24, 0x0f, 3, 0, 0, 0, 0, 0xea, 0x05, 0, 0, 0,
    7, 5, 0x81, 0x03, 16, 0, 9,
    9, 4, 1, 0, 2, 0x0a, 0x00, 0x00, 0,
    7, 5, 0x02, 0x02, 0, 2, 0,
    7, 5, 0x82, 0x02, 0, 2, 0
};

const uint32_t config_desc_size = sizeof(config_desc);
const uint8_t string_lang[] = { 4, 3, 0x09, 0x04 };
const uint8_t string_manuf[] = "dr1zzle";
const uint8_t string_product[] = "dr1zzle CDC ECM";
const uint8_t string_serial[] = "0001";
