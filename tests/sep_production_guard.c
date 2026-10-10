#include "sep.h"

int main(void) {
    volatile uint32_t fake_window[1024];
    struct sep_driver drv;
    for (unsigned int i = 0; i < 1024; i++) fake_window[i] = 0xa5a50000u + i;

    int rc = sep_init(&drv, (uint64_t)fake_window);
    if (rc != SEP_ERR_UNSUPPORTED) return 1;
    if (drv.base != 0) return 2;
    if (sep_get_status(&drv) != 0) return 3;
    if (sep_send_command(&drv, SEP_OP_PING, 0, 0, 0, 0) != SEP_ERR_INVALID) return 4;
    for (unsigned int i = 0; i < 1024; i++) {
        if (fake_window[i] != 0xa5a50000u + i) return 5;
    }
    return 0;
}
