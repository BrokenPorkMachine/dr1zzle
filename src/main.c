#include "memory_map.h"
#include "uart.h"
#include "timer.h"
#include "shell.h"
#include "secure_rom.h"
#include "sepos.h"
#include "nand_dump.h"
#include "memory_dump.h"
#include "iboot_dump.h"
#include "keybag.h"
#include "aes.h"
#include "ace2.h"
#include "wifi.h"
#include "kernel_patch.h"
#include "panic_log.h"

extern void mmu_init(void);
extern void exception_init(void);
extern void usb_init(void);
extern void reboot(void);

void c_main(void) {
    mmu_init();
    uart_early_init();
    timer_init();
    exception_init();
    usb_init();
    ace2_init();
    wifi_init();
    
    uart_puts("\n=== A11 Research Payload v0.1 ===\n");
    uart_puts("Type 'help' for commands\n\n");
    
    shell_run();
}
