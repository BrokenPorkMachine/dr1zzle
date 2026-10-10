#include <stddef.h>
#include <stdint.h>
#include <drizzle/hardware.h>
#include <boards/qemu_budget.h>
#include <drizzle/monitor.h>
#include <drizzle/net.h>
#include <stdio.h>
#include <stdlib.h>
void qemu_console_init(void);
#ifndef DRIZZLE_SMALL_PROFILE
int qemu_display_init(void);
#endif
extern unsigned char __heap_start[], __heap_end[], __image_start[];
extern unsigned char __stack_bottom[], __stack_top[];
void kernel_main(void) {
    size_t heap_size = (size_t)((uintptr_t)__heap_end - (uintptr_t)__heap_start);
    qemu_console_init();
    uint64_t image_size = (uintptr_t)__heap_start - (uintptr_t)__image_start;
    uint64_t stack_size = (uintptr_t)__stack_top - (uintptr_t)__stack_bottom;
    if ((uintptr_t)__image_start != QEMU_PROFILE.arena_base ||
        drizzle_hw_admit(&QEMU_PROFILE, image_size, heap_size, stack_size, NULL) != DRIZZLE_HW_OK) {
        puts("hardware profile rejected linker layout");
        for (;;) __asm__ volatile("wfe");
    }
#ifndef DRIZZLE_SMALL_PROFILE
    if (!qemu_display_init()) puts("display=unavailable (UART ready)");
#endif
    drizzle_net_init();
    puts("dr1zzle C monitor");
    puts("console=ready");
    drizzle_heap_set(__heap_start, heap_size);
    char status[96];
    snprintf(status, sizeof status, "profile=%s heap=%lu bytes", QEMU_PROFILE.name, (unsigned long)heap_size);
    puts(status);
    puts("target=qemu-virt status=ready");
    drizzle_monitor_run(heap_size);
}
