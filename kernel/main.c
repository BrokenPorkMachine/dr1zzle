#include <stddef.h>
#include <drizzle/monitor.h>
#include <drizzle/net.h>
#include <stdio.h>
#include <stdlib.h>
void qemu_console_init(void);
extern unsigned char __heap_start[], __heap_end[];
void kernel_main(void) {
    size_t heap_size = (size_t)(__heap_end - __heap_start);
    qemu_console_init();
    drizzle_net_init();
    puts("dr1zzle C monitor");
    puts("console=ready");
    drizzle_heap_set(__heap_start, heap_size);
    puts("heap=65536 bytes");
    puts("target=qemu-virt status=ready");
    drizzle_monitor_run(heap_size);
}
