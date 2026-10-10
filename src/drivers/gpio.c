/* GPIO / pinmux driver.
 *
 * This exists for one reason: before any of the other peripheral drivers
 * in this build can be believed, the pins they sit on have to be muxed
 * away from the bootloader's choice and onto the peripheral. That is what
 * gpio_set_func() is for, and it is the only operation here that changes
 * shared hardware state -- everything else is a read, or a direction
 * change on a pin the caller has already claimed by saying so.
 *
 * Everything runs unpolled. The pin level lives in the configuration word
 * itself, so a read of the level is a read of the pin's register; there is
 * no status register to wait on and no interrupt to acknowledge.
 *
 * Unverified: see gpio.h. The driver refuses pins past GPIO_MAX_PINS rather
 * than writing to offsets it cannot account for.
 */

#include "gpio.h"
#include "memory_map.h"
#include "mmio.h"
#include "uart.h"
#include "util.h"

#define GPIO_BASE_WORD ((uintptr_t)GPIO_BASE)

static inline uint32_t gpio_rd(uint32_t off) {
    return mmio_read32(GPIO_BASE_WORD + off);
}

static inline void gpio_wr(uint32_t off, uint32_t val) {
    mmio_write32(GPIO_BASE_WORD + off, val);
}

static int pin_in_range(unsigned int pin) {
    return pin < GPIO_MAX_PINS;
}

int gpio_probe(void) {
    /* A configured pin's word is never all-ones: the mode field has at most
     * six valid encodings and a real bootloader leaves a sane one behind.
     * A window that reads back nothing but ones is not this block. */
    uint32_t cfg = gpio_rd(GPIO_REG(0));
    if (cfg == 0xFFFFFFFFu) return -1;
    return 0;
}

/* Returns 0 if the pin window answers, -1 if it reads back as all ones.
 * There is nothing to program globally: the block has no enable bit and no
 * clock of its own, and pin state is whatever the boot firmware left.
 * Changing it is a caller's decision, so this only checks that the window
 * is live before a caller starts muxing pins through it. */
int gpio_init(void) {
    int err = gpio_probe();
    if (err != 0) {
        uart_puts("gpio: pin window reads 0xffffffff; base may be wrong\n");
    }
    return err;
}

uint32_t gpio_read_config(unsigned int pin) {
    if (!pin_in_range(pin)) return 0;
    return gpio_rd(GPIO_REG(pin));
}

void gpio_write_config(unsigned int pin, uint32_t value) {
    if (!pin_in_range(pin)) return;
    gpio_wr(GPIO_REG(pin), value);
}

void gpio_modify_config(unsigned int pin, uint32_t clear, uint32_t set) {
    if (!pin_in_range(pin)) return;
    uint32_t cfg = gpio_rd(GPIO_REG(pin));
    cfg &= ~clear;
    cfg |= set;
    gpio_wr(GPIO_REG(pin), cfg);
}

void gpio_set_func(unsigned int pin, unsigned int func) {
    if (!pin_in_range(pin)) return;
    if (func > 3) func = 0;

    /* Clear the mode first: a pin left in one of the interrupt-input
     * encodings keeps its comparator live while the mux changes, and the
     * resulting glitch is visible to whatever is listening on the line. */
    gpio_modify_config(pin,
                       GPIO_PERIPH | GPIO_MODE | GPIO_INPUT_ENABLE,
                       ((func << GPIO_PERIPH_SHIFT) & GPIO_PERIPH) |
                       GPIO_INPUT_ENABLE |
                       ((GPIO_IN_IRQ_OFF << GPIO_MODE_SHIFT) & GPIO_MODE));
}

void gpio_direction_input(unsigned int pin) {
    if (!pin_in_range(pin)) return;
    gpio_modify_config(pin,
                       GPIO_PERIPH | GPIO_MODE | GPIO_INPUT_ENABLE,
                       ((GPIO_IN_IRQ_OFF << GPIO_MODE_SHIFT) & GPIO_MODE) |
                       GPIO_INPUT_ENABLE);
}

void gpio_direction_output(unsigned int pin, int value) {
    if (!pin_in_range(pin)) return;
    gpio_modify_config(pin,
                       GPIO_PERIPH | GPIO_MODE,
                       ((GPIO_OUT << GPIO_MODE_SHIFT) & GPIO_MODE) |
                       (value ? GPIO_DATA : 0u));
}

int gpio_get(unsigned int pin) {
    if (!pin_in_range(pin)) return -1;
    return (gpio_rd(GPIO_REG(pin)) & GPIO_DATA) ? 1 : 0;
}

void gpio_set(unsigned int pin, int value) {
    if (!pin_in_range(pin)) return;
    gpio_modify_config(pin, GPIO_DATA, value ? GPIO_DATA : 0u);
}

void gpio_dump(unsigned int pin) {
    if (!pin_in_range(pin)) {
        uart_puts("gpio: pin ");
        uart_puts(utoa(pin));
        uart_puts(" past GPIO_MAX_PINS\n");
        return;
    }
    uint32_t cfg = gpio_read_config(pin);
    uart_puts("gpio: pin ");
    uart_puts(utoa(pin));
    uart_puts(" cfg=0x");
    uart_puts(utoa_hex(cfg));
    uart_puts(" mode=0x");
    uart_puts(utoa_hex((cfg & GPIO_MODE) >> GPIO_MODE_SHIFT));
    uart_puts(" func=0x");
    uart_puts(utoa_hex((cfg & GPIO_PERIPH) >> GPIO_PERIPH_SHIFT));
    uart_puts(" data=");
    uart_puts(utoa((cfg & GPIO_DATA) ? 1 : 0));
    uart_puts("\n");
}
