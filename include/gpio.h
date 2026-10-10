#ifndef GPIO_H
#define GPIO_H

#include <stdint.h>

/* GPIO / pinmux on the A11.
 *
 * Layout grounding: the pin config word below is the one published for the
 * Apple pinctrl block by drivers/pinctrl/pinctrl-apple-gpio.c, and the
 * per-pin register stride (one 32-bit word per pin, config at 4*pin) plus
 * the seven interrupt-group windows at 0x800 + 0x40*group agree with the
 * observed behaviour in the Asahi Linux notes. The block has been present
 * in this shape since well before the A11, which is why it is reasonable
 * to start from it -- but it is still a starting point, not a verified A11
 * datasheet.
 *
 * What is NOT verified: GPIO_BASE in memory_map.h, and the pin count. The
 * controller has no register that reports how many pins it implements, so
 * the cap here (GPIO_MAX_PINS) is a ceiling and reads past it are refused
 * by the driver rather than handed to unknown offsets.
 *
 * Nothing here touches interrupts. GPIO IRQ groups would need an AIC line
 * each, and which line belongs to which group is device-tree information
 * this build does not parse.
 */

/* One 32-bit configuration word per pin. */
#define GPIO_REG(pin)         (4u * (pin))

#define GPIO_DATA             (1u << 0)      /* output value / input level */
#define GPIO_MODE             (7u << 1)
#define GPIO_MODE_SHIFT       1
#define GPIO_OUT              1u             /* push-pull output */
#define GPIO_IN_IRQ_OFF       7u             /* input, no interrupt */
#define GPIO_IN_IRQ_HI        2u
#define GPIO_IN_IRQ_LO        3u
#define GPIO_IN_IRQ_UP        4u
#define GPIO_IN_IRQ_DN        5u
#define GPIO_IN_IRQ_ANY       6u
#define GPIO_PERIPH           (3u << 5)      /* 0 = GPIO, 1..3 = alt funcs */
#define GPIO_PERIPH_SHIFT     5
#define GPIO_PULL             (3u << 7)
#define GPIO_PULL_OFF         0u
#define GPIO_PULL_DOWN        1u
#define GPIO_PULL_UP_STRONG   2u
#define GPIO_PULL_UP          3u
#define GPIO_INPUT_ENABLE     (1u << 9)
#define GPIO_DRIVE0           (3u << 10)
#define GPIO_SCHMITT          (1u << 15)
#define GPIO_GRP              (7u << 16)
#define GPIO_LOCK             (1u << 21)
#define GPIO_DRIVE1           (3u << 22)

/* Interrupt group windows: 7 groups, 0x40 apart, write 1 to clear. */
#define GPIO_IRQ_BASE         0x800
#define GPIO_IRQ_STRIDE       0x40
#define GPIO_IRQ_GROUPS       7

/* Ceiling on the pin number. Reads and writes past this are refused. */
#define GPIO_MAX_PINS         256u

/* Returns 0 if the pin window answers, -1 if it reads back as all ones.
 * There is nothing to program globally; see gpio.c for why this is a probe
 * rather than a bring-up. */
int  gpio_init(void);

int  gpio_probe(void);                       /* 0 if the pin window reads back */
uint32_t gpio_read_config(unsigned int pin);
void     gpio_write_config(unsigned int pin, uint32_t value);
void     gpio_modify_config(unsigned int pin, uint32_t clear, uint32_t set);

/* Function select. 0 = GPIO, 1..3 = the peripheral muxed onto that pin.
 * Enabling input as well is what the reference driver does; a pin left as
 * an input with the buffer off reads garbage. */
void gpio_set_func(unsigned int pin, unsigned int func);

void gpio_direction_input(unsigned int pin);
void gpio_direction_output(unsigned int pin, int value);

int  gpio_get(unsigned int pin);
void gpio_set(unsigned int pin, int value);

void gpio_dump(unsigned int pin);

#endif /* GPIO_H */
