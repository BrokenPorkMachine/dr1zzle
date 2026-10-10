#ifndef I2C_H
#define I2C_H

#include <stdint.h>

/* I2C master on the A11.
 *
 * Layout grounding: the A11-compatible string "apple,t8015-i2c" appears in
 * the upstream device-tree binding as a fallback for "apple,i2c", and
 * "apple,i2c" is bound to the PA Semi PWRficient SMBus controller. The A11
 * therefore runs the same block as the M1's I2C, and the register map
 * below is the one published by drivers/i2c/busses/i2c-pasemi-core.c.
 * That is the strongest kind of reference available for this peripheral:
 * a shared IP block named in a device tree, not a guess.
 *
 * What is NOT verified: I2C_BASE from memory_map.h, and the reference clock
 * frequency the block divides. The clock matters more than it looks -- the
 * divider is a plain integer divide of the reference, and a wrong
 * reference produces a wrong bus speed rather than an error. The computed
 * divider is exposed (i2c_divider()) so bring-up can check it against what
 * a scope actually sees.
 *
 * The block is driven purely by polling. Its interrupt is masked in
 * i2c_init() and stays that way; see the AIC notes for why IRQ lines are
 * not wired to these peripherals in this build.
 */

/* Register offsets. */
#define I2C_MTXFIFO          0x00
#define I2C_MRXFIFO          0x04
#define I2C_XFSTA            0x0C
#define I2C_SMSTA            0x14
#define I2C_IMASK            0x18
#define I2C_CTL              0x1C
#define I2C_REV              0x28

/* Transmit FIFO word: address byte, data byte, or a length with flags. */
#define I2C_TXFIFO_START     (1u << 8)
#define I2C_TXFIFO_STOP      (1u << 9)
#define I2C_TXFIFO_READ      (1u << 10)

/* Receive FIFO word. */
#define I2C_RXFIFO_EMPTY     (1u << 8)
#define I2C_RXFIFO_DATA      0xFFu

/* Status (SMSTA). */
#define I2C_SMSTA_XIP        (1u << 28)  /* transaction in progress */
#define I2C_SMSTA_XEN        (1u << 27)  /* transfer complete */
#define I2C_SMSTA_JMD        (1u << 25)  /* jam, data */
#define I2C_SMSTA_JAM        (1u << 24)  /* jam, clock */
#define I2C_SMSTA_MTO        (1u << 23)  /* peripheral timeout */
#define I2C_SMSTA_MTA        (1u << 22)  /* arbitration lost */
#define I2C_SMSTA_MTN        (1u << 21)  /* no acknowledge */
#define I2C_SMSTA_MRNE       (1u << 19)  /* receive FIFO not empty */
#define I2C_SMSTA_MTE        (1u << 16)  /* transmit FIFO empty */
#define I2C_SMSTA_TOM        (1u << 6)   /* controller internal timeout */

/* Control (CTL). */
#define I2C_CTL_EN           (1u << 11)
#define I2C_CTL_MRR          (1u << 10)
#define I2C_CTL_MTR          (1u << 9)
#define I2C_CTL_UJM          (1u << 8)
#define I2C_CTL_CLK_M        0xFFu

/* Divider range accepted by the reference driver. Outside it the bus speed
 * cannot be represented and the transfer is refused rather than run at a
 * speed nobody asked for. */
#define I2C_DIV_MIN          4u
#define I2C_DIV_MAX          255u

/* Default reference clock and bus speed. 24 MHz is the slowest of the
 * clocks the Apple platform publishes, and 100 kHz is the standard mode
 * the binding falls back to. */
#define I2C_REF_CLK_HZ       24000000u
#define I2C_DEFAULT_HZ       100000u

/* Transfer bounds. Reads carry their length in the MTXFIFO data field, so
 * they are capped at one byte-field; writes are capped well below any FIFO
 * depth because the depth is not published and an overflow would silently
 * drop bytes. */
#define I2C_MAX_READ         255u
#define I2C_MAX_WRITE        64u

/* Error codes. Kept negative so a caller cannot mistake one for a length. */
#define I2C_ERR_TIMEOUT      (-1)
#define I2C_ERR_NACK         (-2)
#define I2C_ERR_ARB          (-3)
#define I2C_ERR_JAM          (-4)
#define I2C_ERR_PERIPH       (-5)
#define I2C_ERR_UNDERRUN     (-6)
#define I2C_ERR_RANGE       (-7)

const char *i2c_strerror(int err);

/* Returns 0 on success. A failure means the controller was not programmed;
 * the previous value is left in place. */
int  i2c_init(uint32_t bus_hz);
int  i2c_set_speed(uint32_t bus_hz);
int  i2c_set_ref_clk(uint32_t hz);

uint32_t i2c_revision(void);
uint32_t i2c_ref_clk(void);
uint32_t i2c_speed(void);
uint32_t i2c_divider(void);

/* Primitive transfers. Addresses are 7-bit, unshifted. */
int  i2c_write(uint8_t addr7, const uint8_t *buf, uint16_t len);
int  i2c_read(uint8_t addr7, uint8_t *buf, uint16_t len);
int  i2c_write_read(uint8_t addr7, const uint8_t *tx, uint16_t txlen,
                    uint8_t *rx, uint16_t rxlen);
int  i2c_probe(uint8_t addr7);

/* Quick-command probe of the whole 7-bit space. Writes up to `max`
 * addresses that acknowledged into `found`, returns the count, or negative
 * on a bus-level failure. */
int  i2c_scan(uint8_t *found, int max);

void i2c_dump(void);

#endif /* I2C_H */
