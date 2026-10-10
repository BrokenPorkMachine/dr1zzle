/* I2C master (PA Semi PWRficient SMBus, the block the A11-compatible
 * "apple,i2c" node binds to).
 *
 * The controller is command-based: the transmit FIFO takes a small
 * instruction stream, and the status register tells you when the bus has
 * gone quiet again. The four messages this driver builds are:
 *
 *   write      START | addr<<1 , data... , last | STOP
 *   read       START | addr<<1 | 1 , len | READ | STOP
 *   register   write of one or more bytes followed by a read
 *   quick      addr | rflag | START | STOP          (used by the scan)
 *
 * `len | READ` deserves a note because it is the unusual part: the length
 * of a read is written *into the FIFO as a data word*, which is why reads
 * are capped at 255 bytes and why a read is primed with two FIFO writes and
 * then waits for completion before draining.
 *
 * Every transfer ends with a bus recovery step. The reference driver does
 * the same thing: if the status shows a jam, an arbitration loss, or a
 * non-empty receive FIFO at the wrong moment, the FIFOs are reset and the
 * control word is rewritten. Leaving the block in that state wedges all
 * later transfers, which is worse than losing one.
 */

#include "i2c.h"
#include "memory_map.h"
#include "mmio.h"
#include "timer.h"
#include "uart.h"
#include "util.h"

#define I2C_BASE_WORD ((uintptr_t)I2C_BASE)

static inline void i2c_wr(uint32_t off, uint32_t val) {
    mmio_write32(I2C_BASE_WORD + off, val);
}

static inline uint32_t i2c_rd(uint32_t off) {
    return mmio_read32(I2C_BASE_WORD + off);
}

static volatile uint32_t *const smsta_reg =
    (volatile uint32_t *)((uintptr_t)I2C_BASE + I2C_SMSTA);

/* Bound for every status poll. The reference driver uses 100 ms, citing a
 * hardware clock-stretching timeout of ~25 ms; the same number is used
 * here so a stuck bus cannot hang the shell forever. */
#define I2C_POLL_TIMEOUT_US  100000

static uint32_t i2c_ref_clk_hz = I2C_REF_CLK_HZ;
static uint32_t i2c_bus_hz  = I2C_DEFAULT_HZ;
static uint32_t i2c_clk_div;
static uint32_t i2c_hw_rev;
static int      i2c_initialised;

const char *i2c_strerror(int err) {
    switch (err) {
        case I2C_ERR_TIMEOUT:   return "timeout";
        case I2C_ERR_NACK:      return "nack";
        case I2C_ERR_ARB:       return "arbitration lost";
        case I2C_ERR_JAM:       return "bus jam";
        case I2C_ERR_PERIPH:    return "peripheral timeout";
        case I2C_ERR_UNDERRUN:  return "receive underrun";
        case I2C_ERR_RANGE:     return "length out of range";
        default:                return "ok";
    }
}

static void i2c_reset(void) {
    uint32_t ctl = I2C_CTL_MTR | I2C_CTL_MRR | I2C_CTL_UJM |
                   (i2c_clk_div & I2C_CTL_CLK_M);
    /* The enable bit only exists on later revisions of the block. Writing
     * it to a controller that does not implement it is harmless, but the
     * reference driver gates it on the revision readback and so does this:
     * the revision is logged at init for exactly this check. */
    if (i2c_hw_rev >= 6) ctl |= I2C_CTL_EN;
    i2c_wr(I2C_CTL, ctl);
}

/* Clear whatever state the last transfer left. */
static int i2c_clear_bus(void) {
    if (timer_wait_reg(smsta_reg, I2C_SMSTA_XIP | I2C_SMSTA_JAM, 0,
                       I2C_POLL_TIMEOUT_US) != 0) {
        return I2C_ERR_TIMEOUT;
    }

    uint32_t status = i2c_rd(I2C_SMSTA);
    if ((status & (I2C_SMSTA_MRNE | I2C_SMSTA_JMD | I2C_SMSTA_MTN |
                   I2C_SMSTA_MTO | I2C_SMSTA_MTA)) ||
        !(status & I2C_SMSTA_MTE)) {
        i2c_reset();
    }

    i2c_wr(I2C_SMSTA, status);
    return 0;
}

/* Wait for the bus to go quiet and classify why it stopped. */
static int i2c_wait_ready(void) {
    if (timer_wait_reg(smsta_reg, I2C_SMSTA_XEN, I2C_SMSTA_XEN,
                       I2C_POLL_TIMEOUT_US) != 0) {
        return I2C_ERR_TIMEOUT;
    }

    uint32_t status = i2c_rd(I2C_SMSTA);
    if (status & I2C_SMSTA_TOM) return I2C_ERR_TIMEOUT;
    if (status & I2C_SMSTA_MTO) return I2C_ERR_PERIPH;
    if (status & I2C_SMSTA_MTA) return I2C_ERR_ARB;
    if (status & I2C_SMSTA_MTN) return I2C_ERR_NACK;

    /* Status bits are write-to-clear. Acknowledge completion, or the next
     * transfer's poll sees a stale XEN and returns immediately. */
    i2c_wr(I2C_SMSTA, I2C_SMSTA_XEN);
    return 0;
}

int i2c_set_ref_clk(uint32_t hz) {
    if (hz == 0) return -1;
    i2c_ref_clk_hz = hz;
    if (i2c_initialised) {
        /* Re-derive the divider from the speed the bus was last asked
         * for, so the bus keeps running at the speed the caller chose and
         * only the divider changes underneath it. */
        return i2c_set_speed(i2c_bus_hz);
    }
    return 0;
}

int i2c_set_speed(uint32_t bus_hz) {
    if (bus_hz == 0) return -1;

    /* Same rounding as the reference driver: ceil(ref / (16 * hz)), and
     * anything outside 4..255 cannot be represented. */
    uint32_t div = (i2c_ref_clk_hz + 16u * bus_hz - 1u) / (16u * bus_hz);
    if (div < I2C_DIV_MIN || div > I2C_DIV_MAX) return -1;

    i2c_bus_hz = bus_hz;
    i2c_clk_div = div;
    i2c_reset();
    return 0;
}

int i2c_init(uint32_t bus_hz) {
    i2c_wr(I2C_IMASK, 0);          /* polling: never unmask the interrupt */
    i2c_hw_rev = i2c_rd(I2C_REV) & 0xFFu;

    uint32_t div = (i2c_ref_clk_hz + 16u * bus_hz - 1u) / (16u * bus_hz);
    if (div < I2C_DIV_MIN || div > I2C_DIV_MAX) {
        uart_puts("i2c: no divider for ");
        uart_puts(utoa(bus_hz));
        uart_puts("Hz from a ");
        uart_puts(utoa(i2c_ref_clk_hz));
        uart_puts("Hz reference\n");
        return -1;
    }
    i2c_bus_hz = bus_hz;
    i2c_clk_div = div;

    int err = i2c_clear_bus();
    if (err != 0) {
        uart_puts("i2c: bus not idle (");
        uart_puts(i2c_strerror(err));
        uart_puts(")\n");
        return -1;
    }

    i2c_reset();
    i2c_initialised = 1;
    return 0;
}

uint32_t i2c_revision(void) { return i2c_hw_rev; }
uint32_t i2c_ref_clk(void)  { return i2c_ref_clk_hz; }
uint32_t i2c_divider(void)  { return i2c_clk_div; }
uint32_t i2c_speed(void) {
    if (i2c_clk_div == 0) return 0;
    return i2c_ref_clk_hz / (16u * i2c_clk_div);
}

int i2c_write(uint8_t addr7, const uint8_t *buf, uint16_t len) {
    if (len == 0 || len > I2C_MAX_WRITE) return I2C_ERR_RANGE;

    int err = i2c_clear_bus();
    if (err != 0) return err;

    i2c_wr(I2C_MTXFIFO, I2C_TXFIFO_START | ((uint32_t)addr7 << 1));
    for (uint16_t i = 0; i < len - 1; i++) {
        i2c_wr(I2C_MTXFIFO, buf[i]);
    }
    i2c_wr(I2C_MTXFIFO, buf[len - 1] | I2C_TXFIFO_STOP);

    err = i2c_wait_ready();
    if (err == I2C_ERR_NACK || err == I2C_ERR_ARB || err == I2C_ERR_PERIPH ||
        err == I2C_ERR_TIMEOUT) {
        i2c_reset();
    }
    return err;
}

int i2c_read(uint8_t addr7, uint8_t *buf, uint16_t len) {
    if (len == 0 || len > I2C_MAX_READ) return I2C_ERR_RANGE;

    int err = i2c_clear_bus();
    if (err != 0) return err;

    i2c_wr(I2C_MTXFIFO, I2C_TXFIFO_START | ((uint32_t)addr7 << 1) | 1u);
    i2c_wr(I2C_MTXFIFO, len | I2C_TXFIFO_READ | I2C_TXFIFO_STOP);

    err = i2c_wait_ready();
    if (err != 0) {
        i2c_reset();
        return err;
    }

    for (uint16_t i = 0; i < len; i++) {
        uint32_t word = i2c_rd(I2C_MRXFIFO);
        if (word & I2C_RXFIFO_EMPTY) {
            i2c_reset();
            return I2C_ERR_UNDERRUN;
        }
        buf[i] = (uint8_t)(word & I2C_RXFIFO_DATA);
    }
    return 0;
}

int i2c_write_read(uint8_t addr7, const uint8_t *tx, uint16_t txlen,
                   uint8_t *rx, uint16_t rxlen) {
    if (txlen == 0 || txlen > I2C_MAX_WRITE) return I2C_ERR_RANGE;
    if (rxlen == 0 || rxlen > I2C_MAX_READ) return I2C_ERR_RANGE;

    int err = i2c_clear_bus();
    if (err != 0) return err;

    /* Write phase without a stop: the block re-issues START for the read
     * phase, which is a repeated start, not a fresh transaction. */
    i2c_wr(I2C_MTXFIFO, I2C_TXFIFO_START | ((uint32_t)addr7 << 1));
    for (uint16_t i = 0; i < txlen; i++) {
        i2c_wr(I2C_MTXFIFO, tx[i]);
    }

    i2c_wr(I2C_MTXFIFO, I2C_TXFIFO_START | ((uint32_t)addr7 << 1) | 1u);
    i2c_wr(I2C_MTXFIFO, rxlen | I2C_TXFIFO_READ | I2C_TXFIFO_STOP);

    err = i2c_wait_ready();
    if (err != 0) {
        i2c_reset();
        return err;
    }

    for (uint16_t i = 0; i < rxlen; i++) {
        uint32_t word = i2c_rd(I2C_MRXFIFO);
        if (word & I2C_RXFIFO_EMPTY) {
            i2c_reset();
            return I2C_ERR_UNDERRUN;
        }
        rx[i] = (uint8_t)(word & I2C_RXFIFO_DATA);
    }
    return 0;
}

int i2c_probe(uint8_t addr7) {
    if (addr7 < 0x08 || addr7 > 0x77) return I2C_ERR_RANGE;

    int err = i2c_clear_bus();
    if (err != 0) return err;

    i2c_wr(I2C_MTXFIFO, I2C_TXFIFO_START | ((uint32_t)addr7 << 1) |
                          I2C_TXFIFO_STOP);

    err = i2c_wait_ready();
    if (err == I2C_ERR_NACK) return 0;      /* acknowledged as "absent" */
    if (err != 0) {
        i2c_reset();
        return err;
    }
    return 1;
}

int i2c_scan(uint8_t *found, int max) {
    int count = 0;
    for (unsigned int addr = 0x08; addr <= 0x77; addr++) {
        int present = i2c_probe((uint8_t)addr);
        if (present < 0) return -1;
        if (present > 0) {
            if (count < max) found[count] = (uint8_t)addr;
            count++;
        }
    }
    return count;
}

void i2c_dump(void) {
    uart_puts("i2c: base=0x");
    uart_puts(utoa_hex(I2C_BASE));
    uart_puts(" rev=0x");
    uart_puts(utoa_hex(i2c_hw_rev));
    uart_puts(" clk_div=");
    uart_puts(utoa(i2c_clk_div));
    uart_puts(" ref=");
    uart_puts(utoa(i2c_ref_clk_hz));
    uart_puts("Hz speed=");
    uart_puts(utoa(i2c_speed()));
    uart_puts("Hz\n");

    uart_puts("i2c: ctl=0x");
    uart_puts(utoa_hex(i2c_rd(I2C_CTL)));
    uart_puts(" smsta=0x");
    uart_puts(utoa_hex(i2c_rd(I2C_SMSTA)));
    uart_puts(" xfsta=0x");
    uart_puts(utoa_hex(i2c_rd(I2C_XFSTA)));
    uart_puts(i2c_initialised ? " ready\n" : " not-ready\n");
}
