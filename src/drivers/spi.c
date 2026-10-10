/* SPI master (Apple SPI controller).
 *
 * The block is a FIFO-based shift engine: TXCNT/RXCNT say how many words
 * the transfer moves, RUN starts the clock, and completion is reported
 * through the IF_XFER flags. Because this build drives it polled, the
 * interrupt enables stay at zero and IF_* is read directly.
 *
 * The transfer loop is the same shape as the reference driver's:
 *
 *   1. reset both FIFOs, clear the flag registers
 *   2. program TXCNT/RXCNT for the whole transfer
 *   3. prime the transmit FIFO up to its depth
 *   4. set RUN
 *   5. drain the receive FIFO and refill the transmit FIFO until the word
 *      count is done, waiting on the FIFO levels rather than on flags
 *
 * Step 5 uses the FIFO levels instead of the threshold flags because the
 * levels are always current and need no interrupt enable to become so.
 *
 * Chip select is left where it was: the driver moves it only if a caller
 * asks, so a peripheral that needs CS held low across two transfers can be
 * given that, and a transfer run on its own does not leave the line low.
 *
 * Unverified: see spi.h.
 */

#include "spi.h"
#include "memory_map.h"
#include "mmio.h"
#include "timer.h"
#include "uart.h"
#include "util.h"

#define SPI_BASE_WORD ((uintptr_t)SPI_BASE)

static inline void spi_wr(uint32_t off, uint32_t val) {
    mmio_write32(SPI_BASE_WORD + off, val);
}

static inline uint32_t spi_rd(uint32_t off) {
    return mmio_read32(SPI_BASE_WORD + off);
}

static inline void spi_modify(uint32_t off, uint32_t clear, uint32_t set) {
    uint32_t val = spi_rd(off);
    val &= ~clear;
    val |= set;
    spi_wr(off, val);
}

/* One transfer, no matter the length, must not outlive this. The reference
 * driver uses 200 ms, which is generous for any speed this divider range
 * can produce. */
#define SPI_TIMEOUT_US        200000

/* TXCNT/RXCNT width is not documented; stay well inside a 16-bit field so a
 * length that cannot be represented is refused instead of truncated. */
#define SPI_MAX_WORDS         4096u

static uint32_t spi_ref_clk = SPI_REF_CLK_HZ;
static uint32_t spi_clk_div;
static uint32_t spi_bus_hz   = SPI_DEFAULT_HZ;
static int      spi_initialised;

const char *spi_strerror(int err) {
    switch (err) {
        case SPI_ERR_TIMEOUT:  return "timeout";
        case SPI_ERR_RANGE:    return "length out of range";
        default:               return "ok";
    }
}

static inline uint32_t fifo_tx_level(void) {
    return (spi_rd(SPI_FIFOSTAT) & SPI_FIFOSTAT_LEVEL_TX) >> SPI_FIFOSTAT_LEVEL_TX_SHIFT;
}

static inline int fifo_rx_empty(void) {
    return (spi_rd(SPI_FIFOSTAT) & SPI_FIFOSTAT_RXEMPTY) != 0;
}

/* The receive level is deliberately not wrapped: the empty bit is the only
 * receive condition this driver needs, and a helper that is never called is
 * a helper that cannot be checked. Drain until the level says so. */

int spi_ready(void) {
    return spi_initialised;
}

int spi_set_speed(uint32_t hz) {
    if (hz == 0) return -1;

    uint32_t div = (spi_ref_clk + hz - 1u) / hz;
    if (div == 0) div = 1;
    if (div > SPI_CLKDIV_MAX) div = SPI_CLKDIV_MAX;

    spi_bus_hz = hz;
    spi_clk_div = div;
    spi_wr(SPI_CLKDIV, div);
    return 0;
}

uint32_t spi_speed(void) {
    if (spi_clk_div == 0) return 0;
    return spi_ref_clk / spi_clk_div;
}

uint32_t spi_divider(void) {
    return spi_clk_div;
}

void spi_init(void) {
    /* CS idles high and is driven by the shift engine, not by this driver. */
    spi_wr(SPI_PIN, SPI_PIN_CS);
    spi_modify(SPI_SHIFTCFG, SPI_SHIFTCFG_OVERRIDE_CS, 0);
    spi_modify(SPI_PINCFG, SPI_PINCFG_CS_IDLE_VAL, SPI_PINCFG_KEEP_CS);

    spi_wr(SPI_CTRL, SPI_CTRL_TX_RESET | SPI_CTRL_RX_RESET);

    /* Polled mode, 8-bit words, threshold of eight bytes. The reference
     * driver picks the same threshold and runs in interrupt mode; only the
     * mode field differs here. */
    spi_wr(SPI_CFG, ((SPI_CFG_FIFO_THRESH_8B) & SPI_CFG_FIFO_THRESH) |
                    ((SPI_CFG_MODE_POLLED) & SPI_CFG_MODE) |
                    ((SPI_CFG_WORD_SIZE_8B) & SPI_CFG_WORD_SIZE));

    /* No interrupts, and the delay block is not used: a research transfer
     * does not need inter-byte hold times. */
    spi_wr(SPI_IE_FIFO, 0);
    spi_wr(SPI_IE_XFER, 0);
    spi_wr(SPI_WORD_DELAY, 0);

    /* Word size field. The reference driver writes bits_per_word into
     * SHIFTCFG bits 21:16 without an offset, so an 8-bit transfer is 8 and
     * not 7; the same is done here. */
    spi_modify(SPI_SHIFTCFG, SPI_SHIFTCFG_BITS,
               8u << SPI_SHIFTCFG_BITS_SHIFT);

    (void)spi_set_speed(spi_bus_hz);
    spi_initialised = 1;
}

void spi_cs(int high) {
    spi_modify(SPI_PIN, SPI_PIN_CS, high ? SPI_PIN_CS : 0u);
}

int spi_xfer(const uint8_t *tx, uint8_t *rx, uint32_t len) {
    if (len == 0 || len > SPI_MAX_WORDS) return SPI_ERR_RANGE;
    if (!spi_initialised) return SPI_ERR_TIMEOUT;

    spi_wr(SPI_CTRL, SPI_CTRL_TX_RESET | SPI_CTRL_RX_RESET);
    spi_wr(SPI_IF_XFER, 0xFFFFFFFFu);
    spi_wr(SPI_IF_FIFO, 0xFFFFFFFFu);

    spi_wr(SPI_TXCNT, len);
    spi_wr(SPI_RXCNT, len);

    uint32_t sent = 0;    /* words written to TXDATA */
    uint32_t done = 0;    /* words read out of RXDATA */

    while (sent < len && fifo_tx_level() < SPI_FIFO_DEPTH) {
        spi_wr(SPI_TXDATA, tx ? (uint32_t)tx[sent] : 0u);
        sent++;
    }

    spi_wr(SPI_CTRL, SPI_CTRL_RUN);

    uint64_t deadline = timer_now_cycles() +
                        SPI_TIMEOUT_US * (timer_freq_hz() / 1000000ULL);

    while (done < len) {
        while (!fifo_rx_empty() && done < len) {
            uint32_t word = spi_rd(SPI_RXDATA);
            if (rx) rx[done] = (uint8_t)(word & 0xFFu);
            done++;
        }
        while (sent < len && fifo_tx_level() < SPI_FIFO_DEPTH) {
            spi_wr(SPI_TXDATA, tx ? (uint32_t)tx[sent] : 0u);
            sent++;
        }

        if (done >= len) break;

        if ((int64_t)(timer_now_cycles() - deadline) >= 0) {
            spi_wr(SPI_CTRL, 0);
            return SPI_ERR_TIMEOUT;
        }
        timer_sleep_us(50);
    }

    spi_wr(SPI_CTRL, 0);
    return 0;
}

int spi_read_id(uint8_t out[3]) {
    /* One transfer, full duplex: the command byte is shifted out while the
     * first byte comes back in and is discarded, and the three id bytes
     * follow. The controller's FIFOs are full duplex, so there is no need
     * for the two-phase "command, then read" dance a bit-banging master
     * would require. */
    uint8_t tx[4] = { 0x9F, 0, 0, 0 };   /* JEDEC RDID */
    uint8_t rx[4];

    int err = spi_xfer(tx, rx, sizeof(tx));
    if (err != 0) return err;

    out[0] = rx[1];
    out[1] = rx[2];
    out[2] = rx[3];
    return 0;
}

void spi_dump(void) {
    uart_puts("spi: base=0x");
    uart_puts(utoa_hex(SPI_BASE));
    uart_puts(" clk_div=");
    uart_puts(utoa(spi_clk_div));
    uart_puts(" ref=");
    uart_puts(utoa(spi_ref_clk));
    uart_puts("Hz speed=");
    uart_puts(utoa(spi_speed()));
    uart_puts("Hz\n");

    uart_puts("spi: ctrl=0x");
    uart_puts(utoa_hex(spi_rd(SPI_CTRL)));
    uart_puts(" cfg=0x");
    uart_puts(utoa_hex(spi_rd(SPI_CFG)));
    uart_puts(" shiftcfg=0x");
    uart_puts(utoa_hex(spi_rd(SPI_SHIFTCFG)));
    uart_puts(" fifo=0x");
    uart_puts(utoa_hex(spi_rd(SPI_FIFOSTAT)));
    uart_puts(" if=0x");
    uart_puts(utoa_hex(spi_rd(SPI_IF_XFER)));
    uart_puts(spi_ready() ? " ready\n" : " not-ready\n");
}
