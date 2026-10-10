#ifndef SPI_H
#define SPI_H

#include <stdint.h>

/* SPI master on the A11.
 *
 * Layout grounding: the Apple SPI controller is published in
 * drivers/spi/spi-apple.c with the compatible string "apple,spi". The
 * register set below -- CTRL/CFG/STATUS/PIN/TXDATA/RXDATA/CLKDIV/RXCNT/
 * TXCNT and the FIFO status and shift-configuration windows -- is that
 * map. The A11 is not one of the parts that driver names, so this is
 * "same vendor, same IP family", which is a weaker claim than the I2C one
 * and is why every offset here is a define in one place.
 *
 * What is NOT verified: SPI_BASE from memory_map.h, and the reference clock
 * the divider counts from. The reference clock is reported by
 * spi_ref_clk() so a wrong choice shows up as the wrong bus speed rather
 * than as silence.
 *
 * The controller has three completion paths (interrupt, DMA, polled). Only
 * the polled one is implemented: it needs no AIC line and no scatter lists,
 * and the transfers this payload does are a handful of bytes.
 */

/* Control and configuration */
#define SPI_CTRL              0x000
#define SPI_CTRL_RUN          (1u << 0)
#define SPI_CTRL_TX_RESET     (1u << 2)
#define SPI_CTRL_RX_RESET     (1u << 3)

#define SPI_CFG               0x004
#define SPI_CFG_CPHA          (1u << 1)
#define SPI_CFG_CPOL          (1u << 2)
#define SPI_CFG_MODE          ((1u << 6) | (1u << 5))
#define SPI_CFG_MODE_POLLED   0u
#define SPI_CFG_LSB_FIRST     (1u << 13)
#define SPI_CFG_WORD_SIZE     ((1u << 15) | (1u << 16))
#define SPI_CFG_WORD_SIZE_8B  0u
#define SPI_CFG_FIFO_THRESH   ((1u << 17) | (1u << 18))
#define SPI_CFG_FIFO_THRESH_8B 0u

#define SPI_STATUS            0x008
#define SPI_PIN               0x00C
#define SPI_PIN_CS            (1u << 1)

#define SPI_TXDATA            0x010
#define SPI_RXDATA            0x020
#define SPI_CLKDIV            0x030
#define SPI_CLKDIV_MAX        0x7FFu
#define SPI_RXCNT             0x034
#define SPI_TXCNT             0x04C
#define SPI_WORD_DELAY        0x038

#define SPI_FIFOSTAT          0x10C
#define SPI_FIFOSTAT_TXFULL   (1u << 4)
#define SPI_FIFOSTAT_LEVEL_TX ((0xFFu << 8))
#define SPI_FIFOSTAT_RXEMPTY  (1u << 20)
#define SPI_FIFOSTAT_LEVEL_RX ((0xFFu << 24))
#define SPI_FIFOSTAT_LEVEL_TX_SHIFT 8
#define SPI_FIFOSTAT_LEVEL_RX_SHIFT 24

#define SPI_IE_XFER           0x130
#define SPI_IF_XFER           0x134
#define SPI_XFER_RXCOMPLETE   (1u << 0)
#define SPI_XFER_TXCOMPLETE   (1u << 1)

/* FIFO-level interrupt mask/flag windows. Both are written here even though
 * the payload runs polled: clearing the flags is what puts a transfer in a
 * known state, whatever the enables are set to. */
#define SPI_IE_FIFO           0x138
#define SPI_IF_FIFO           0x13c
#define SPI_FIFO_RXTHRESH     (1u << 4)
#define SPI_FIFO_TXTHRESH     (1u << 5)

#define SPI_SHIFTCFG          0x150
#define SPI_SHIFTCFG_CLK_ENABLE (1u << 0)
#define SPI_SHIFTCFG_CS_ENABLE (1u << 1)
#define SPI_SHIFTCFG_CS_AS_DATA (1u << 9)
#define SPI_SHIFTCFG_TX_ENABLE (1u << 10)
#define SPI_SHIFTCFG_RX_ENABLE (1u << 11)
#define SPI_SHIFTCFG_BITS      (0x3Fu << 16)
#define SPI_SHIFTCFG_BITS_SHIFT 16
#define SPI_SHIFTCFG_OVERRIDE_CS (1u << 24)

#define SPI_PINCFG            0x154
#define SPI_PINCFG_KEEP_CLK   (1u << 0)
#define SPI_PINCFG_KEEP_CS    (1u << 1)
#define SPI_PINCFG_KEEP_MOSI  (1u << 2)
#define SPI_PINCFG_CS_IDLE_VAL (1u << 9)
#define SPI_PINCFG_MOSI_IDLE_VAL (1u << 10)

/* FIFO depth. The reference driver hard-codes 16 and uses half of it as its
 * threshold; the same value is used here. */
#define SPI_FIFO_DEPTH        16

/* Longest single transfer. The TXCNT/RXCNT width is not documented, so this
 * stays well inside a 16-bit field. The shell caps its own buffers far
 * below this: a hex argument that long is not something to type by hand. */
#define SPI_MAX_WORDS         4096u

/* Reference clock the divider counts from. 24 MHz is the slowest clock the
 * Apple platform publishes. */
#define SPI_REF_CLK_HZ        24000000u
#define SPI_DEFAULT_HZ        1000000u

#define SPI_ERR_TIMEOUT       (-1)
#define SPI_ERR_RANGE         (-2)

const char *spi_strerror(int err);

void spi_init(void);
int  spi_ready(void);

int  spi_set_speed(uint32_t hz);
uint32_t spi_speed(void);
uint32_t spi_divider(void);

/* Full-duplex transfer of `len` 8-bit words. `tx` or `rx` may be null, in
 * which case the controller is driven with a padding word or its output is
 * discarded. */
int  spi_xfer(const uint8_t *tx, uint8_t *rx, uint32_t len);

/* JEDEC RDID: sends 0x9F and reads back the 3-byte device id. Returns 0
 * and fills `out` with the high byte first. */
int  spi_read_id(uint8_t out[3]);

/* Manual chip-select control. The transfer leaves the line as it found it
 * otherwise; drive it low yourself to hold a peripheral selected across
 * several transfers. */
void spi_cs(int high);

void spi_dump(void);

#endif /* SPI_H */
