#include "sepos.h"
#include "uart.h"
#include "timer.h"
#include "util.h"
#include "memory_map.h"
#include "usb.h"

/* SEP mailbox protocol implementation */
#define SEP_MAILBOX_BASE MAILBOX_BASE

#define AP_TO_IOP_MSG     0x800
#define AP_TO_IOP_DB      0x808
#define IOP_TO_AP_MSG     0x80C
#define IOP_TO_AP_DB      0x814

static volatile uint32_t *sep_mbox = (volatile uint32_t *)SEP_MAILBOX_BASE;

static inline void sep_write(uint32_t offset, uint32_t val) {
    sep_mbox[offset / 4] = val;
}

static inline uint32_t sep_read(uint32_t offset) {
    return sep_mbox[offset / 4];
}

/* Send command to SEP */
int sep_send_command(uint16_t opcode, const uint8_t *data, uint32_t len) {
    /* Wait for doorbell clear */
    while (sep_read(AP_TO_IOP_DB) != 0) {
        timer_sleep_us(10);
    }
    
    /* Write message */
    uint64_t msg = opcode;
    if (len >= 8) {
        for (int i = 0; i < 8; i++) {
            ((uint8_t *)&msg)[i] = data[i];
        }
    } else {
        for (uint32_t i = 0; i < len; i++) {
            ((uint8_t *)&msg)[i] = data[i];
        }
    }
    
    sep_write(AP_TO_IOP_MSG, msg & 0xFFFFFFFF);
    sep_write(AP_TO_IOP_MSG + 4, (msg >> 32) & 0xFFFFFFFF);
    
    /* Ring doorbell */
    sep_write(AP_TO_IOP_DB, 1);
    
    /* Wait for reply */
    uint32_t timeout = 1000000;
    while (timeout--) {
        uint64_t reply = sep_read(IOP_TO_AP_MSG) | ((uint64_t)sep_read(IOP_TO_AP_MSG + 4) << 32);
        if (reply != 0) {
            /* Acknowledge */
            sep_write(IOP_TO_AP_DB, 1);
            return 0;
        }
        timer_sleep_us(1);
    }
    
    return -1;
}

/* Dump SEPOS via mailbox protocol */
void dump_sepos(void) {
    uart_puts("Dumping SEPOS via SEP mailbox...\n");
    
    /* First, ping SEP */
    if (sep_send_command(0xFF, 0, 0) != 0) {
        uart_puts("SEP ping failed\n");
        return;
    }
    uart_puts("SEP ping OK\n");
    
    /* Get random data (tests SEP crypto) */
    if (sep_send_command(0x10, 0, 0) == 0) {
        uart_puts("Got random data from SEP\n");
    }
    
    /* Try to boot TZ0 (SEPOS) */
    uart_puts("Attempting to boot TZ0...\n");
    if (sep_send_command(0x05, 0, 0) == 0) {
        uart_puts("TZ0 boot command sent\n");
    }
    
    /* Dump SEPOS memory via mailbox */
    uart_puts("SEPOS dump requires SEP-side cooperation\n");
    uart_puts("Use 'sepos memdump <addr> <len>' for memory dump\n");
}

/* SEP memory dump via mailbox */
void sepos_memdump(uint64_t addr, uint32_t len) {
    uart_puts("SEPOS memdump: ");
    uart_puts(utoa_hex(addr));
    uart_puts(" len ");
    uart_puts(utoa(len));
    uart_puts("\n");
    
    /* This would require SEPOS cooperation to read its memory */
    uart_puts("Requires SEPOS-side memory dump command\n");
}

/* SEP mailbox status */
void sepos_status(void) {
    uart_puts("SEP Mailbox Status:\n");
    uart_puts("  AP->IOP_MSG: 0x"); uart_puts(utoa_hex(sep_read(AP_TO_IOP_MSG))); uart_puts("\n");
    uart_puts("  AP->IOP_DB:  0x"); uart_puts(utoa_hex(sep_read(AP_TO_IOP_DB))); uart_puts("\n");
    uart_puts("  IOP->AP_MSG: 0x"); uart_puts(utoa_hex(sep_read(IOP_TO_AP_MSG))); uart_puts("\n");
    uart_puts("  IOP->AP_DB:  0x"); uart_puts(utoa_hex(sep_read(IOP_TO_AP_DB))); uart_puts("\n");
}
