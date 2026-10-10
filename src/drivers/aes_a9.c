/* AES engine driver for A11 (T8015) - DCP AES pipe.
 *
 * Based on pongoOS aes_a9.c
 */

#include "aes.h"
#include "uart.h"
#include "mmio.h"
#include "timer.h"
#include "memory_map.h"
#include "string.h"

enum {
    AES_OP_KEY   = 0x10000000,
    AES_OP_IV    = 0x20000000,
    AES_OP_DATA  = 0x50000000,
    AES_OP_FLAGS = 0x80000000,
};

enum {
    AES_FLAG_STOP = 0x04000000,
    AES_FLAG_INT  = 0x08000000,
};

enum {
    AES_BLOCK_START = 1,
    AES_BLOCK_STOP  = 2,
};

static uintptr_t gAESBase;
static uintptr_t gAESPipeBase;
static uint64_t gAESClockAddr;

#define rAES_CTL    *(volatile uint32_t*)(gAESBase + 0x008)
#define rAES_INT    *(volatile uint32_t*)(gAESBase + 0x018)
#define rAES_PIPE   *(volatile uint32_t*)(gAESPipeBase)

void aes_a9_init(void)
{
    gAESBase = DCP_BASE + SOC_DCP_AES_OFFSET;
    gAESPipeBase = gAESBase + SOC_DCP_AES_PIPE_OFFSET;
    gAESClockAddr = SOC_AES_CLK_GATE;

    /* Reset AES engine */
    rAES_CTL = 0;
    timer_sleep_us(10);
}

int aes_a9_crypt_block(enum aes_key_slot slot, int decrypt,
                    const uint8_t input[16], uint8_t output[16],
                    const uint8_t iv[16])
{
    if (!input || !output || !iv || slot > AES_KEY_GID_UID) return -1;

    uint64_t src_addr = (uint64_t)(uintptr_t)input;
    uint64_t dst_addr = (uint64_t)(uintptr_t)output;

    /* Check alignment */
    if ((src_addr & 0xF) || (dst_addr & 0xF)) return -2;

    const uint32_t *u32_key = NULL;
    const uint32_t *u32_iv = (const uint32_t*)iv;

    uint32_t keyid, bits, encrypt, mode;

    switch (slot) {
        case AES_KEY_USER: keyid = 0; break;
        case AES_KEY_UID:  keyid = 1; break;
        case AES_KEY_GID:  keyid = 2; break;
        case AES_KEY_GID_UID: keyid = 3; break;
        default: return -3;
    }
    bits = 2;  // AES-256 only for now
    encrypt = decrypt ? 0 : 1;
    mode = 1;  // CBC mode

    uint32_t op_key = AES_OP_KEY | (keyid << 24) | (bits << 22) | (encrypt << 20) | (mode << 16);

    /* Gate clock */
    mmio_write32(gAESClockAddr, 1);
    timer_sleep_us(10);

    /* Start block */
    rAES_CTL = AES_BLOCK_START;

    /* Push key */
    rAES_PIPE = op_key;
    if (slot == AES_KEY_USER && u32_key) {
        rAES_PIPE = u32_key[0];
        rAES_PIPE = u32_key[1];
        rAES_PIPE = u32_key[2];
        rAES_PIPE = u32_key[3];
        rAES_PIPE = u32_key[4];
        rAES_PIPE = u32_key[5];
        rAES_PIPE = u32_key[6];
        rAES_PIPE = u32_key[7];
    }

    /* Push IV */
    rAES_PIPE = AES_OP_IV;
    if (u32_iv) {
        rAES_PIPE = u32_iv[0];
        rAES_PIPE = u32_iv[1];
        rAES_PIPE = u32_iv[2];
        rAES_PIPE = u32_iv[3];
    } else {
        rAES_PIPE = 0;
        rAES_PIPE = 0;
        rAES_PIPE = 0;
        rAES_PIPE = 0;
    }

    /* Push data */
    rAES_PIPE = AES_OP_DATA | (16 & 0xfffff0);
    rAES_PIPE = ((src_addr >> 16) & 0xFF0000) | ((dst_addr >> 32) & 0xff);
    rAES_PIPE = (uint32_t)src_addr;
    rAES_PIPE = (uint32_t)dst_addr;

    /* Execute */
    rAES_PIPE = AES_OP_FLAGS | AES_FLAG_STOP | AES_FLAG_INT;

    /* Wait for completion */
    while ((rAES_INT & 0x20) == 0) {}
    rAES_INT = 0x20;

    /* End block */
    rAES_CTL = AES_BLOCK_STOP;

    /* Ungate clock */
    mmio_write32(gAESClockAddr, 0);

    return 0;
}

void aes_a9_test(void)
{
    /* Test with known FIPS-197 vector */
    static const uint8_t key[32] = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
    };
    static const uint8_t cipher[16] = {
        0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c,
        0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8
    };
    static const uint8_t expected[16] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
    };
    uint8_t zero_iv[16] = {0};
    uint8_t plain[16];

    uart_puts("aes: testing software AES-256 CBC...\n");
    extern int aes_software_decrypt_cbc(const uint8_t key[32], const uint8_t iv[16],
                                        const uint8_t *ciphertext, uint32_t length,
                                        uint8_t *output);
    if (aes_software_decrypt_cbc(key, zero_iv, cipher, sizeof(cipher), plain) == 0) {
        int match = 1;
        for (unsigned i = 0; i < 16; i++) if (plain[i] != expected[i]) match = 0;
        uart_puts(match ? "aes: AES-256 vector OK\n" : "aes: AES-256 vector FAILED\n");
    } else {
        uart_puts("aes: software path failed\n");
    }
}

/* Shell command: aes [cbc|ecb] [enc|dec] [128|192|256] <uid|gid0|gid1|iv+key> <data> */
void aes_cmd(const char *cmd, char *args)
{
    (void)cmd;
    uart_puts("aes: command not fully implemented - use aes_test for testing\n");
    (void)args;
}