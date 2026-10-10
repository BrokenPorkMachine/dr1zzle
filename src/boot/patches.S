/*
 * dr1zzle - iBoot patches for A11 (T8015)
 * Based on pongoOS patches.S
 */

// ********************************************************
// **                                                    **
// ** THIS FILE IS SHARED BETWEEN DR1ZZLE AND CHECKRA1N! **
// **                                                    **
// **   MAKE SURE ANY EDIT IS REFLECTED IN BOTH REPOS!   **
// **                                                    **
// ********************************************************

.align 2

// void iorvbar_yeet(volatile void *boot_image)
/*
 * RVBAR_ELx is controlled by the IORVBAR MMIO register.
 * Each CPU has one, obtainable from its DeviceTree entry, "reg-private" property +0x40000.
 * 
 * For A11:
 *   PCORE0: 0x208450000  PCORE1: 0x208550000
 *   ECORE0: 0x208050000  ECORE1: 0x208150000
 *   ECORE2: 0x208250000  ECORE3: 0x208350000
 * 
 * Bits [63:36] readonly, Bits [35:11] = RVBAR address (mask 0xffffff800),
 * Bits [10:1] res0, Bit [0] locks the register.
 * 
 * We find the instruction sequence:
 *   and xN, x0, 0xfffffffffffff800
 *   orr xM, xN, 1
 * And replace the orr with orr xM, xN, xzr (don't lock)
 */

.globl iorvbar_yeet
iorvbar_yeet:
    mov x2, x0                    // x2 = boot_image pointer
    movz w5, 0x9275, lsl 16       // and xN, x0, 0xfffffffffffff800
    movk w5, 0xd000
    movz w6, 0xb240, lsl 16       // orr xM, xN, 1
    movz w7, 0xaa1f, lsl 16       // orr xM, xN, xzr
1:
    ldr w3, [x2], 0x4
    and w4, w3, 0xffffffe0
    cmp w4, w5
    b.ne 1b
    // Match orr with immediate
    bfi w6, w3, 5, 5
    ldr w4, [x2]
    and w3, w4, 0xffffffe0
    cmp w3, w6
    b.eq 2f
    b 1b
2:
    // Patch: replace orr-immediate with orr-register (xzr)
    bfi w7, w4, 0, 10
    str w7, [x2]
    dmb sy
    isb sy
    ret


// void aes_keygen(volatile void *boot_image)
/*
 * A11 AES_DISABLE at 0x2352d0000
 * We find two calls to security_allow_modes() with 0x40000 and 0x80000,
 * then the call to platform_disable_keys() - we patch it to ret.
 */

.globl aes_keygen
aes_keygen:
    mov x2, x0                    // x2 = boot_image pointer
    movz w7, 0x320e, lsl 16       // orr w0, wzr, 0x40000
    movk w7, 0x03e0
    movz w8, 0x52a0, lsl 16       // mov w0, 0x40000
    movk w8, 0x0080
    movz w9, 0xaa00, lsl 16       // mov x{16-31}, x0
    movk w9, 0x03f0
    sub w10, w7, 0x10, lsl 12     // orr w0, wzr, 0x80000
    add w11, w8, 0x80             // mov w0, 0x80000
1:
    // First call: orr w0, wzr, 0x40000
    ldr w3, [x2], 0x4
    cmp w3, w7
    ccmp w3, w8, 4, ne
    b.ne 1b
    // Next: mov x{16-31}, x0 then orr w0, wzr, 0x80000
    ldp w3, w4, [x2, 0x4]
    and w3, w3, 0xfffffff0
    cmp w4, w10
    ccmp w4, w11, 4, ne
    ccmp w3, w9, 0, eq
    b.ne 1b
    // Next two instructions should be bl to same target
    ldr w3, [x2]
    ldr w4, [x2, 0xc]
    sub w3, w3, w4
    ubfx w4, w4, 26, 6
    cmp w4, 0x25
    ccmp w3, 0x3, 0, eq
    b.ne 1b

    // Second loop: find following bl (platform_disable_keys)
    add x2, x2, 0xc
2:
    ldr w3, [x2, 0x4]!
    ubfx w4, w3, 26, 6
    cmp w4, 0x25
    b.ne 2b
    sbfx w3, w3, 0, 26
    ldr w7, Lol
    str w7, [x2, w3, sxtw 2]
    dmb sy
    isb sy
Lol:
    ret


// void recfg_yoink(volatile void *boot_image)
/*
 * A11 recfg: AOP_CFG_TABLE=0x2352c0200, AOP_CFG_LOCK=0x2352c0214,
 * AOP_SRAM_LOCK_RANGE=0x235000200, AOP_SRAM_LOCK_SET=0x235000204
 * 
 * Find three calls to reconfig_init/insert/lock with BOOT_DARWIN (3),
 * patch the last one (reconfig_lock) to ret.
 */

.globl recfg_yoink
recfg_yoink:
    mov x2, x0
    movz w8, 0x3200, lsl 16       // orr w0, wzr, 3
    movk w8, 0x07e0
    movz w9, 0x5280, lsl 16       // mov w0, 3
    movk w9, 0x0060
    movz w10, 0x25                // bl top bits
1:
    ldr w3, [x2], 0x4
    cmp w3, w8
    ccmp w3, w9, 4, ne
    b.ne 1b
    ldp w3, w4, [x2]
    ldp w5, w6, [x2, 0x8]
    ldr w7, [x2, 0x10]
    ubfx w3, w3, 26, 6
    ubfx w5, w5, 26, 6
    cmp w4, w8
    ccmp w4, w9, 4, ne
    b.ne 1b
    cmp w6, w8
    ccmp w6, w9, 4, ne
    ubfx w4, w7, 26, 6
    ccmp w3, w10, 0, eq
    ccmp w5, w10, 0, eq
    ccmp w4, w10, 0, eq
    b.ne 1b

    // Patch the last call (reconfig_lock) to ret
    add x2, x2, 0x10
    sbfx w7, w7, 0, 26
    ldr w3, Lul
    str w3, [x2, w7, sxtw 2]
    dmb sy
    isb sy
Lul:
    ret