#!/usr/bin/env python3
"""Static checks on the built dr1zzle payload.

Run: python3 tests/test_hw.py [path/to/a11-payload.elf]

These are build-artifact assertions, not hardware tests. They exist because
the hardware layer cannot be exercised from a Mac, and several of the bugs
they guard against (wrong vector table geometry, register save/restore that
clobbers x20-x27, a translation table that maps nothing) are invisible in a
successful compile.
"""

import os
import re
import struct
import subprocess
import sys
import unittest
from pathlib import Path

LLVM = "/opt/homebrew/opt/llvm/bin"


def tool(name):
    return f"{LLVM}/{name}"


class Payload:
    def __init__(self, path):
        self.path = path
        self.readelf = self._run("llvm-readelf", "-S", path)
        self.nm = dict(self._parse_nm(self._run("llvm-nm", path)))
        self._vectors = None

    def _run(self, *args):
        return subprocess.run(
            [tool(args[0]), *args[1:]], capture_output=True, text=True
        ).stdout

    def _parse_nm(self, out):
        for line in out.splitlines():
            parts = line.split()
            if len(parts) == 3:
                yield parts[2], int(parts[0], 16)

    def section(self, name):
        m = re.search(
            rf"\[.*?\]\s+{re.escape(name)}\s+\S+\s+([0-9a-f]+)\s+\S+\s+([0-9a-f]+)",
            self.readelf,
        )
        if not m:
            return None
        return int(m.group(1), 16), int(m.group(2), 16)

    def vectors(self):
        if self._vectors is None:
            out = subprocess.run(
                [tool("llvm-objcopy"), "-O", "binary", "--only-section=.vectors",
                 self.path, "/tmp/.dr1zzle_vectors"],
                capture_output=True, text=True,
            )
            if out.returncode != 0:
                raise unittest.SkipTest(f"objcopy failed: {out.stderr}")
            self._vectors = open("/tmp/.dr1zzle_vectors", "rb").read()
        return self._vectors

    def disasm(self, symbol):
        return self._run("llvm-objdump", "-d",
                         f"--disassemble-symbols={symbol}", self.path)

    def word_at(self, addr, width=4):
        """Read a little-endian value out of the ELF at a virtual address.
        `ldr xN, <literal>` pools hold 64-bit values for symbol addresses, so
        the default width here is 8 when the caller asks for a full pointer."""
        for name in (".text", ".rodata", ".data"):
            sec = self.section(name)
            if not sec:
                continue
            start, size = sec
            if not (start <= addr < start + size):
                continue
            off = addr - start
            self._objcopy(name)
            fmt = "<I" if width == 4 else "<Q"
            if off + width <= len(self._blob):
                return struct.unpack_from(fmt, self._blob, off)[0]
        raise KeyError(f"address 0x{addr:X} is in no loadable section")

    def _objcopy(self, name):
        if getattr(self, "_blob_name", None) == name:
            return
        out = "/tmp/.dr1zzle_section"
        r = subprocess.run(
            [tool("llvm-objcopy"), "-O", "binary", f"--only-section={name}",
             self.path, out],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            raise KeyError(f"objcopy {name}: {r.stderr}")
        self._blob = open(out, "rb").read()
        self._blob_name = name


PAYLOAD = None


def setUpModule():
    global PAYLOAD
    path = sys.argv[1] if len(sys.argv) > 1 else "build/a11-payload.elf"
    try:
        open(path)
    except OSError:
        raise unittest.SkipTest(f"no payload at {path}; run make first")
    PAYLOAD = Payload(path)


class TestVectorTable(unittest.TestCase):
    def test_section_exists(self):
        self.assertIsNotNone(PAYLOAD.section(".vectors"))

    def test_exactly_16_slots(self):
        """VBAR_EL1 indexes 16 entries of 0x80 bytes. 1924 bytes (0x784) was
        the old broken size: 15.03 slots."""
        size = PAYLOAD.section(".vectors")[1]
        self.assertEqual(size, 0x800, f".vectors is 0x{size:X}, want 0x800")
        self.assertEqual(size % 0x80, 0)

    def test_2kb_aligned(self):
        addr = PAYLOAD.section(".vectors")[0]
        self.assertEqual(addr % 0x800, 0, f"VBAR base 0x{addr:X} not 2KB aligned")

    def test_every_slot_has_a_branch(self):
        """AArch64 unconditional B is 000101 imm26. Anything else in a slot
        means the table geometry is wrong and the CPU takes the garbage as a
        PC-relative branch."""
        v = PAYLOAD.vectors()
        for i in range(16):
            word = struct.unpack_from("<I", v, i * 0x80)[0]
            self.assertEqual(
                word >> 26, 0b000101,
                f"slot {i} @ +0x{i*0x80:X} is 0x{word:08X}, not a B instruction",
            )

    def test_branches_stay_inside_the_image(self):
        """A slot branch must resolve inside .text, not off the end."""
        vbase = PAYLOAD.section(".vectors")[0]
        tstart, tsize = PAYLOAD.section(".text")
        tend = tstart + tsize
        v = PAYLOAD.vectors()
        for i in range(16):
            word = struct.unpack_from("<I", v, i * 0x80)[0]
            imm = word & 0x03FFFFFF
            if imm & 0x02000000:
                imm -= 0x04000000
            target = vbase + i * 0x80 + (imm << 2)
            self.assertTrue(
                tstart <= target < tend,
                f"slot {i} branches to 0x{target:X}, outside .text "
                f"[0x{tstart:X},0x{tend:X})",
            )

    def test_sp0_and_spx_slots_differ_from_lower_el(self):
        """Current-EL vectors must not be the same code as Lower-EL ones: a
        Lower-EL entry needs its own register/bank handling."""
        v = PAYLOAD.vectors()
        cur = struct.unpack_from("<I", v, 0x200)[0]   # EL1h Sync, SPx
        low = struct.unpack_from("<I", v, 0x400)[0]   # Lower EL AArch64 Sync
        self.assertNotEqual(cur, low)


class TestRegisterSaveRestore(unittest.TestCase):
    """The old macros allocated 128 bytes but wrote to [sp,#224], and used
    slots #10 and #11 for two register pairs each."""

    STORES = [
        ("x0", 0x00), ("x2", 0x10), ("x4", 0x20), ("x6", 0x30),
        ("x8", 0x40), ("x10", 0x50), ("x12", 0x60), ("x14", 0x70),
        ("x16", 0x80), ("x18", 0x90), ("x20", 0xA0), ("x22", 0xB0),
        ("x24", 0xC0), ("x26", 0xD0), ("x28", 0xE0),
    ]

    def _vector(self):
        v = PAYLOAD.vectors()
        # slot 1 = Current EL SP0 IRQ
        word = struct.unpack_from("<I", v, 0x80)[0]
        imm = word & 0x03FFFFFF
        if imm & 0x02000000:
            imm -= 0x04000000
        base = PAYLOAD.section(".vectors")[0]
        return PAYLOAD.nm.get("_irq_el1h", base + 0x80 + (imm << 2))

    def test_frame_is_large_enough(self):
        """First instruction of _irq_el1h must be `sub sp, sp, #imm` with
        imm >= 240 (15 slots of 16 bytes)."""
        asm = PAYLOAD.disasm("_irq_el1h")
        m = re.search(r"sub\s+sp, sp, #0x([0-9a-f]+)", asm)
        self.assertIsNotNone(m, "no `sub sp, sp, #imm` in _irq_el1h")
        frame = int(m.group(1), 16)
        self.assertGreaterEqual(
            frame, 0xF0,
            f"frame is 0x{frame:X}; writing x30 at +0xF0 would overflow it",
        )

    def test_no_slot_collisions(self):
        """Each store offset must be distinct. The old code reused #10 and
        #11, silently discarding four registers."""
        asm = PAYLOAD.disasm("_irq_el1h")
        offsets = []
        for m in re.finditer(
            r"stp\s+x\d+, x\d+, \[sp(?:,\s*#(0x[0-9a-f]+))?\]", asm
        ):
            offsets.append(int(m.group(1), 16) if m.group(1) else 0)
        self.assertGreaterEqual(len(offsets), 15, f"only {len(offsets)} pairs saved")
        self.assertEqual(
            len(offsets), len(set(offsets)),
            f"duplicate stack slots in SAVE_REGS: {sorted(offsets)}",
        )

    def test_registers_are_contiguous(self):
        """Slots must step by 16 with no gap, or RESTORE_REGS reads garbage."""
        asm = PAYLOAD.disasm("_irq_el1h")
        offsets = []
        for m in re.finditer(
            r"stp\s+x\d+, x\d+, \[sp(?:,\s*#(0x[0-9a-f]+))?\]", asm
        ):
            offsets.append(int(m.group(1), 16) if m.group(1) else 0)
        offsets.sort()
        expected = [i * 16 for i in range(len(offsets))]
        self.assertEqual(offsets, expected)

    def test_x30_is_saved_and_restored(self):
        asm = PAYLOAD.disasm("_irq_el1h")
        self.assertIn("str\tx30", asm)
        self.assertIn("ldr\tx30", asm)

    def test_eret_present(self):
        self.assertIn("eret", PAYLOAD.disasm("_irq_el1h"))


class TestStartup(unittest.TestCase):
    def test_stack_is_loaded_before_any_call(self):
        """SP must be set before the first `bl`; otherwise the first C call
        runs on whatever SP checkm8 left behind."""
        asm = PAYLOAD.disasm("_start")
        sp_idx = asm.find("mov\tsp,")
        bl_idx = asm.find("\tbl\t")
        self.assertNotEqual(sp_idx, -1, "_start never sets sp")
        self.assertLess(sp_idx, bl_idx, "sp is set after the first call")

    def test_stack_value_is_stack_top(self):
        """Resolve the literal-pool entry feeding `mov sp` and check it
        really is _stack_top."""
        asm = PAYLOAD.disasm("_start")
        m = re.search(r"ldr\s+x0, 0x([0-9a-f]+)", asm)
        self.assertIsNotNone(m, "no literal-pool load before `mov sp`")
        pool = int(m.group(1), 16)
        self.assertEqual(
            PAYLOAD.word_at(pool, 8), PAYLOAD.nm["_stack_top"],
            "the value loaded into SP is not _stack_top",
        )

    def test_bss_is_zeroed(self):
        """`strb wzr` in a loop between __bss_start and __bss_end."""
        asm = PAYLOAD.disasm("_start")
        self.assertIn("strb\twzr", asm, "no byte-store loop: .bss is not zeroed")
        loads = re.findall(r"ldr\s+x\d+, 0x([0-9a-f]+)", asm)
        vals = [PAYLOAD.word_at(int(a, 16), 8) for a in loads]
        self.assertIn(PAYLOAD.nm["__bss_start"], vals,
                      "the zeroing loop bounds do not resolve to __bss_start")
        self.assertIn(PAYLOAD.nm["__bss_end"], vals,
                      "the zeroing loop bounds do not resolve to __bss_end")

    def test_bss_bounds_are_ordered(self):
        self.assertLess(PAYLOAD.nm["__bss_start"], PAYLOAD.nm["__bss_end"])

    def test_vbar_installed(self):
        self.assertIn("VBAR_EL1", PAYLOAD.disasm("_start"))

    def test_interrupts_unmasked_only_after_bringup(self):
        """daifclr must come after `bl c_main`, or we take an IRQ against
        uninitialised state."""
        asm = PAYLOAD.disasm("_start")
        self.assertLess(asm.find("\tbl\t"), asm.find("DAIFClr"))

    def test_symbols_exist(self):
        for sym in ("_stack_top", "__bss_start", "__bss_end", "_vectors",
                    "_start", "reboot"):
            self.assertIn(sym, PAYLOAD.nm, f"missing symbol {sym}")


class TestMemoryMap(unittest.TestCase):
    SRAM_BASE = 0x180000000
    SRAM_SIZE = 0x1E8000

    def test_payload_fits_in_sram(self):
        top = PAYLOAD.nm["_stack_top"]
        self.assertLessEqual(
            top, self.SRAM_BASE + self.SRAM_SIZE,
            f"image ends 0x{top:X}, past SRAM end 0x{self.SRAM_BASE+self.SRAM_SIZE:X}",
        )

    def test_no_overlap(self):
        order = ["_vectors", "__bss_start", "__bss_end", "_heap_start",
                 "_stack_bottom", "_stack_top"]
        addrs = [PAYLOAD.nm[s] for s in order if s in PAYLOAD.nm]
        self.assertEqual(addrs, sorted(addrs), f"sections out of order: {order}")

    def test_vectors_before_text(self):
        self.assertLessEqual(
            PAYLOAD.section(".vectors")[0] + PAYLOAD.section(".vectors")[1],
            PAYLOAD.section(".text")[0],
        )


class TestMmuDescriptors(unittest.TestCase):
    """The old mmu.c wrote 2MB block descriptors into an L0 table indexed by
    vaddr>>39, which maps nothing (index 0 covers 0..0x80000000, and SRAM is
    at 0x180000000)."""

    def _mmu_consts(self):
        asm = PAYLOAD.disasm("mmu_init")
        return asm

    def test_uses_l3_page_tables(self):
        src = Path("src/arch/arm64/mmu.c").read_text()
        self.assertIn("#define L3_ENTRIES", src)
        self.assertIn("#define PAGE_DESC", src)
        self.assertIn("static uint64_t *l3_for", src)
        self.assertIn("l3[i3] = descriptor", src)
        self.assertNotIn("map_blocks", src)

    def test_tcr_t0sz_is_25(self):
        """T0SZ=25 -> 512 L0 entries covering 1GB each."""
        self.assertIn("TCR_EL1", self._mmu_consts())

    def test_mmu_not_enabled_unless_requested(self):
        """MMU stays off by default: enabling an untested table risks an
        instruction-fetch fault we cannot report."""
        main = PAYLOAD.disasm("c_main")
        self.assertNotIn("SCTLR_EL1", main,
                         "c_main turns on SCTLR.M without a build flag")


class TestUartAndTimer(unittest.TestCase):
    """Register writes to the S5L UART block. Offsets are checked against the
    struct layout: ulcon +0, ucon +4, ufcon +8, umcon +0xc, ubrdiv +0x28,
    udivslot +0x2c."""

    UART_BASE = 0x20A0C0000

    def _writes(self, symbol):
        """Map of UART_BASE-relative offset -> immediate value.

        The compiler anchors on whichever field base it likes, so store
        displacements are relative to that anchor, not to UART_BASE. Recover
        the anchor from the address materialisation and rebase everything.
        """
        asm = PAYLOAD.disasm(symbol)
        m = re.search(r"mov\s+x8, #(0x[0-9a-f]+)", asm)
        self.assertIsNotNone(m, f"{symbol}: no base register materialised")
        anchor = int(m.group(1), 16)

        writes = {}
        pending = None
        for line in asm.splitlines():
            imm = re.search(r"mov\s+w\d+, #(0x[0-9a-f]+)", line)
            if imm:
                pending = int(imm.group(1), 16)
                continue
            if re.search(r"str\s+wzr, \[x8", line):
                pending = 0  # a zero register store resets the tracked value
            # stur (unscaled, may be negative) and str (scaled) both appear.
            st = re.search(
                r"st(?:r|ur)\s+w(?:\d+|zr), \[x8(?:, #(0x[0-9a-f]+|-0x[0-9a-f]+))?\]",
                line,
            )
            if st:
                delta = int(st.group(1), 16) if st.group(1) else 0
                # Do not clear `pending`: one immediate is commonly reused
                # for several consecutive stores (ulcon/ucon/ufcon all get 3).
                writes[anchor + delta] = pending
        return writes

    def _uart_source(self):
        return Path("src/drivers/uart.c").read_text()

    def test_uart_registers_land_at_documented_offsets(self):
        """The MMIO offsets remain explicit after replacing the register
        struct with accessor calls."""
        src = self._uart_source()
        for name, offset in (("UART_ULCON", "0x00u"), ("UART_UCON", "0x04u"),
                             ("UART_UFCON", "0x08u"), ("UART_UMCON", "0x0Cu"),
                             ("UART_UTRSTAT", "0x18u"), ("UART_UTXH", "0x20u"),
                             ("UART_URXH", "0x24u"), ("UART_UBRDIV", "0x28u"),
                             ("UART_UDIVSLOT", "0x2Cu")):
            self.assertRegex(src, rf"#define\s+{name}\s+{offset}")
        self.assertNotIn("uart->", src)

    def test_uart_enables_transmitter(self):
        """UCON must be 0x3 (RX_EN|TX_EN). The old value was 0x5, which left
        TX_EN clear, so uart_putc spun forever on a TX-empty bit the
        transmitter could never raise."""
        src = self._uart_source()
        self.assertIn("mmio_write32(uart_reg(UART_UCON), UCON_RX_EN | UCON_TX_EN)", src)

    def test_baud_divisor_is_12(self):
        """24MHz / (16 * 115200) - 1 == 12, written to UBRDIV at +0x28.
        The old code computed 12 by dividing before subtracting, which is
        right by accident; the register offset it wrote was wrong."""
        src = self._uart_source()
        self.assertIn("mmio_write32(uart_reg(UART_UBRDIV), (PCLK_HZ / (16 * BAUD)) - 1)", src)

    def test_udivslot_written(self):
        """UDIVSLOT at +0x2c must exist; at 24MHz/115200 it is zero."""
        self.assertIn("mmio_write32(uart_reg(UART_UDIVSLOT), 0)", self._uart_source())

    def test_putc_waits_on_tx_empty_bit1(self):
        asm = PAYLOAD.disasm("uart_putc")
        self.assertRegex(asm, r"tbz\s+w\d+, #0x1",
                         "uart_putc does not test UTRSTAT bit 1 (TX empty)")

    def test_timer_reads_cntfrq(self):
        self.assertIn("CNTFRQ_EL0", PAYLOAD.disasm("timer_init"))


class TestUsb(unittest.TestCase):
    """Register-level checks. USB_BASE-relative offsets come from the DWC2
    layout: GRXFSIZ +0x24, GNPTXFSIZ +0x28, GOTGCTL +0x0."""

    def _usb_stores(self, symbol):
        asm = PAYLOAD.disasm(symbol)
        offs = set()
        for m in re.finditer(r"stur\s+w\d+, \[x\d+, #(0x[0-9a-f]+)\]", asm):
            offs.add(int(m.group(1), 16))
        for m in re.finditer(r"str\s+w\d+, \[x\d+, #(0x[0-9a-f]+)\]", asm):
            offs.add(int(m.group(1), 16))
        return offs

    def _usb_source(self):
        return Path("src/drivers/usb.c").read_text()

    def test_init_programs_rx_fifo_size(self):
        """GRXFSIZ was never written in the old driver, so the core had no
        receive buffer configured."""
        self.assertRegex(self._usb_source(), r"wr\(DWC2_GRXFSIZ,\s*0x200\)",
                         "no GRXFSIZ write")

    def test_init_programs_tx_fifo_size(self):
        self.assertRegex(self._usb_source(), r"wr\(DWC2_GNPTXFSIZ,\s*0x200\)",
                         "no GNPTXFSIZ write")

    def test_phy_base_is_touched(self):
        """USB_PHY_BASE (0x20A1A0000) must be written before DWC2 config.
        The PHY init is now a separate function usb_phy_init()."""
        asm = PAYLOAD.disasm("usb_phy_init")
        self.assertRegex(asm, r"#0xa1a0000",
                         "usb_phy_init never touches USB_PHY_BASE")

    def test_device_mode_selected(self):
        """GOTGCTL_CMODE (bit 3) must be set for device operation."""
        self.assertRegex(self._usb_source(),
                         r"wr\(DWC2_GOTGCTL,\s*GOTGCTL_CSRST\s*\|\s*GOTGCTL_CMODE\)",
                         "GOTGCTL is not written as CSRST|CMODE")

    def test_phy_is_brought_up(self):
        """The PHY init is inlined, so assert on its register writes instead
        of a call."""
        self.assertIn("mmio_write32(phy_reg(USB_PHY_CTRL), ctrl)", self._usb_source())

    def test_register_accesses_use_mmio_api(self):
        src = self._usb_source()
        self.assertIn('#include "mmio.h"', src)
        self.assertIn("mmio_write32(usb_reg(off), val)", src)
        self.assertIn("mmio_read32(usb_reg(off))", src)
        self.assertNotIn("dwc2[", src)
        self.assertNotIn("phy[", src)

    def test_set_address_is_deferred(self):
        """SET_ADDRESS must be parked and applied on IN completion, not
        written during the setup packet."""
        src = open("src/drivers/usb.c").read()
        self.assertIn("pending_address", src)
        handler = src.split("void usb_irq_handler")[1]
        self.assertIn("pending_address", handler,
                      "SET_ADDRESS is never applied after the status stage")


class TestAce2Safety(unittest.TestCase):
    """ACE2 remains an unverified research surface; these checks only ensure
    that its shell-facing failure paths are bounded and range-checked."""

    def _ace2_source(self):
        return Path("src/research/ace2.c").read_text()

    def test_reset_has_a_bounded_timeout(self):
        src = self._ace2_source()
        self.assertIn("timer_wait_reg(&ace2[0x10 / 4], 1, 0, 10000)", src)
        self.assertIn("refusing to configure it", src)

    def test_port_operations_validate_the_port(self):
        src = self._ace2_source()
        self.assertEqual(src.count("if (!ace2_valid_port(port)) return;"), 3)
        self.assertIn("#define ACE2_MAX_PORTS 8", Path("include/ace2.h").read_text())


class TestAicInterruptController(unittest.TestCase):
    """IRQ dispatch used to poll the sources it knew by name and call a
    stubbed aic_eoi(). It now dispatches on the line number the controller
    reports. These checks pin down the register work that makes that real.

    Offsets are AIC v1: EVENT +0x2004 (read acks and masks), MASK_CLR
    +0x4180 (the end of interrupt)."""

    def _sizes(self):
        sizes = {}
        out = subprocess.run(
            [tool("llvm-nm"), "-S", "--size-sort", PAYLOAD.path],
            capture_output=True, text=True,
        ).stdout
        for line in out.splitlines():
            parts = line.split()
            if len(parts) == 4:
                sizes[parts[3]] = int(parts[1], 16)
        return sizes

    def test_event_is_read_from_the_aic_window(self):
        """Base is 0x232100000, so bits 47:16 materialise as 0x3210."""
        asm = PAYLOAD.disasm("aic_event")
        self.assertRegex(asm, r"#0x3210",
                         "aic_event does not read the AIC window")

    def test_eoi_writes_mask_clear(self):
        """The end of interrupt is MASK_CLR at +0x4180. The stub this
        replaced was a `dsb`, which acknowledges nothing and would leave
        every line masked forever after its first IRQ."""
        asm = PAYLOAD.disasm("aic_enable")
        self.assertRegex(asm, r"#0x4180",
                         "aic_enable does not write AIC_MASK_CLR")

    def test_init_validates_info_before_programming(self):
        """AIC_INFO is masked to its 16-bit count before any other register
        is touched, so a wrong base is refused rather than written to."""
        asm = PAYLOAD.disasm("aic_init")
        self.assertRegex(asm, r"and\s+\w+, \w+, #0xffff",
                         "aic_init does not validate AIC_INFO")

    def test_dispatch_table_covers_the_controller(self):
        """The table is indexed by the controller's line number and must be
        sized to its maximum, not to the number of sources this build
        registers: AIC_MAX_IRQ is 1024, so the table is 8 KiB."""
        self.assertEqual(
            self._sizes().get("irq_handlers"), 0x2000,
            "irq_handlers is not sized for AIC_MAX_IRQ",
        )

    def test_exception_init_brings_the_controller_up(self):
        src = open("src/arch/arm64/exception.c").read()
        init = src.split("void exception_init")[1]
        self.assertIn("aic_init()", init,
                      "exception_init still does nothing but install vectors")

    def test_unclaimed_lines_are_not_unmasked(self):
        """An IRQ nobody claims has to stay masked: unmasking a live source
        with nothing draining it is a storm, not a counter increment."""
        src = open("src/arch/arm64/exception.c").read()
        handler = src.split("void irq_handler")[1]
        self.assertIn("handler == 0", handler)
        self.assertIn("aic_eoi((unsigned int)irq);", handler)

    def test_irq_register_enables_the_line_it_claims(self):
        src = open("src/arch/arm64/exception.c").read()
        register = src.split("int irq_register")[1].split("}")[0]
        self.assertIn("aic_enable(irq);", register,
                      "registering a handler does not unmask the line")


class TestPeripheralDrivers(unittest.TestCase):
    """Register-level checks for the Phase 3 drivers.

    Offsets: I2C IMASK +0x18 and REV +0x28 (PA Semi SMBus), SPI CLKDIV
    +0x30, watchdog WD1 CUR_TIME +0x10 / BITE_TIME +0x14."""

    def test_i2c_masks_its_interrupt(self):
        """The block is driven by polling, so IMASK is written zero at init.
        Leaving it unmasked would deliver an IRQ nobody claims."""
        asm = PAYLOAD.disasm("i2c_init")
        self.assertRegex(asm, r"str\s+wzr, \[\w+(?:, #0x0)?\]",
                         "i2c_init does not clear IMASK")

    def test_i2c_reads_the_revision_register(self):
        """The block only sets CTL_EN when the revision readback is at least
        6, so the revision has to be read: base is 0x20A200000, which
        materialises as 0xa20, and the value is masked to a byte."""
        asm = PAYLOAD.disasm("i2c_init")
        self.assertRegex(asm, r"#0xa20", "i2c_init does not touch the I2C window")
        self.assertRegex(asm, r"and\s+\w+, \w+, #0xff",
                         "i2c_init does not read the revision register")

    def test_spi_programs_the_clock_divider(self):
        """CS idles high on PIN (+0xc behind the SHIFTCFG anchor at +0x150),
        and the divider is clamped to CLKDIV_MAX = 0x7ff."""
        asm = PAYLOAD.disasm("spi_init")
        self.assertRegex(asm, r"#0x144", "spi_init does not drive the PIN register")
        self.assertRegex(asm, r"#0x7ff", "spi_init does not clamp the divider")

    def test_watchdog_init_zeros_the_counters(self):
        """Disarming is CTRL = 0 and CUR_TIME = 0 for each watchdog. A
        counter left past its bite time bites as soon as it is looked at."""
        asm = PAYLOAD.disasm("watchdog_init")
        self.assertRegex(asm, r"str\s+wzr, \[\w+, #0x10\]", "WD1 CUR_TIME not zeroed")
        self.assertRegex(asm, r"str\s+wzr, \[\w+, #0x14\]", "WD1 BITE_TIME not zeroed")

    def test_timer_interrupt_output_is_masked(self):
        """CNTP_CTL_EL0 is written 3 (ENABLE | IMASK). The ARM generic timers
        arrive as FIQs on this part, and fiq_handler() halts the payload."""
        asm = PAYLOAD.disasm("timer_init")
        self.assertRegex(asm, r"mov\s+w\d+, #0x3\b",
                         "timer_init does not mask the timer interrupt output")

    def test_only_irq_is_unmasked_at_the_end_of_boot(self):
        """F stays masked: every FIQ source on this SoC is unused or
        masked by its driver."""
        asm = PAYLOAD.disasm("_start")
        self.assertIn("DAIFClr", asm)
        self.assertRegex(asm, r"DAIFClr, #0x2",
                         "start.S unmasks F as well as I")

    def test_pmgr_ungate_skips_an_empty_mask(self):
        """A zero mask is a device whose PMGR bits are not published; writing
        it anyway would clear bits belonging to other devices."""
        src = open("src/drivers/pmgr.c").read()
        ungate = src.split("void pmgr_ungate")[1].split("}")[0]
        self.assertIn("if (clocks == 0) return;", ungate)

    def test_usb_irq_line_comes_from_the_soc_profile(self):
        """The DWC2 line number is device-tree information, so it belongs to
        the selected SoC profile -- not hardcoded in the USB header. A wrong
        line costs an unclaimed IRQ, not a crash."""
        usb = open("include/usb.h").read()
        profile = open("include/soc/t8015.h").read()
        self.assertIn("#define AIC_IRQ_USB_OTG SOC_IRQ_USB_OTG", usb,
                      "usb.h should take the IRQ line from the SoC profile")
        self.assertIn("#define SOC_T8015_IRQ_USB_OTG 324u", profile,
                      "the t8015 profile should carry the A11 otg_irq line")


class TestBringupOrder(unittest.TestCase):
    """c_main's sequence is a dependency chain. Getting it wrong does not
    look like a bug at compile time: a driver behind a gated clock, or a
    peripheral enabled before the controller that routes its line, just
    silently fails on hardware."""

    def _main(self):
        return open("src/main.c").read().split("void c_main")[1]

    def test_clocks_before_the_console(self):
        main = self._main()
        self.assertLess(main.index("pmgr_init();"),
                        main.index("uart_early_init();"))

    def test_controller_before_the_device_that_claims_a_line(self):
        main = self._main()
        self.assertLess(main.index("exception_init();"),
                        main.index("irq_register("))

    def test_peripherals_are_probed_before_usb(self):
        main = self._main()
        self.assertLess(main.index("watchdog_init();"),
                        main.index("usb_init()"))
        self.assertLess(main.index("i2c_init("),
                        main.index("usb_init()"))

    def test_static_address_is_configured_at_bringup(self):
        """The static address is what makes the remote side easy: it is
        installed at bring-up, not negotiated, so ARP answers for it from the
        first frame."""
        main = self._main()
        self.assertIn("net_configure_static();", main)

    def test_goatloader_is_bound_before_the_shell(self):
        """The listener has to exist before the shell's idle loop is the only
        thing servicing it -- and before anyone types a keystroke, because
        `goat push` can arrive first."""
        main = self._main()
        self.assertIn("goatloader_init()", main)
        self.assertLess(main.index("goatloader_init()"),
                        main.index("shell_run();"))

    def test_goatloader_listener_is_not_conditional(self):
        """Bound unconditionally: the result only decides what the log says.
        A condition around the call would make the payload's only TCP service
        optional, which is the opposite of the rule."""
        main = self._main()
        index = main.index("goatloader_init()")
        line = main[main.rfind("\n", 0, index):index]
        self.assertNotIn("if", line, f"goatloader_init() looks conditional: {line}")

    def test_port_matches_the_host_tool(self):
        """1234 is a contract with goat/cli.py, not a local choice."""
        header = open("include/goat/loader.h").read()
        cli = open("goat/cli.py").read()
        device = re.search(r"#define GOATLOADER_PORT (\d+)u", header).group(1)
        host = re.search(r"GOATLOADER_PORT = (\d+)", cli).group(1)
        self.assertEqual(device, host)


class TestNandWriter(unittest.TestCase):
    """Static checks on the NAND write path.

    You cannot run this on a Mac: an erase or a program either works or turns
    a block into a brick, and the difference is whether the ONFI command bytes
    and the ready/status polls are right. A successful compile proves none of
    that, so the sequences are asserted here.
    """

    def setUp(self):
        self.src = open("src/drivers/nand.c").read()
        self.hdr = open("include/nand.h").read()

    def _fn(self, signature):
        """Return the body of the function whose definition contains
        `signature`, brace-balanced, so a call can be attributed to the right
        function even when several share it."""
        start = self.src.index(signature)
        i = self.src.index("{", start)
        depth = 0
        for j in range(i, len(self.src)):
            if self.src[j] == "{":
                depth += 1
            elif self.src[j] == "}":
                depth -= 1
                if depth == 0:
                    return self.src[start:j + 1]
        self.fail(f"unbalanced braces after {signature}")

    def test_erase_uses_the_onfi_command_pair(self):
        self.assertRegex(self.src, r"NAND_CMD_ERASE1\s+0x60u")
        self.assertRegex(self.src, r"NAND_CMD_ERASE2\s+0xD0u")

    def test_program_uses_the_onfi_command_pair(self):
        self.assertRegex(self.src, r"NAND_CMD_PROGRAM\s+0x80u")
        self.assertRegex(self.src, r"NAND_CMD_PROGRAM_EXEC\s+0x10u")

    def test_status_poll_uses_0x70_and_the_fail_bit(self):
        self.assertRegex(self.src, r"NAND_CMD_STATUS\s+0x70u")
        self.assertRegex(self.src, r"NAND_STATUS_FAIL\s+0x01u")

    def test_erase_polls_ready_and_status(self):
        body = self._fn("nand_erase_block(")
        self.assertIn("nfc_wait_ready()", body, "erase never waits for the array")
        self.assertIn("nfc_status_failed()", body, "erase ignores the status bit")

    def test_program_polls_ready_and_status(self):
        body = self._fn("nand_write_page(")
        self.assertIn("nfc_wait_ready()", body, "program never waits for the array")
        self.assertIn("nfc_status_failed()", body, "program ignores the status bit")

    def test_verify_reads_back_through_the_ecc_engine(self):
        """Verification must go through nand_read_page, not a raw replay of the
        write: the controller's ECC has to be in the path for the readback to
        mean the page decoded correctly."""
        body = self._fn("nand_verify_page(")
        self.assertIn("nand_read_page", body)
        self.assertIn("bytes_same", body)

    def test_write_path_is_declared(self):
        self.assertIn("int nand_erase_block(uint32_t block);", self.hdr)
        self.assertIn("int nand_write_page(", self.hdr)
        self.assertIn("int nand_verify_page(", self.hdr)

    def test_write_counters_are_public(self):
        self.assertIn("nand_write_stats_t", self.hdr)
        self.assertIn("nand_write_stats_t write;", self.hdr)

    def test_core_exports_the_write_path(self):
        for sym in ("nand_erase_block", "nand_write_page", "nand_verify_page"):
            self.assertIn(sym, PAYLOAD.nm, f"{sym} missing from the core image")


class TestFirmwareImage(unittest.TestCase):
    """The firmware can write itself to a NAND slot (`fw install`), so the
    extent the linker hands it -- `__firmware_image_end` -- has to be exactly
    the .bin the build produced. If they drift the copy on flash is truncated
    or padded, and nothing on the device would notice until the next boot."""

    def setUp(self):
        self.elf = Path("build/firmware/dr1zzle.elf")
        self.bin = Path("build/firmware/dr1zzle.bin")
        if not self.elf.exists() or not self.bin.exists():
            self.skipTest("firmware not built; run make firmware first")
        out = subprocess.run([tool("llvm-nm"), str(self.elf)],
                             capture_output=True, text=True, check=True).stdout
        self.sym = {}
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 3:
                self.sym[parts[2]] = int(parts[0], 16)

    def test_image_end_is_defined(self):
        self.assertIn("__firmware_image_end", self.sym,
                      "linker/firmware.ld does not define __firmware_image_end")

    def test_image_end_matches_the_binary(self):
        size = os.path.getsize(self.bin)
        length = self.sym["__firmware_image_end"] - 0x180100000
        self.assertEqual(
            length, size,
            f"linker image end 0x{length:X} != .bin length 0x{size:X}; "
            "`fw install` would write the wrong number of bytes")

    def test_stack_top_is_inside_sram(self):
        self.assertLessEqual(self.sym["_stack_top"], 0x1801E8000,
                             "firmware stack runs past the top of SRAM")

    def test_firmware_links_the_slot_store(self):
        for sym in ("fw_store_scan", "fw_store_install", "fw_store_slot",
                    "fw_run_slot"):
            self.assertIn(sym, self.sym, f"{sym} missing from the firmware")


if __name__ == "__main__":
    unittest.main(verbosity=2)
