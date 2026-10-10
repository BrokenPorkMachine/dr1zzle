"""Host-only checks for goat: image planning (kload) and the loader plumbing.

These run without a device. The device side is exercised through a fake that
records what it was asked to write, so a regression in chunking, in the
readback verify, in the register order of the jump, or in the handoff wait
fails here instead of on hardware.
"""

import struct
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from goat import cli, container, kload, rsa  # noqa: E402

ARTIFACT_ELF = ROOT / "build" / "a11-payload.elf"

ET_EXEC = 2
EM_AARCH64 = 183
PT_LOAD = 1


def make_elf(entry=0x180001000, segments=((0x180000000, 0x2000, b"A" * 0x2000),))\
        :
    """A minimal AArch64 ET_EXEC ELF with the given entry and PT_LOADs."""
    phoff = 64
    phentsize = 56
    body = b""
    headers = b""
    cursor = phoff + phentsize * len(segments)
    for vaddr, memsz, blob in segments:
        blob = bytes(blob)
        memsz = max(memsz, len(blob))     # .bss is allowed, never the reverse
        headers += struct.pack("<IIQQQQQQ", PT_LOAD, 0, cursor, vaddr, vaddr,
                               len(blob), memsz, 0x1000)
        body += blob
        cursor += len(blob)

    ehdr = b"\x7fELF" + bytes([kload.ELFCLASS64, kload.ELFDATA2LSB, 1, 0, 0]) \
        + b"\0" * 7
    ehdr += struct.pack("<HHIQQQIHHHHHH", ET_EXEC, EM_AARCH64, 1, entry, phoff,
                        0, 0, 64, phentsize, len(segments), 64, 0, 0)
    assert len(ehdr) == phoff, len(ehdr)
    return ehdr + headers + body


class FakeDevice:
    """A pwndfu device that keeps every byte it is handed."""

    def __init__(self, serial="CPID:8015 CPRV:11 PWND:[checkm8]"):
        self.serial = serial
        self.usb = FakeUsb(present=True)
        self.memory = bytearray(1 << 26)
        self.writes = []           # (address, length) in order
        self.commands = []         # raw command framings, for arg checks
        self.closed = False
        self.fail_write_at = None  # corrupt the next write of this address

    def _base(self):
        return 0x180000000

    def write_memory(self, address, data, chunk=0x1000):
        data = bytes(data)
        for off in range(0, len(data), chunk):
            part = data[off:off + chunk]
            if self.fail_write_at is not None and \
                    address + off == self.fail_write_at:
                part = part[:len(part) // 2]      # short write
            start = address + off - self._base()
            self.memory[start:start + len(part)] = part
            self.writes.append((address + off, len(part)))

    def read_memory(self, address, length):
        start = address - self._base()
        return bytes(self.memory[start:start + length])

    def execute(self, entry, *args):
        self.commands.append((entry,) + tuple(args))
        self.entry = entry

    def close(self):
        self.closed = True


class FakeUsb:
    def __init__(self, present=True):
        self.present = present
        self.probes = 0

    def dfu_present(self):
        self.probes += 1
        if isinstance(self.present, list):
            return self.present.pop(0) if len(self.present) > 1 \
                else self.present[0]
        return self.present


class GoatIdentity:
    """A throwaway sealing identity for container tests."""

    key = bytes(range(32))

    def __init__(self):
        priv = rsa.keygen(1024)
        self.doc = {
            "serial": 1, "issuer": "goat test", "subject": "goat test",
            "not_before": 0, "not_after": 4102444800,
            "n": priv["n"], "e": priv["e"], "d": priv["d"],
        }
        self.cert, _ = rsa.build_cert(self.doc, self.doc)


class TestSniff(unittest.TestCase):
    def test_each_form_is_recognised(self):
        ident = GoatIdentity()
        sealed = container.seal(b"payload" * 64, GoatIdentity.key, ident.doc,
                                0x180180000, 0x40)
        self.assertEqual(kload.sniff(make_elf()), kload.KIND_ELF)
        self.assertEqual(kload.sniff(sealed), kload.KIND_CONTAINER)
        self.assertEqual(kload.sniff(b"\x00" * 4096), kload.KIND_RAW)
        self.assertEqual(kload.sniff(b"dr1zzle"), kload.KIND_RAW)

    def test_der_that_is_not_a_container_is_raw(self):
        # A SEQUENCE of something else must not be mistaken for a container.
        other = b"\x30\x03\x02\x01\x2a"
        self.assertEqual(kload.sniff(other), kload.KIND_RAW)
        self.assertEqual(kload.sniff(b"\x30\x80"), kload.KIND_RAW)


class TestElfParsing(unittest.TestCase):
    def test_two_segments_keep_their_placement(self):
        blob = b"B" * 0x40
        elf = make_elf(segments=[(0x180000000, 0x1000, b"A" * 0x2000),
                                 (0x180017000, 0x1000, blob)])
        entry, segments = kload.parse_elf(elf)
        self.assertEqual(entry, 0x180001000)
        self.assertEqual([addr for addr, _ in segments], [0x180000000,
                                                         0x180017000])
        self.assertEqual(segments[1][1], blob)

    def test_bss_is_not_sent(self):
        # memsz above filesz means .bss: only file bytes travel.
        elf = make_elf(segments=[(0x180000000, 0x8000, b"A" * 0x2000)])
        _, segments = kload.parse_elf(elf)
        self.assertEqual(len(segments), 1)
        self.assertEqual(len(segments[0][1]), 0x2000)

    def test_paddr_is_used_when_set(self):
        phoff, phentsize = 64, 56
        blob = b"C" * 0x20
        phase = struct.pack("<IIQQQQQQ", PT_LOAD, 0, phoff + phentsize,
                            0, 0x180000000, len(blob), 0x1000, 0x1000)
        ehdr = b"\x7fELF" + bytes([2, 1, 1, 0, 0]) + b"\0" * 7
        ehdr += struct.pack("<HHIQQQIHHHHHH", ET_EXEC, EM_AARCH64, 1,
                            0x180001000, phoff, 0, 0, 64, phentsize, 1, 64, 0,
                            0)
        elf = ehdr + phase + blob
        _, segments = kload.parse_elf(elf)
        self.assertEqual(segments[0][0], 0x180000000)

    def test_rejects_foreign_elves(self):
        cases = {
            "32-bit": b"\x7fELF" + bytes([1, 1, 1, 0, 0]) + b"\0" * 7
                      + struct.pack("<HHIQQQIHHHHHH", ET_EXEC, EM_AARCH64, 1,
                                    0x180001000, 64, 0, 0, 52, 32, 1, 32, 0, 0),
            "big-endian": b"\x7fELF" + bytes([2, 2, 1, 0, 0]) + b"\0" * 7
                          + struct.pack("<HHIQQQIHHHHHH", ET_EXEC, EM_AARCH64, 1,
                                        0x180001000, 64, 0, 0, 64, 56, 1, 64, 0,
                                        0),
            "wrong machine": b"\x7fELF" + bytes([2, 1, 1, 0, 0]) + b"\0" * 7
                             + struct.pack("<HHIQQQIHHHHHH", ET_EXEC, 3, 1,
                                           0x180001000, 64, 0, 0, 64, 56, 1, 64,
                                           0, 0),
            "not executable": b"\x7fELF" + bytes([2, 1, 1, 0, 0]) + b"\0" * 7
                              + struct.pack("<HHIQQQIHHHHHH", 1, EM_AARCH64, 1,
                                            0x180001000, 64, 0, 0, 64, 56, 1, 64,
                                            0, 0),
            "no segments": b"\x7fELF" + bytes([2, 1, 1, 0, 0]) + b"\0" * 7
                           + struct.pack("<HHIQQQIHHHHHH", ET_EXEC, EM_AARCH64, 1,
                                         0x180001000, 64, 0, 0, 64, 56, 0, 64, 0,
                                         0),
            "no entry": b"\x7fELF" + bytes([2, 1, 1, 0, 0]) + b"\0" * 7
                        + struct.pack("<HHIQQQIHHHHHH", ET_EXEC, EM_AARCH64, 1, 0,
                                      64, 0, 0, 64, 56, 1, 64, 0, 0)
                        + struct.pack("<IIQQQQQQ", PT_LOAD, 0, 128, 0x180000000,
                                      0x180000000, 16, 16, 0x1000) + b"D" * 16,
        }
        for name, elf in cases.items():
            with self.subTest(name):
                with self.assertRaises(kload.KloadError):
                    kload.parse_elf(elf)


class TestPlan(unittest.TestCase):
    def setUp(self):
        self.image = b"\xcc" * 0x3000        # past the +0x1000 default entry

    def test_raw_defaults_to_the_linker_layout(self):
        plan_ = kload.plan_image(self.image)
        self.assertEqual(plan_.kind, kload.KIND_RAW)
        self.assertEqual(plan_.load_base, 0x180000000)
        self.assertEqual(plan_.entry, 0x180001000)
        self.assertFalse(plan_.staged)
        self.assertEqual(plan_.size, 0x3000)

    def test_stage_and_entry_override_a_raw_image(self):
        plan_ = kload.plan_image(self.image, stage=0x1800A0000, entry=0x1800A0400)
        self.assertEqual(plan_.load_base, 0x1800A0000)
        self.assertEqual(plan_.entry, 0x1800A0400)
        # The entry follows the image when it is relocated by --stage.
        self.assertEqual(kload.plan_image(self.image, stage=0x1800A0000).entry,
                         0x1800A1000)

    def test_elf_placement_comes_from_the_file(self):
        plan_ = kload.plan_image(make_elf())
        self.assertEqual(plan_.load_base, 0x180000000)
        self.assertEqual(plan_.entry, 0x180001000)
        self.assertEqual(plan_.kind, kload.KIND_ELF)

    def test_stage_moves_an_elf(self):
        plan_ = kload.plan_image(make_elf(), stage=0x1800A0000)
        self.assertEqual(plan_.load_base, 0x1800A0000)
        self.assertEqual(plan_.entry, 0x1800A1000)
        self.assertEqual([a for a, _ in plan_.segments], [0x1800A0000])

    def test_elf_refuses_a_conflicting_entry(self):
        with self.assertRaises(kload.KloadError) as caught:
            kload.plan_image(make_elf(), entry=0x180000000)
        self.assertIn("--entry", str(caught.exception))

    def test_rejects_addresses_outside_sram(self):
        for name, kwargs in (
                ("below sram", {"stage": 0x100000000, "entry": 0x100001000}),
                ("past sram", {"stage": 0x1801D0000}),
        ):
            with self.subTest(name):
                with self.assertRaises(kload.KloadError):
                    kload.plan_image(self.image, **kwargs)

    def test_rejects_the_container_staging_window(self):
        # The staging window belongs to the device-side loader.
        with self.assertRaises(kload.KloadError):
            kload.plan_image(self.image, stage=0x1800FF000)
        with self.assertRaises(kload.KloadError):
            kload.plan_image(make_elf(segments=[(0x1800E0000, 0x40000,
                                           b"A" * 0x40000)]))

    def test_rejects_an_entry_outside_the_image(self):
        with self.assertRaises(kload.KloadError):
            kload.plan_image(self.image, entry=0x180090000)

    def test_empty_image_is_refused(self):
        with self.assertRaises(kload.KloadError):
            kload.plan_image(b"")


class TestPlanContainer(unittest.TestCase):
    def setUp(self):
        self.ident = GoatIdentity()
        self.payload = bytes(range(256)) * 64     # 16 KiB, > default entry
        self.args = {"load_base": 0x180180000, "entry_off": 0x40}

    def seal(self, wrap=False, **overrides):
        kwargs = dict(self.args)
        kwargs.update(overrides)
        return container.seal(self.payload, GoatIdentity.key, self.ident.doc,
                              wrap=wrap, **kwargs)

    def test_container_is_unsealed_and_planned(self):
        plan_ = kload.plan_image(self.seal(), key=GoatIdentity.key)
        self.assertEqual(plan_.kind, kload.KIND_CONTAINER)
        self.assertEqual(plan_.load_base, 0x180180000)
        self.assertEqual(plan_.entry, 0x180180040)
        self.assertEqual(plan_.segments[0][1], self.payload)
        self.assertFalse(plan_.staged)

    def test_wrapped_container_unwraps_with_the_identity(self):
        sealed = self.seal(wrap=True)
        parsed = container.parse(sealed)
        self.assertTrue(parsed.has_keywrap)
        key = parsed.unwrap_key(self.ident.doc)
        self.assertEqual(key, GoatIdentity.key)
        plan_ = kload.plan_image(sealed, key=key)
        self.assertEqual(plan_.segments[0][1], self.payload)

    def test_staged_container_is_written_untouched(self):
        sealed = self.seal()
        plan_ = kload.plan_image(sealed, key=GoatIdentity.key, stage_container=True)
        self.assertTrue(plan_.staged)
        self.assertEqual(plan_.load_base, container.GOAT_STAGE_BASE)
        self.assertEqual(plan_.segments[0][1], sealed)
        self.assertEqual(plan_.note, "staged for the device-side loader")

    def test_staged_container_ignores_the_staging_window_rule(self):
        sealed = self.seal()
        plan_ = kload.plan_image(sealed, stage=0x180100000, stage_container=True)
        self.assertEqual(plan_.load_base, 0x180100000)

    def test_refuses_without_a_key(self):
        sealed = self.seal()
        with self.assertRaises(kload.KloadError) as caught:
            kload.plan_image(sealed)
        self.assertIn("--key-hex", str(caught.exception))

        wrapped = self.seal(wrap=True)
        with self.assertRaises(kload.KloadError) as caught:
            kload.plan_image(wrapped)
        self.assertIn("--key-from-cert", str(caught.exception))

    def test_refuses_a_container_whose_signature_is_broken(self):
        sealed = bytearray(self.seal())
        sealed[-64] ^= 0xFF
        with self.assertRaises(kload.KloadError) as caught:
            kload.plan_image(bytes(sealed), key=GoatIdentity.key)
        self.assertIn("signature", str(caught.exception))


class TestArtifact(unittest.TestCase):
    """The real payload, checked against the linker's own layout."""

    def test_built_elf_plans_where_the_linker_put_it(self):
        if not ARTIFACT_ELF.exists():
            self.skipTest("build/a11-payload.elf not built")
        plan_ = kload.plan_image(ARTIFACT_ELF.read_bytes())
        self.assertEqual(plan_.kind, kload.KIND_ELF)
        self.assertEqual(plan_.load_base, 0x180000000)
        self.assertEqual(plan_.entry, 0x180001000)
        self.assertLessEqual(plan_.end, container.GOAT_SRAM_END)
        # Where each segment lands is the linker's business, not a number to
        # pin: the first is the vector table plus .text, and the rest start on
        # the page boundaries linker/a11.ld aligns them to. (This used to
        # assert one hard-coded segment address, which stopped meaning
        # anything the moment the image grew.)
        segments = [addr for addr, _ in plan_.segments]
        self.assertEqual(segments[0], 0x180000000)
        self.assertGreater(len(segments), 1)
        for addr in segments:
            self.assertEqual(addr & 0xFFF, 0, "segment not page-aligned")

    def test_flat_bin_and_elf_agree_on_the_entry(self):
        binary = ROOT / "build" / "a11-payload.bin"
        if not (ARTIFACT_ELF.exists() and binary.exists()):
            self.skipTest("build artifacts not built")
        elf = kload.plan_image(ARTIFACT_ELF.read_bytes())
        raw = kload.plan_image(binary.read_bytes())
        self.assertNotEqual(raw.kind, kload.KIND_ELF)
        self.assertEqual(raw.entry, elf.entry)
        self.assertEqual(raw.load_base, elf.load_base)


class TestLoad(unittest.TestCase):
    def setUp(self):
        self.dev = FakeDevice()
        self.plan = kload.plan_image(b"\xcc" * 0x3000)

    def test_writes_every_chunk_in_order(self):
        written = kload.load(self.dev, self.plan, chunk=0x1000)
        self.assertEqual(written, 0x3000)
        self.assertEqual([a for a, _ in self.dev.writes],
                         [0x180000000 + o for o in range(0, 0x3000, 0x1000)])
        self.assertEqual(self.dev.read_memory(0x180000000, 0x3000),
                         self.plan.segments[0][1])

    def test_readback_mismatch_is_reported_not_silent(self):
        self.dev.fail_write_at = 0x180002000
        with self.assertRaises(RuntimeError) as caught:
            kload.load(self.dev, self.plan)
        message = str(caught.exception)
        self.assertIn("readback mismatch", message)
        self.assertIn("first bad byte at 0x180002800", message)

    def test_verification_can_be_turned_off(self):
        self.dev.fail_write_at = 0x180002000
        written = kload.load(self.dev, self.plan, verify=False)
        self.assertEqual(written, 0x3000)

    def test_boot_passes_registers_in_order(self):
        kload.boot(self.dev, self.plan.entry, (0, cli.GOAT_LAUNCH_TAG, 0))
        self.assertEqual(self.dev.entry, 0x180001000)
        # entry, then x0, x1, x2 -- see the register table in goat.h.
        self.assertEqual(self.dev.commands,
                         [(0x180001000, 0, cli.GOAT_LAUNCH_TAG, 0)])

    def test_wait_for_handoff_reports_either_way(self):
        usb = FakeUsb(present=[True, True, False])
        self.assertTrue(kload.wait_for_handoff(usb, timeout=2.0, poll=0.01))
        self.assertGreaterEqual(usb.probes, 3)

    def test_handoff_wait_gives_up(self):
        started = time.time()
        self.assertFalse(kload.wait_for_handoff(FakeUsb(present=True),
                                                timeout=0.05, poll=0.01))
        self.assertLess(time.time() - started, 1.0)


class TestSendCommand(unittest.TestCase):
    """The command path end to end, against a device that is a stub."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.work = Path(self.temp.name)
        self.dev = FakeDevice()
        self.waits = []
        self.image = self.work / "payload.bin"
        self.image.write_bytes(b"\xcc" * 0x3000)

    def tearDown(self):
        self.temp.cleanup()

    def sealed(self):
        path = self.work / "payload.g1"
        path.write_bytes(container.seal(b"\xcc" * 0x3000, GoatIdentity.key,
                                        GoatIdentity().doc, 0x180180000, 0x40))
        return path

    def run_cli(self, argv, image=None):
        """Run `goat kload ...` with the device and the handoff wait stubbed."""
        waited = []

        def fake_acquire(**kwargs):
            self.acquired = kwargs
            return self.dev

        def fake_wait(usb, timeout, poll=0.25):
            waited.append(timeout)
            return True

        original = (cli._acquire_pwndfu, kload.wait_for_handoff)
        cli._acquire_pwndfu = fake_acquire
        kload.wait_for_handoff = fake_wait
        try:
            code = cli.main(["kload", str(image or self.image)] + argv)
        finally:
            cli._acquire_pwndfu, kload.wait_for_handoff = original
        self.waited = waited
        return code

    def test_boots_the_image_and_waits_for_the_handoff(self):
        self.assertEqual(self.run_cli([]), 0)
        self.assertTrue(self.acquired["auto_pwn"])
        self.assertEqual([a for a, _ in self.dev.writes],
                         [0x180000000 + o for o in range(0, 0x3000, 0x1000)])
        # entry, then x0, x1, x2: no device tree from pwndfu, the launch tag,
        # nothing staged for the payload.
        self.assertEqual(self.dev.commands,
                         [(0x180001000, 0, cli.GOAT_LAUNCH_TAG, 0)])
        self.assertEqual(self.waited, [kload.DEFAULT_WAIT])

    def test_no_run_stages_and_stops(self):
        self.assertEqual(self.run_cli(["--no-run"]), 0)
        self.assertEqual(self.dev.commands, [])
        self.assertEqual(self.waited, [])

    def test_pwn_and_wait_toggles(self):
        self.assertEqual(self.run_cli(["--no-pwn", "--wait", "0"]), 0)
        self.assertFalse(self.acquired["auto_pwn"])
        self.assertEqual(self.waited, [])

    def test_container_that_does_not_wrap_a_key_says_so(self):
        # --key-from-cert on a container that has no keywrap is a mistake worth
        # naming, not a modulus-length error.
        sealed = self.sealed()
        try:
            with self.assertRaises(SystemExit):
                self.run_cli(["--cert", "goat-key.json", "--key-from-cert"],
                             image=sealed)
            self.assertEqual(self.dev.writes, [])
        finally:
            sealed.unlink(missing_ok=True)

    def test_a_staged_container_is_never_executed(self):
        sealed = self.sealed()
        try:
            with self.assertRaises(SystemExit):
                self.run_cli(["--stage-container", "--run"], image=sealed)
            self.assertEqual(self.dev.writes, [])
            # Without --run the same container stages into the staged window.
            self.assertEqual(self.run_cli(["--stage-container"], image=sealed),
                             0)
            self.assertEqual(self.dev.commands, [])
            self.assertEqual(self.dev.writes[0][0], container.GOAT_STAGE_BASE)
            self.assertEqual(sum(n for _, n in self.dev.writes),
                             sealed.stat().st_size)
        finally:
            sealed.unlink(missing_ok=True)


class TestAcquire(unittest.TestCase):
    """The pwndfu gate: what happens when the device is not there yet."""

    class StubDevice:
        def __init__(self, serial):
            self.serial = serial
            self.closed = False

        def close(self):
            self.closed = True

    class StubList:
        def __init__(self, present=True, serial="PWND:[checkm8]"):
            self.present = present
            self.serial = serial

        def dfu_present(self):
            return self.present

    def acquire(self, present=True, serial="PWND:[checkm8]", auto_pwn=False,
                checkm8_result=0, pwndfu_after=False, failure=False):
        """_acquire_pwndfu with the USB layer replaced by stubs."""
        import goat.pwn as pwn_module
        import goat.usb as usb_module

        made = {"devices": 0}

        def make_list():
            return self.StubList(present=present, serial=serial)

        def make_device(usb, timeout=5.0):
            made["devices"] += 1
            if failure:
                raise usb_module.UsbError("could not claim DFU interface 0")
            # The exploit leaves a pwndfu serial behind, the same way checkm8
            # does on a real device.
            found = usb.serial
            if pwndfu_after and made["devices"] > 1:
                found = usb.serial + " PWND:[checkm8]"
            return TestAcquire.StubDevice(found)

        calls = []

        def fake_checkm8(directory="ipwndfu"):
            calls.append(directory)
            return checkm8_result

        original = (usb_module.LibusbDeviceList, usb_module.PwnedDFU,
                    pwn_module.checkm8)
        usb_module.LibusbDeviceList = make_list
        usb_module.PwnedDFU = make_device
        pwn_module.checkm8 = fake_checkm8
        try:
            try:
                dev = cli._acquire_pwndfu(auto_pwn=auto_pwn)
                result = (True, dev.serial)
            except usb_module.UsbError as exc:
                result = (False, str(exc))
        finally:
            (usb_module.LibusbDeviceList, usb_module.PwnedDFU,
             pwn_module.checkm8) = original
        return result, made, calls

    def test_pwndfu_device_is_used_as_is(self):
        (ok, serial), made, calls = self.acquire()
        self.assertTrue(ok)
        self.assertEqual(serial, "PWND:[checkm8]")
        self.assertEqual(made["devices"], 1)
        self.assertEqual(calls, [])

    def test_dfu_only_device_is_exploited_when_allowed(self):
        serial = "CPID:8015 CPRV:11 SRTG:[iBoot-3332.0.0.1.23]"
        args = {"serial": serial, "auto_pwn": True, "pwndfu_after": True}
        (ok, result), made, calls = self.acquire(**args)
        self.assertTrue(ok, result)
        self.assertEqual(result.endswith("PWND:[checkm8]"), True)
        self.assertEqual(calls, ["ipwndfu"])           # checkm8 ran once
        self.assertEqual(made["devices"], 2)           # reopened afterwards

    def test_dfu_only_device_is_refused_without_pwn(self):
        serial = "CPID:8015 CPRV:11 SRTG:[iBoot-3332.0.0.1.23]"
        (ok, message), made, calls = self.acquire(serial=serial)
        self.assertFalse(ok)
        self.assertIn("not pwndfu", message)
        self.assertIn("goat pwn", message)
        self.assertEqual(calls, [])

    def test_exploit_failure_is_reported(self):
        serial = "CPID:8015 CPRV:11 SRTG:[iBoot-3332.0.0.1.23]"
        args = {"serial": serial, "auto_pwn": True, "checkm8_result": 1}
        (ok, message), _, calls = self.acquire(**args)
        self.assertFalse(ok)
        self.assertIn("checkm8", message)
        self.assertEqual(calls, ["ipwndfu"])

    def test_no_device_in_dfu_is_reported_plainly(self):
        (ok, message), made, calls = self.acquire(present=False)
        self.assertFalse(ok)
        self.assertIn("DFU mode", message)
        self.assertEqual(made["devices"], 0)

    def test_a_device_that_will_not_open_is_not_exploited(self):
        # A failed open says nothing about the device's state, so the error is
        # reported rather than worked around by running the exploit.
        args = {"failure": True, "auto_pwn": True, "serial": "CPID:8015"}
        (ok, message), _, calls = self.acquire(**args)
        self.assertFalse(ok)
        self.assertIn("claim", message)
        self.assertEqual(calls, [])


class TestCommandLine(unittest.TestCase):
    def setUp(self):
        self.parser = cli.build_parser()

    def test_kload_and_send_are_the_same_command(self):
        for name in ("send", "kload"):
            args = self.parser.parse_args([name, "image.bin"])
            self.assertIs(args.func, cli.cmd_send)
            self.assertIsNone(args.run, "run defaults to whatever the image "
                                        "implies")
            self.assertTrue(args.pwn)
            self.assertTrue(args.verify)
            self.assertEqual(args.wait, kload.DEFAULT_WAIT)
            self.assertEqual(args.chunk, kload.DEFAULT_CHUNK)

    def test_toggles_flip(self):
        args = self.parser.parse_args(["kload", "image.bin", "--no-run",
                                       "--no-pwn", "--no-verify", "--wait", "0",
                                       "--chunk", "0x800", "--stage",
                                       "0x180020000", "--entry", "0x180020100"])
        self.assertFalse(args.run)
        self.assertFalse(args.pwn)
        self.assertFalse(args.verify)
        self.assertEqual(args.wait, 0)
        self.assertEqual(args.chunk, 0x800)
        self.assertEqual(args.stage, 0x180020000)
        self.assertEqual(args.entry, 0x180020100)

    def test_explicit_run_and_stage_container_conflict(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "container.g1"
            path.write_bytes(container.seal(b"\xcc" * 0x3000, GoatIdentity.key,
                                           GoatIdentity().doc, 0x180180000,
                                           0x40))
            args = self.parser.parse_args(["kload", str(path), "--run",
                                          "--stage-container"])
            with self.assertRaises(SystemExit):
                cli.cmd_send(args)


if __name__ == "__main__":
    unittest.main(verbosity=2)
