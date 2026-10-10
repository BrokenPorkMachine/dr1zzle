"""kload: put an image into a pwndfu device and jump into it.

checkra1n shipped `kload` to push a pongoOS image onto a device that had
already been exploited; this is the same job for a dr1zzle image, done through
goat's own transport instead of ipwndfu's. The flow is:

    plan      decide what goes where, and where to jump, with no device
              attached. A bad image fails here, not half-written into SRAM.
    acquire   DFU must be present. A device that is in DFU but not yet
              exploited gets checkm8 run on it first (unless --no-pwn).
    load      write the plan over the pwndfu command channel in chunks and
              read every chunk back and compare it.
    boot      hand the CPU to the entry point with the register convention.
    watch     poll until the DFU interface disappears, which means the
              image's own USB core came up.

Three image forms are accepted, identified from the file's own bytes:

    elf        program headers are honoured: each PT_LOAD is written at its
               own address and the entry comes from the header. This is what
               build/a11-payload.elf is, and it is the preferred form.
    container  a sealed .g1: signature-checked, decrypted here (so the key
               never travels to the device), and placed at the load base
               recorded when it was sealed. With stage_container the sealed
               bytes are written untouched into the staging window for the
               device-side loader, and nothing is jumped to.
    raw        a flat binary, placed at the linker's base with the entry the
               linker gives _start, both overridable.

The exploit itself is not here: this module contains no exploit logic. It
calls the same checkm8 entry point `goat pwn` uses, which shells out to the
vendored ipwndfu (Python 2).
"""

import struct
import time

from . import container
from .der import DerError
from .usb import DFU_IMAGE_BASE

# Image forms, as reported by sniff().
KIND_ELF = "elf"
KIND_CONTAINER = "container"
KIND_RAW = "raw"

# ELF64, little-endian, AArch64, executable.
ELFCLASS64 = 2
ELFDATA2LSB = 1
ET_EXEC = 2
EM_AARCH64 = 183
PT_LOAD = 1
EHDR_SIZE = 64
PHDR_SIZE = 56

# linker/a11.ld: SRAM lives at 0x180000000, the vector table takes the first
# 0x800 bytes, and .text is page-aligned after it -- which is where _start
# lands. That pair is the default placement of a flat binary.
SRAM_BASE = 0x180000000
DEFAULT_ENTRY_OFFSET = 0x1000

# Bytes per pwndfu write command, and how long to watch for the handoff.
DEFAULT_CHUNK = 0x1000
DEFAULT_WAIT = 15.0
HANDOFF_POLL = 0.25

# The pwndfu command channel keeps its request/response scratch at
# load_base() and lifts the bytes a memcpy should copy from right behind it.
# An image that spans that window would be uploading over the channel that is
# doing the uploading.
CMD_AREA_SIZE = 0x1000

# A pwndfu device re-enumerates with this in its serial number.
PWND_SERIAL = "PWND:[checkm8]"

# x1 handed to a payload launched by goat: 'goat' big endian, so the payload
# can tell who started it. Must match GOAT_LAUNCH_TAG in include/goat/goat.h.
GOAT_LAUNCH_TAG = 0x676F6174
# x0, x1, x2 for a jump from pwndfu state: no device tree to hand over from
# the SecureROM, the launch tag, and nothing staged for the payload.
BOOT_ARGS = (0, GOAT_LAUNCH_TAG, 0)


class KloadError(ValueError):
    """The image, or the placement asked for, cannot be used."""


class LoadError(KloadError, RuntimeError):
    """A write did not read back the way it was written."""


class Plan:
    """What to write, where, and where to jump. Built without a device."""

    def __init__(self, kind, load_base, entry, segments, staged=False,
                 note=None):
        self.kind = kind
        self.load_base = load_base
        self.entry = entry
        self.segments = segments
        self.staged = staged
        self.note = note

    @property
    def size(self):
        return sum(len(data) for _, data in self.segments)

    @property
    def end(self):
        return max(addr + len(data) for addr, data in self.segments)

    def summary(self):
        if self.staged:
            return ("%s image staged at 0x%x (%d bytes, %s)"
                    % (self.kind, self.load_base, self.size, self.note))
        return ("%s image: %d bytes at 0x%x-0x%x, entry 0x%x"
                % (self.kind, self.size, self.load_base, self.end,
                   self.entry))


# ---------------------------------------------------------------------------
# identifying an image
# ---------------------------------------------------------------------------

def sniff(blob):
    """Identify an image from its own bytes.

    A container is a DER SEQUENCE whose first member is the GOAT magic, so
    "starts with 0x30" is only a hint and the parse has to confirm it. Anything
    that fails that is treated as an opaque image rather than half-identified:
    a stray SEQUENCE in a binary must not turn a raw upload into a container
    upload.
    """
    if blob[:len(container.GOAT_MAGIC)] == container.GOAT_MAGIC:
        return KIND_CONTAINER
    if blob[:4] == b"\x7fELF":
        return KIND_ELF
    if blob[:1] == b"\x30":
        try:
            container.parse(blob)
        except (DerError, ValueError):
            return KIND_RAW
        return KIND_CONTAINER
    return KIND_RAW


def parse_elf(blob):
    """Return (entry, [(address, bytes), ...]) for an AArch64 ET_EXEC ELF.

    Each PT_LOAD contributes only its file bytes: p_memsz above p_filesz is
    .bss, which the image itself zeroes on entry, so there is nothing to send.
    p_paddr wins over p_vaddr when it is set, because that is where a
    bare-metal image actually wants to be placed.
    """
    if len(blob) < EHDR_SIZE:
        raise KloadError("truncated ELF header")
    if blob[:4] != b"\x7fELF":
        raise KloadError("not an ELF file")
    if blob[4] != ELFCLASS64:
        raise KloadError("not a 64-bit ELF (EI_CLASS %d)" % blob[4])
    if blob[5] != ELFDATA2LSB:
        raise KloadError("not a little-endian ELF")

    (e_type, e_machine, _version, e_entry, e_phoff, _e_shoff, _e_flags,
     _e_ehsize, e_phentsize, e_phnum) = struct.unpack_from("<HHIQQQIHHH",
                                                           blob, 16)
    if e_machine != EM_AARCH64:
        raise KloadError("ELF is not AArch64 (e_machine %d)" % e_machine)
    if e_type != ET_EXEC:
        raise KloadError("ELF is not ET_EXEC (e_type %d); a relocatable image "
                         "has no fixed address to be loaded at" % e_type)
    if e_entry == 0:
        raise KloadError("ELF has no entry point")
    if e_phnum == 0:
        raise KloadError("ELF has no program headers")
    if e_phentsize < PHDR_SIZE:
        raise KloadError("ELF program header is %d bytes, want %d"
                         % (e_phentsize, PHDR_SIZE))

    segments = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        if off + PHDR_SIZE > len(blob):
            raise KloadError("program header %d is outside the file" % i)
        (p_type, _p_flags, p_offset, p_vaddr, p_paddr, p_filesz,
         _p_memsz) = struct.unpack_from("<IIQQQQQ", blob, off)
        if p_type != PT_LOAD or p_filesz == 0:
            continue
        if p_offset + p_filesz > len(blob):
            raise KloadError("segment %d runs past the end of the file" % i)
        segments.append((p_paddr or p_vaddr,
                         bytes(blob[p_offset:p_offset + p_filesz])))

    if not segments:
        raise KloadError("ELF has no PT_LOAD segments")
    segments.sort(key=lambda seg: seg[0])
    return e_entry, segments


# ---------------------------------------------------------------------------
# placing an image
# ---------------------------------------------------------------------------

def _check_sram(base, size, what):
    """The hard bound: everything goat writes has to land in SRAM."""
    if size <= 0:
        raise KloadError("%s is empty" % what)
    if base < SRAM_BASE or base + size > container.GOAT_SRAM_END:
        raise KloadError(
            "%s [0x%x, 0x%x) is outside the SRAM window [0x%x, 0x%x)"
            % (what, base, base + size, SRAM_BASE, container.GOAT_SRAM_END))


def _check_scratch(base, size, what):
    """Reject a placement that cannot work before anything is written.

    On top of the SRAM bound, a raw or ELF image has to stay clear of two
    windows: the container staging window, which belongs to the device-side
    loader, and the pwndfu command area, which is the channel doing the write.
    """
    _check_sram(base, size, what)
    if base + size > container.GOAT_STAGE_BASE:
        raise KloadError(
            "%s [0x%x, 0x%x) runs into the container staging window at 0x%x; "
            "place the image below it, or hand a sealed container over with "
            "--stage-container"
            % (what, base, base + size, container.GOAT_STAGE_BASE))
    if base < DFU_IMAGE_BASE + CMD_AREA_SIZE and base + size > DFU_IMAGE_BASE:
        raise KloadError(
            "%s [0x%x, 0x%x) spans the pwndfu command area at 0x%x; the "
            "upload would overwrite the channel it is using"
            % (what, base, base + size, DFU_IMAGE_BASE))


def _plan_raw(blob, stage, entry):
    base = SRAM_BASE if stage is None else stage
    want = base + DEFAULT_ENTRY_OFFSET if entry is None else entry
    _check_scratch(base, len(blob), "the image")
    if not base <= want < base + len(blob):
        raise KloadError("entry 0x%x is outside the image [0x%x, 0x%x)"
                         % (want, base, base + len(blob)))
    return Plan(KIND_RAW, base, want, [(base, bytes(blob))])


def _plan_elf(blob, stage, entry):
    elf_entry, segments = parse_elf(blob)
    base = segments[0][0]
    delta = 0 if stage is None else stage - base
    want = elf_entry + delta
    if entry is not None and entry != want:
        raise KloadError(
            "--entry 0x%x disagrees with the ELF entry 0x%x; drop --entry to "
            "use the header's own entry point" % (entry, want))
    placed = [(addr + delta, data) for addr, data in segments]
    for addr, data in placed:
        _check_scratch(addr, len(data), "the ELF segment at 0x%x" % addr)
    return Plan(KIND_ELF, base + delta, want, placed)


def _plan_container(blob, stage, entry, key, stage_container):
    parsed = container.parse(blob)

    if stage_container:
        if entry is not None:
            raise KloadError(
                "--entry cannot be used with --stage-container: nothing is "
                "jumped to, the device-side loader runs the image it is "
                "handed")
        base = container.GOAT_STAGE_BASE if stage is None else stage
        sealed = bytes(blob)
        _check_sram(base, len(sealed), "the staged container")
        if not parsed.verify():
            raise KloadError(
                "the container signature is invalid; refusing to stage it for "
                "the device-side loader")
        return Plan(KIND_CONTAINER, base, None, [(base, sealed)], staged=True,
                    note="staged for the device-side loader")

    if not parsed.verify():
        raise KloadError("the container signature is invalid; refusing to run "
                         "what it holds")
    if parsed.has_keywrap:
        if key is None:
            raise KloadError(
                "the container carries its AES key wrapped to a certificate; "
                "pass --key-from-cert with the identity that holds the "
                "private key, or the key itself with --key-hex")
    elif key is None:
        raise KloadError("the container does not carry its key; pass "
                         "--key-hex or --key-file")

    try:
        payload = parsed.decrypt(key)
    except ValueError as exc:
        raise KloadError("the container did not decrypt: %s" % exc)

    if stage is not None:
        raise KloadError(
            "--stage cannot be used with a sealed container: its load base "
            "was fixed when it was sealed (--stage-container hands it to the "
            "device-side loader instead)")

    base = parsed.load_base
    want = base + parsed.entry_off
    if entry is not None and entry != want:
        raise KloadError(
            "--entry 0x%x disagrees with the container's entry 0x%x (load "
            "base 0x%x + entry offset 0x%x); drop --entry to use the sealed "
            "value" % (entry, want, base, parsed.entry_off))
    _check_sram(base, len(payload), "the container's payload")
    return Plan(KIND_CONTAINER, base, want, [(base, payload)])


def plan_image(blob, stage=None, entry=None, key=None,
               stage_container=False):
    """Turn image bytes into a Plan. No device is touched."""
    if not blob:
        raise KloadError("the image is empty")

    kind = sniff(blob)
    if kind == KIND_CONTAINER:
        return _plan_container(blob, stage, entry, key, stage_container)
    if kind == KIND_ELF:
        return _plan_elf(blob, stage, entry)
    return _plan_raw(blob, stage, entry)


# ---------------------------------------------------------------------------
# the device side
# ---------------------------------------------------------------------------

def _first_difference(a, b):
    for i in range(min(len(a), len(b))):
        if a[i] != b[i]:
            return i
    return min(len(a), len(b))


def load(dev, plan, chunk=DEFAULT_CHUNK, verify=True):
    """Write the plan to the device, reading every chunk back.

    Returns the number of bytes written. The readback is not decoration: a
    chunk that lands wrong means the image the device would jump into is not
    the image that was planned, and LoadError names the first byte that
    disagrees.
    """
    if chunk <= 0:
        raise KloadError("--chunk must be at least one byte")

    written = 0
    for base, data in plan.segments:
        for off in range(0, len(data), chunk):
            part = data[off:off + chunk]
            dev.write_memory(base + off, part, chunk=chunk)
            written += len(part)
            if not verify:
                continue
            back = dev.read_memory(base + off, len(part))
            if back != part:
                bad = _first_difference(back, part)
                wrote = part[bad] if bad < len(part) else None
                read = back[bad] if bad < len(back) else None
                raise LoadError(
                    "readback mismatch: first bad byte at 0x%x (wrote %s, "
                    "read %s, %d of %d bytes came back)"
                    % (base + off + bad,
                       "0x%02x" % wrote if wrote is not None else "nothing",
                       "0x%02x" % read if read is not None else "nothing",
                       len(back), len(part)))
    return written


def boot(dev, entry, args=BOOT_ARGS):
    """Hand the CPU to the image: entry in the PC, the rest in x0, x1, ..."""
    dev.execute(entry, *args)


def wait_for_handoff(usb, timeout, poll=HANDOFF_POLL):
    """Wait for the DFU interface to disappear once the image is running.

    Returns True when it did and False when `timeout` ran out first. A payload
    that takes control brings up its own USB core, so 05ac:1227 going away is
    the only evidence the host gets that the jump landed. A payload that
    faults before its USB init leaves the interface in place, which is what a
    timeout reports.
    """
    if timeout is None or timeout <= 0:
        return False
    poll = max(float(poll), 0.001)
    deadline = time.time() + float(timeout)
    while True:
        if not usb.dfu_present():
            return True
        left = deadline - time.time()
        if left <= 0:
            return False
        time.sleep(min(poll, left))


def acquire_pwndfu(auto_pwn=True, ipwndfu_dir="ipwndfu", timeout=5.0):
    """Open a pwndfu device, exploiting it first when that is allowed.

    A device that is in DFU but not yet pwndfu gets checkm8 run on it when
    auto_pwn is set, because "put this image on my device" is one action, not
    two. With auto_pwn off, that device is an error and the message says to
    run `goat pwn`. A device that will not open at all says nothing about its
    state, so it is reported rather than worked around by exploiting it.
    """
    from .pwn import checkm8
    from .usb import LibusbDeviceList, PwnedDFU, UsbError

    usb = LibusbDeviceList()
    if not usb.dfu_present():
        raise UsbError("no Apple device in DFU mode (05ac:1227); put the "
                       "device into DFU and try again")

    dev = PwnedDFU(usb, timeout=timeout)
    if PWND_SERIAL in dev.serial:
        return dev

    if not auto_pwn:
        serial = dev.serial
        dev.close()
        raise UsbError("the device is in DFU but not pwndfu (%s); run "
                       "'goat pwn' first, or pass --pwn"
                       % (serial or "no serial"))

    dev.close()
    if checkm8(ipwndfu_dir) != 0:
        raise UsbError("checkm8 did not succeed; the device was not left in "
                       "pwndfu state")

    dev = PwnedDFU(LibusbDeviceList(), timeout=timeout)
    if PWND_SERIAL not in dev.serial:
        serial = dev.serial
        dev.close()
        raise UsbError("checkm8 reported success but the device is still not "
                       "pwndfu (%s)" % (serial or "no serial"))
    return dev
