"""libusb transport and the pwndfu (checkm8) command channel.

This is the loader half: it puts bytes into device memory and tells the device
to run them, with no dependency on the vendored ipwndfu (which is Python 2 and
cannot be imported from here). The wire format is dfu.py's control-transfer
sequence plus usbexec.py's command/response framing, both of which are the
DFU command channel the checkm8 patch installs:

    send_data(b"\\0" * 16)         # clear the command/response area
    DNLOAD, GETSTATUS, GETSTATUS   # prime the hacked state machine
    send_data(request)             # lift the request into memory
    GET_STATE-ish read (0xA1/2)    # fetch the response

A "device in pwndfu" means the SecureROM has already been exploited (checkm8)
and re-enumerated with the patched serial number. goat does not perform the
exploit itself -- see the `pwn` command, which drives the vendored ipwndfu for
that one step only.
"""

import ctypes
import ctypes.util
import struct
import time

APPLE_VID = 0x05AC
DFU_PID = 0x1227

MAX_PACKET = 0x800
USB_READ_LIMIT = 0x8000
CMD_TIMEOUT_MS = 5000

EXEC_MAGIC = b"execexec"
DONE_MAGIC = b"donedone"
MEMC_MAGIC = b"memcmemc"
MEMS_MAGIC = b"memsmems"

# t8015 (A11, the platform this payload targets).
DFU_IMAGE_BASE = 0x18001C000
DFU_LOAD_BASE = 0x800000000


class UsbError(RuntimeError):
    pass


def _load_libusb():
    candidates = [
        "libusb-1.0.dylib", "libusb-1.0.so", "libusb-1.0.so.0",
        "/usr/lib/libusb-1.0.dylib",
        "/opt/homebrew/lib/libusb-1.0.dylib",
        "/usr/local/lib/libusb-1.0.dylib",
        ctypes.util.find_library("usb-1.0"),
    ]
    for name in candidates:
        if not name:
            continue
        try:
            return ctypes.CDLL(name)
        except OSError:
            continue
    raise UsbError(
        "libusb-1.0 was not found. On macOS: 'brew install libusb'; "
        "on Debian/Ubuntu: 'apt install libusb-1.0-0'.")


class LibusbDeviceList:
    """ctypes declarations for exactly the calls needed."""

    def __init__(self):
        lib = _load_libusb()
        self.lib = lib

        lib.libusb_init.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
        lib.libusb_exit.argtypes = [ctypes.c_void_p]
        lib.libusb_get_device_list.argtypes = [ctypes.c_void_p,
                                                ctypes.POINTER(ctypes.POINTER(
                                                    ctypes.c_void_p))]
        lib.libusb_free_device_list.argtypes = [ctypes.POINTER(ctypes.c_void_p),
                                                ctypes.c_int]
        lib.libusb_open.argtypes = [ctypes.c_void_p,
                                    ctypes.POINTER(ctypes.c_void_p)]
        lib.libusb_close.argtypes = [ctypes.c_void_p]
        lib.libusb_claim_interface.argtypes = [ctypes.c_void_p, ctypes.c_int]
        lib.libusb_release_interface.argtypes = [ctypes.c_void_p, ctypes.c_int]
        lib.libusb_control_transfer.argtypes = [
            ctypes.c_void_p, ctypes.c_uint8, ctypes.c_uint8,
            ctypes.c_uint16, ctypes.c_uint16, ctypes.c_void_p,
            ctypes.c_uint16, ctypes.c_uint]
        lib.libusb_control_transfer.restype = ctypes.c_int
        lib.libusb_get_string_descriptor_ascii.argtypes = [
            ctypes.c_void_p, ctypes.c_uint8, ctypes.c_void_p, ctypes.c_int]
        lib.libusb_error_name.argtypes = [ctypes.c_int]
        lib.libusb_error_name.restype = ctypes.c_char_p

        ctx = ctypes.c_void_p()
        if lib.libusb_init(ctypes.byref(ctx)) != 0:
            raise UsbError("libusb_init failed")
        self.ctx = ctx

    def error(self, code):
        name = self.lib.libusb_error_name(code)
        return name.decode() if name else "libusb error %d" % code

    def find_dfu(self, timeout=5.0):
        deadline = time.time() + timeout
        while True:
            found = self._scan_dfu()
            if found is not None:
                return found
            if time.time() >= deadline:
                raise UsbError(
                    "no Apple device in DFU (05ac:1227) after %.1fs" % timeout)
            time.sleep(0.02)

    def dfu_present(self):
        """Is a device attached in DFU mode right now?

        Reads the descriptor list without opening anything: a handoff watch
        polls this once a second, and opening a device that is about to
        disappear is both slower and more likely to fail than asking libusb
        what is on the bus.
        """
        try:
            return self._attached_dfu()
        except UsbError:
            return False

    def _attached_dfu(self):
        devlist = ctypes.POINTER(ctypes.c_void_p)()
        count = self.lib.libusb_get_device_list(self.ctx, ctypes.byref(devlist))
        if count < 0:
            raise UsbError(self.error(count))
        found = False
        try:
            for i in range(count):
                dev = devlist[i]
                if self._vendor(dev) == APPLE_VID and \
                        self._product(dev) == DFU_PID:
                    found = True
                    break
        finally:
            self.lib.libusb_free_device_list(devlist, 1)
        return found

    def _scan_dfu(self):
        devlist = ctypes.POINTER(ctypes.c_void_p)()
        count = self.lib.libusb_get_device_list(self.ctx, ctypes.byref(devlist))
        if count < 0:
            raise UsbError(self.error(count))
        handle = None
        index = self._find_dfu_index(count, devlist)
        if index is not None:
            h = ctypes.c_void_p()
            if self.lib.libusb_open(devlist[index], ctypes.byref(h)) == 0:
                handle = h.value
        self.lib.libusb_free_device_list(devlist, 1)
        return handle

    def _find_dfu_index(self, count, devlist):
        """Index of the first Apple DFU device in a live device list, or None.

        Both the open path and the presence probe go through here so they
        cannot disagree about what counts as the device.
        """
        for i in range(count):
            if (self._vendor(devlist[i]) == APPLE_VID
                    and self._product(devlist[i]) == DFU_PID):
                return i
        return None

    def dfu_present(self):
        """True when an Apple DFU device is enumerated, without opening it.

        This is the handoff signal for kload: a payload that boots brings up
        its own USB core, so 05ac:1227 going away means the image took over.
        Opening a handle per poll would leak one per iteration, so this only
        walks the descriptors libusb has already cached.
        """
        devlist = ctypes.POINTER(ctypes.c_void_p)()
        count = self.lib.libusb_get_device_list(self.ctx, ctypes.byref(devlist))
        if count < 0:
            raise UsbError(self.error(count))
        found = self._find_dfu_index(count, devlist) is not None
        self.lib.libusb_free_device_list(devlist, 1)
        return found

    def _descriptor_field(self, dev, offset, size):
        # The device descriptor is fetched by libusb internally; instead of
        # reimplementing that, use the idVendor/idProduct via the standard
        # descriptor call through the device handle below. Here we resolve
        # them via the descriptor cache libusb keeps on the device.
        fd = self.lib.libusb_get_device_descriptor
        fd.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        fd.restype = ctypes.c_int
        desc = (ctypes.c_uint8 * 18)()
        if fd(dev, ctypes.byref(desc)) != 0:
            return None
        value = int.from_bytes(bytes(desc[offset:offset + size]), "little")
        return value

    def _vendor(self, dev):
        return self._descriptor_field(dev, 8, 2)

    def _product(self, dev):
        return self._descriptor_field(dev, 10, 2)


class PwnedDFU:
    """A device in pwndfu state, driven through the DFU command channel."""

    def __init__(self, usb=None, timeout=5.0):
        self.usb = usb or LibusbDeviceList()
        self.handle = self.usb.find_dfu(timeout)
        if self.handle is None:
            raise UsbError("no DFU handle")
        if self.usb.lib.libusb_claim_interface(ctypes.c_void_p(self.handle), 0) != 0:
            raise UsbError("could not claim DFU interface 0")
        self.serial = self._serial()

    # -- low level ---------------------------------------------------------

    def _ctrl(self, bmRequestType, bRequest, wValue, wIndex, data, wLength,
              timeout):
        buf = None
        ptr = None
        if data is None:
            buf = ctypes.create_string_buffer(wLength if wLength else 1)
            ptr = ctypes.cast(buf, ctypes.c_void_p)
        else:
            ptr = ctypes.cast(ctypes.c_char_p(bytes(data)), ctypes.c_void_p)
        rc = self.usb.lib.libusb_control_transfer(
            ctypes.c_void_p(self.handle), bmRequestType, bRequest,
            wValue, wIndex, ptr, wLength, timeout)
        if rc < 0:
            raise UsbError("control transfer 0x%02x/0x%02x failed: %s"
                           % (bmRequestType, bRequest, self.usb.error(rc)))
        if data is None:
            return buf.raw[:wLength]
        return None

    def _serial(self):
        buf = ctypes.create_string_buffer(256)
        try:
            rc = self.usb.lib.libusb_get_string_descriptor_ascii(
                ctypes.c_void_p(self.handle), 3,
                ctypes.cast(buf, ctypes.c_void_p), 256)
        except Exception:
            return ""
        if rc < 0:
            return ""
        return buf.raw[:rc].decode("latin-1", "replace")

    # -- dfu transfer helpers ----------------------------------------------

    def send_data(self, data):
        index = 0
        while index < len(data):
            part = data[index:index + MAX_PACKET]
            self._ctrl(0x21, 1, 0, 0, part, len(part), 5000)
            index += len(part)

    def get_data(self, amount):
        out = b""
        while amount > 0:
            part = min(amount, MAX_PACKET)
            out += self._ctrl(0xA1, 2, 0, 0, None, part, 5000)
            amount -= part
        return out

    # -- command channel ---------------------------------------------------

    def load_base(self):
        return DFU_IMAGE_BASE if "SRTG:" in self.serial else DFU_LOAD_BASE

    def cmd_data_offset(self, index):
        return 16 + index * 8

    def cmd_data_address(self, index):
        return self.load_base() + self.cmd_data_offset(index)

    def command(self, request, response_length):
        if response_length > USB_READ_LIMIT:
            raise ValueError("response too large for one command")
        self.send_data(b"\0" * 16)
        self._ctrl(0x21, 1, 0, 0, b"", 0, 100)
        self._ctrl(0xA1, 3, 0, 0, None, 6, 100)
        self._ctrl(0xA1, 3, 0, 0, None, 6, 100)
        self.send_data(request)
        if response_length == 0:
            return self._ctrl(0xA1, 2, 0xFFFF, 0, None, response_length + 1,
                              CMD_TIMEOUT_MS)[1:]
        return self._ctrl(0xA1, 2, 0xFFFF, 0, None, response_length,
                          CMD_TIMEOUT_MS)

    def cmd_memcpy(self, dest, src, length):
        return struct.pack("<8s8x3Q", MEMC_MAGIC, dest, src, length)

    def cmd_memset(self, address, value, length):
        return struct.pack("<8s8x3Q", MEMS_MAGIC, address, value, length)

    def write_memory(self, address, data, chunk=0x1000):
        data = bytes(data)
        for off in range(0, len(data), chunk):
            part = data[off:off + chunk]
            self.command(self.cmd_memcpy(address + off,
                                         self.cmd_data_address(3),
                                         len(part)) + part, 0)

    def memset(self, address, value, length, chunk=0x1000):
        for off in range(0, length, chunk):
            part = min(chunk, length - off)
            self.command(self.cmd_memset(address + off, value, part), 0)

    def read_memory(self, address, length):
        data = b""
        while len(data) < length:
            part = min(length - len(data),
                       USB_READ_LIMIT - self.cmd_data_offset(0))
            response = self.command(self.cmd_memcpy(self.cmd_data_address(0),
                                                    address + len(data), part),
                                    self.cmd_data_offset(0) + part)
            if response[:8] != DONE_MAGIC:
                raise UsbError("device did not complete the read command")
            data += response[self.cmd_data_offset(0):]
        return data

    def execute(self, entry, *args):
        """Jump the device to `entry` with the remaining values in x0, x1, ..."""
        cmd = EXEC_MAGIC + b"".join(struct.pack("<Q", a)
                                    for a in (entry,) + tuple(args))
        self.command(cmd, 0)

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

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
