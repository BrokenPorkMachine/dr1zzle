//! Thin wrapper over libusb-1.0 mirroring exactly the pyusb calls that rpwn uses.
//!
//! The Python original drives the device through pyusb's libusb1 backend. The exploit
//! paths in `checkm8` / `limera1n` reach below pyusb into raw libusb (async control
//! transfers with `LIBUSB_TRANSFER_FREE_BUFFER`), so this module talks to libusb
//! directly rather than going through a higher level wrapper.

use std::ffi::{c_int, c_uchar, c_uint, c_void, CStr};
use std::ptr;
use std::sync::OnceLock;
use std::time::Instant;

use libusb1_sys::constants::{LIBUSB_ERROR_NOT_FOUND, LIBUSB_TRANSFER_FREE_BUFFER};
use libusb1_sys::*;

// `libusb_clear_halted` was renamed to `libusb_clear_halt`, and the deprecated
// `libusb_read`/`libusb_write` helpers were dropped entirely in favour of the
// synchronous *_transfer calls. Both live outside the libusb1-sys bindings.
extern "C" {
    fn libusb_clear_halt(dev_handle: *mut libusb_device_handle, endpoint: c_uchar) -> c_int;
}

pub const FLUSH_INBOUND: c_uchar = 0x01;
pub const FLUSH_OUTBOUND: c_uchar = 0x02;
/// Index of the serial number string descriptor (USB device descriptor layout).
const SERIAL_DESCRIPTOR_INDEX: u8 = 3;

pub fn error_name(code: c_int) -> String {
    unsafe {
        let p = libusb_error_name(code);
        if p.is_null() {
            return format!("unknown error {}", code);
        }
        CStr::from_ptr(p).to_string_lossy().into_owned()
    }
}

/// Panics with a libusb error description; used where the Python original asserts.
pub fn check(result: c_int) -> c_int {
    if result < 0 {
        panic!("libusb error: {} ({})", error_name(result), result);
    }
    result
}

/// Process-wide libusb context. The Python original built a fresh backend per
/// `acquire_device()` call; a single shared context is equivalent and much cheaper.
pub fn ctx() -> *mut libusb_context {
    static CTX: OnceLock<usize> = OnceLock::new();
    *CTX.get_or_init(|| unsafe {
        let mut ctx: *mut libusb_context = ptr::null_mut();
        let rc = libusb_init(&mut ctx);
        if rc != 0 {
            panic!("libusb_init failed: {}", error_name(rc));
        }
        ctx as usize
    }) as *mut libusb_context
}

/// Owns an open `libusb_device_handle`. Closing the handle on drop is the equivalent of
/// `usb.util.dispose_resources(device)` in the Python original.
pub struct Device {
    pub handle: *mut libusb_device_handle,
    pub serial_number: String,
}

impl Drop for Device {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { libusb_close(self.handle) };
            self.handle = ptr::null_mut();
        }
    }
}

/// RAII wrapper around `libusb_get_device_list`.
struct DeviceList {
    list: *const *mut libusb_device,
    count: usize,
}

impl DeviceList {
    fn new() -> Option<Self> {
        unsafe {
            let mut list: *const *mut libusb_device = ptr::null();
            let count = libusb_get_device_list(ctx(), &mut list);
            if count < 0 {
                return None;
            }
            Some(DeviceList {
                list,
                count: count as usize,
            })
        }
    }

    fn get(&self, index: usize) -> *mut libusb_device {
        unsafe { *self.list.add(index) }
    }
}

impl Drop for DeviceList {
    fn drop(&mut self) {
        if !self.list.is_null() {
            unsafe { libusb_free_device_list(self.list, 1) };
        }
    }
}

fn read_serial_number(handle: *mut libusb_device_handle) -> String {
    let mut buf = vec![0u8; 255];
    let rc = unsafe {
        libusb_get_string_descriptor_ascii(
            handle,
            SERIAL_DESCRIPTOR_INDEX,
            buf.as_mut_ptr() as *mut c_uchar,
            buf.len() as c_int,
        )
    };
    if rc <= 0 {
        return String::new();
    }
    buf.truncate(rc as usize);
    String::from_utf8_lossy(&buf).into_owned()
}

fn try_open(dev: *mut libusb_device) -> Option<Device> {
    unsafe {
        let mut handle: *mut libusb_device_handle = ptr::null_mut();
        if libusb_open(dev, &mut handle) != 0 {
            return None;
        }
        Some(Device {
            handle,
            serial_number: read_serial_number(handle),
        })
    }
}

/// Equivalent of `usb.core.find(idVendor=..., idProduct=..., backend=...)`, optionally
/// filtered by a substring of the USB serial number like pyusb's `match=` argument.
pub fn find_device(vid: u16, pid: u16, serial_match: Option<&str>) -> Option<Device> {
    let list = DeviceList::new()?;
    for i in 0..list.count {
        let dev = list.get(i);
        let mut desc: libusb_device_descriptor = unsafe { std::mem::zeroed() };
        if unsafe { libusb_get_device_descriptor(dev, &mut desc) } != 0 {
            continue;
        }
        if desc.idVendor != vid || desc.idProduct != pid {
            continue;
        }
        let Some(device) = try_open(dev) else {
            continue;
        };
        match serial_match {
            None => return Some(device),
            Some(m) => {
                if device.serial_number.contains(m) {
                    return Some(device);
                }
                // Dropping `device` closes the handle, moving on to the next candidate.
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Synchronous control transfers
// ---------------------------------------------------------------------------

/// `device.ctrl_transfer(...)` with a byte payload (host-to-device), returning the number
/// of bytes transferred.
pub fn ctrl_out(
    device: &Device,
    request_type: u8,
    request: u8,
    value: u16,
    index: u16,
    data: &[u8],
    timeout: c_uint,
) -> c_int {
    unsafe {
        libusb_control_transfer(
            device.handle,
            request_type,
            request,
            value,
            index,
            data.as_ptr() as *mut c_uchar,
            data.len() as u16,
            timeout,
        )
    }
}

/// `device.ctrl_transfer(...)` with an integer `wLength` (device-to-host), returning the
/// received bytes. pyusb returns an array padded to `wLength`; libusb reports the actual
/// length, so the buffer is padded here to keep the original's exact behaviour of always
/// yielding `wLength` bytes.
pub fn ctrl_in(
    device: &Device,
    request_type: u8,
    request: u8,
    value: u16,
    index: u16,
    length: usize,
    timeout: c_uint,
) -> Result<Vec<u8>, c_int> {
    let mut buf = vec![0u8; length];
    let rc = unsafe {
        libusb_control_transfer(
            device.handle,
            request_type,
            request,
            value,
            index,
            buf.as_mut_ptr() as *mut c_uchar,
            length as u16,
            timeout,
        )
    };
    if rc < 0 {
        return Err(rc);
    }
    buf.truncate(length);
    Ok(buf)
}

// ---------------------------------------------------------------------------
// Asynchronous control transfers (checkm8 / limera1n)
// ---------------------------------------------------------------------------

/// Equivalent of `libusb1_async_ctrl_transfer`: builds the SETUP packet by hand, submits
/// the transfer, spins for `timeout` milliseconds, then cancels it.
///
/// The transfer buffer is handed to libusb with `LIBUSB_TRANSFER_FREE_BUFFER`, so it is
/// intentionally leaked here exactly as the Python version leaks its `array.array`.
pub fn async_ctrl_transfer(
    device: &Device,
    request_type: u8,
    request: u8,
    value: u16,
    index: u16,
    data: &[u8],
    timeout: f64,
) {
    let request_timeout: c_uint = if timeout >= 1.0 { timeout as c_uint } else { 0 };

    let mut buf: Vec<u8> = Vec::with_capacity(8 + data.len());
    buf.push(request_type);
    buf.push(request);
    buf.extend_from_slice(&value.to_le_bytes());
    buf.extend_from_slice(&index.to_le_bytes());
    buf.extend_from_slice(&(data.len() as u16).to_le_bytes());
    buf.extend_from_slice(data);
    let length = buf.len();
    let buffer_ptr = buf.as_mut_ptr();
    std::mem::forget(buf);

    unsafe {
        let transfer = libusb_alloc_transfer(0);
        assert!(!transfer.is_null(), "libusb_alloc_transfer failed");

        (*transfer).dev_handle = device.handle;
        (*transfer).endpoint = 0; // EP0
        (*transfer).transfer_type = 0; // LIBUSB_TRANSFER_TYPE_CONTROL
        (*transfer).timeout = request_timeout;
        (*transfer).buffer = buffer_ptr;
        (*transfer).length = length as c_int;
        (*transfer).user_data = ptr::null_mut();
        (*transfer).callback =
            std::mem::transmute::<*mut c_void, libusb_transfer_cb_fn>(ptr::null_mut());
        (*transfer).flags = LIBUSB_TRANSFER_FREE_BUFFER;

        check(libusb_submit_transfer(transfer));

        let start = Instant::now();
        while start.elapsed().as_secs_f64() < timeout / 1000.0 {
            std::hint::spin_loop();
        }

        let rc = libusb_cancel_transfer(transfer);
        if rc != 0 && rc != LIBUSB_ERROR_NOT_FOUND {
            libusb_free_transfer(transfer);
            panic!("libusb_cancel_transfer failed: {}", error_name(rc));
        }
    }
}

/// `libusb1_no_error_ctrl_transfer` for host-to-device requests: errors are swallowed.
pub fn no_error_ctrl_out(
    device: &Device,
    request_type: u8,
    request: u8,
    value: u16,
    index: u16,
    data: &[u8],
    timeout: c_uint,
) {
    let _ = ctrl_out(device, request_type, request, value, index, data, timeout);
}

/// `libusb1_no_error_ctrl_transfer` for device-to-host requests: errors are swallowed.
pub fn no_error_ctrl_in(
    device: &Device,
    request_type: u8,
    request: u8,
    value: u16,
    index: u16,
    length: usize,
    timeout: c_uint,
) {
    let _ = ctrl_in(device, request_type, request, value, index, length, timeout);
}

// ---------------------------------------------------------------------------
// Port reset / bulk transfer
// ---------------------------------------------------------------------------

/// `dfu.usb_reset`: mirrors pyusb's `Device.reset()` for an unclaimed device, which claims
/// interface 0, flushes it, resets the port and releases the interface. Every failure is
/// swallowed, matching the bare `except usb.core.USBError: pass` in the original.
pub fn usb_reset(device: &Device) {
    unsafe {
        libusb_claim_interface(device.handle, 0);
        libusb_clear_halt(device.handle, FLUSH_INBOUND);
        libusb_clear_halt(device.handle, FLUSH_OUTBOUND);
        libusb_reset_device(device.handle);
        libusb_release_interface(device.handle, 0);
    }
}

/// Bulk write used by the Recovery Mode NOR flashing path (`device.write(0x04, ...)`).
/// Returns the number of bytes written.
pub fn bulk_write(device: &Device, endpoint: u8, data: &[u8], timeout: c_uint) -> c_int {
    let mut transferred: c_int = 0;
    let rc = unsafe {
        libusb_bulk_transfer(
            device.handle,
            endpoint,
            data.as_ptr() as *mut c_uchar,
            data.len() as c_int,
            &mut transferred,
            timeout,
        )
    };
    if rc < 0 {
        rc
    } else {
        transferred
    }
}

/// `recovery.send_command`: class request OUT with a NUL terminated string.
pub fn ctrl_command(device: &Device, command: &str) {
    let mut buf = command.as_bytes().to_vec();
    buf.push(0);
    ctrl_out(device, 0x40, 0, 0, 0, &buf, 30000);
}

/// Helper mirroring pyusb's `usb.core.USBError` message so failures stay diagnosable.
pub fn usb_error(context: &str, rc: c_int) -> String {
    format!("{}: {} ({})", context, error_name(rc), rc)
}
