//! Port of `dfu.py`: the USB DFU download protocol used by iOS devices in DFU Mode.

use std::thread::sleep;
use std::time::{Duration, Instant};

use crate::libusb::{self, Device};
use crate::utilities::die;

pub const MAX_PACKET_SIZE: usize = 0x800;

const APPLE_VENDOR_ID: u16 = 0x5ac;
const DFU_PRODUCT_ID: u16 = 0x1227;
const DEFAULT_TIMEOUT: f64 = 5.0;

/// `dfu.acquire_device(..., fatal=False)`: poll for a device in DFU Mode.
pub fn try_acquire_device(timeout: f64) -> Option<Device> {
    let start = Instant::now();
    loop {
        if let Some(device) = libusb::find_device(APPLE_VENDOR_ID, DFU_PRODUCT_ID, None) {
            return Some(device);
        }
        if start.elapsed().as_secs_f64() >= timeout {
            return None;
        }
        sleep(Duration::from_millis(1));
    }
}

/// `dfu.acquire_device()`: as above, but exits with status 1 if nothing shows up.
pub fn acquire_device() -> Device {
    match try_acquire_device(DEFAULT_TIMEOUT) {
        Some(device) => device,
        None => die(format!(
            "ERROR: No Apple device in DFU Mode 0x1227 detected after {:.2} second timeout. Exiting.",
            DEFAULT_TIMEOUT
        )),
    }
}

/// `dfu.reset_counters`
pub fn reset_counters(device: &Device) {
    let transferred = libusb::ctrl_out(device, 0x21, 4, 0, 0, &[], 1000);
    assert_eq!(transferred, 0);
}

/// `dfu.usb_reset`
pub fn usb_reset(device: &Device) {
    libusb::usb_reset(device);
}

/// `dfu.send_data`: chunked DNLOAD.
pub fn send_data(device: &Device, data: &[u8]) {
    let mut index = 0;
    while index < data.len() {
        let amount = (data.len() - index).min(MAX_PACKET_SIZE);
        let transferred =
            libusb::ctrl_out(device, 0x21, 1, 0, 0, &data[index..index + amount], 5000);
        assert_eq!(
            transferred as usize, amount,
            "send_data: short DNLOAD transfer ({} of {})",
            transferred, amount
        );
        index += amount;
    }
}

/// `dfu.get_data`: chunked UPLOAD.
pub fn get_data(device: &Device, amount: usize) -> Vec<u8> {
    let mut data = Vec::with_capacity(amount);
    let mut remaining = amount;
    while remaining > 0 {
        let part = remaining.min(MAX_PACKET_SIZE);
        let response = libusb::ctrl_in(device, 0xA1, 2, 0, 0, part, 5000)
            .unwrap_or_else(|e| die(libusb::usb_error("get_data", e)));
        assert_eq!(
            response.len(),
            part,
            "get_data: short UPLOAD transfer ({} of {})",
            response.len(),
            part
        );
        data.extend_from_slice(&response);
        remaining -= part;
    }
    data
}

/// `dfu.request_image_validation`: manifest request followed by a port reset.
pub fn request_image_validation(device: &Device) {
    let transferred = libusb::ctrl_out(device, 0x21, 1, 0, 0, &[], 1000);
    assert_eq!(transferred, 0);
    for _ in 0..3 {
        let _ = libusb::ctrl_in(device, 0xA1, 3, 0, 0, 6, 1000);
    }
    usb_reset(device);
}
