//! Port of `recovery.py`: the minimal Recovery Mode protocol used to push the iBSS payload
//! that flashes NOR.

use std::thread::sleep;
use std::time::{Duration, Instant};

use crate::libusb::{self, Device};
use crate::utilities::die;

pub const MAX_PACKET_SIZE: usize = 0x4000;

const APPLE_VENDOR_ID: u16 = 0x5ac;
const RECOVERY_PRODUCT_ID: u16 = 0x1281;
const DEFAULT_TIMEOUT: f64 = 10.0;

/// `recovery.acquire_device`: poll for a device in Recovery Mode.
pub fn acquire_device() -> Device {
    let start = Instant::now();
    while start.elapsed().as_secs_f64() < DEFAULT_TIMEOUT {
        if let Some(device) = libusb::find_device(APPLE_VENDOR_ID, RECOVERY_PRODUCT_ID, None) {
            return device;
        }
        use std::io::Write;
        let _ = std::io::stdout().flush();
        sleep(Duration::from_millis(100));
    }
    die("ERROR: No Apple device in Recovery Mode 0x1281 detected. Exiting.")
}

/// `recovery.send_command`
pub fn send_command(device: &Device, command: &str) {
    libusb::ctrl_command(device, command);
}

/// `recovery.send_data`: bulk upload to endpoint 4, preceded by a start-of-transfer
/// control request.
pub fn send_data(device: &Device, data: &[u8]) {
    let transferred = libusb::ctrl_out(device, 0x41, 0, 0, 0, &[], 1000);
    assert_eq!(transferred, 0);
    let mut index = 0;
    while index < data.len() {
        let amount = (data.len() - index).min(MAX_PACKET_SIZE);
        let written = libusb::bulk_write(device, 0x04, &data[index..index + amount], 1000);
        assert_eq!(
            written as usize, amount,
            "recovery.send_data: short bulk write ({} of {})",
            written, amount
        );
        index += amount;
    }
}
