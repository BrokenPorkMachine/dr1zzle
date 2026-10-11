//! Port of `device_platform.py`: per-SoC memory layout and metadata used by the
//! pwned USB exec path.

use std::sync::LazyLock;

use crate::shellcode::Arch;

#[derive(Clone, Copy)]
#[allow(dead_code)] // full metadata table, mirrored from device_platform.py
pub struct DevicePlatform {
    pub cpid: u32,
    pub cprv: u32,
    pub scep: u32,
    pub arch: Arch,
    pub srtg: &'static str,
    pub rom_base: u64,
    pub rom_size: u32,
    pub rom_sha1: &'static str,
    pub sram_base: u64,
    pub sram_size: u32,
    pub dram_base: u64,
    pub nonce_length: u32,
    pub sep_nonce_length: Option<u32>,
    pub demotion_reg: u64,
    pub dfu_image_base: u64,
    pub dfu_load_base: u64,
    pub recovery_image_base: u64,
    pub recovery_load_base: u64,
}

/// The `if` ladder in `DevicePlatform.__init__` that derives the four load addresses.
fn bases(cpid: u32) -> (u64, u64, u64, u64) {
    match cpid {
        0x8940 | 0x8947 => (0x3400_0000, 0x9FF0_0000, 0x9FF0_0000, 0x8000_0000),
        0x8950 | 0x8955 => (0x1000_0000, 0xBFF0_0000, 0xBFF0_0000, 0x8000_0000),
        0x8960 => (0x1803_80000, 0x1800_00000, 0x83D7_F7000, 0x8000_00000),
        0x8002 | 0x8004 => (0x4881_8000, 0x8000_0000, 0x4881_8000, 0x8000_0000),
        0x8010 | 0x8011 => (0x1800_B0000, 0x8000_00000, 0x1800_B0000, 0x8000_00000),
        0x8015 => (0x1800_1C000, 0x8000_00000, 0x1800_1C000, 0x8000_00000),
        other => crate::utilities::die(format!(
            "ERROR: No memory map known for CPID 0x{:x}. Exiting.",
            other
        )),
    }
}

impl DevicePlatform {
    #[allow(clippy::too_many_arguments)]
    fn new(
        cpid: u32,
        cprv: u32,
        scep: u32,
        arch: Arch,
        srtg: &'static str,
        rom_base: u64,
        rom_size: u32,
        rom_sha1: &'static str,
        sram_base: u64,
        sram_size: u32,
        dram_base: u64,
        nonce_length: u32,
        sep_nonce_length: Option<u32>,
        demotion_reg: u64,
    ) -> Self {
        let (dfu_image_base, dfu_load_base, recovery_image_base, recovery_load_base) = bases(cpid);
        DevicePlatform {
            cpid,
            cprv,
            scep,
            arch,
            srtg,
            rom_base,
            rom_size,
            rom_sha1,
            sram_base,
            sram_size,
            dram_base,
            nonce_length,
            sep_nonce_length,
            demotion_reg,
            dfu_image_base,
            dfu_load_base,
            recovery_image_base,
            recovery_load_base,
        }
    }

    /// `DevicePlatform.name()`
    pub fn name(&self) -> String {
        if (0x8720..=0x8960).contains(&self.cpid) {
            format!("s5l{:x}xsi", self.cpid)
        } else if matches!(self.cpid, 0x7002 | 0x8000 | 0x8001 | 0x8003) {
            format!("s{:x}xsi", self.cpid)
        } else {
            format!("t{:x}xsi", self.cpid)
        }
    }
}

pub static ALL_PLATFORMS: LazyLock<Vec<DevicePlatform>> = LazyLock::new(|| {
    vec![
        DevicePlatform::new(
            0x8947,
            0x00,
            0x10,
            Arch::Armv7,
            "iBoot-1458.2",
            0x3F00_0000,
            0x10000,
            "d9320ddd4bdb1de79ae0601f20e7db23441ab1a7",
            0x3400_0000,
            0x40000,
            0x8000_0000,
            20,
            None,
            0x3F50_0000,
        ),
        DevicePlatform::new(
            0x8950,
            0x20,
            0x10,
            Arch::Armv7,
            "iBoot-1145.3",
            0x3F00_0000,
            0x10000,
            "50a8dd9863868c971aaf95a96e5152378784e4db",
            0x1000_0000,
            0x80000,
            0x8000_0000,
            20,
            None,
            0x3F50_0000,
        ),
        DevicePlatform::new(
            0x8955,
            0x20,
            0x10,
            Arch::Armv7,
            "iBoot-1145.3.3",
            0x3F00_0000,
            0x10000,
            "3af575cc84e54f951db2a83227737664abdc8f40",
            0x1000_0000,
            0x80000,
            0x8000_0000,
            20,
            None,
            0x3F50_0000,
        ),
        DevicePlatform::new(
            0x8002,
            0x10,
            0x01,
            Arch::Armv7,
            "iBoot-2651.0.0.1.31",
            0x4000_0000,
            0x100000,
            "46c14a17f54ec6079260e9253e813084ab1e634b",
            0x4880_0000,
            0x120000,
            0x8000_0000,
            32,
            Some(20),
            0x481B_C000,
        ),
        DevicePlatform::new(
            0x8004,
            0x10,
            0x01,
            Arch::Armv7,
            "iBoot-2651.0.0.3.3",
            0x4000_0000,
            0x20000,
            "8afdcd6c147ac63fddadd1b92536d1f80c0b8a21",
            0x4880_0000,
            0x140000,
            0x8000_0000,
            32,
            Some(20),
            0x481B_C000,
        ),
        DevicePlatform::new(
            0x8960,
            0x11,
            0x01,
            Arch::Arm64,
            "iBoot-1704.10",
            0x1000_00000,
            0x80000,
            "2ae035c46e02ca40ae777f89a6637be694558f0a",
            0x1800_00000,
            0x400000,
            0x8000_00000,
            20,
            Some(20),
            0x20E0_2A000,
        ),
        DevicePlatform::new(
            0x8010,
            0x11,
            0x01,
            Arch::Arm64,
            "iBoot-2696.0.0.1.33",
            0x1000_00000,
            0x20000,
            "41a488b3c46ff06c1a2376f3405b079fb0f15316",
            0x1800_00000,
            0x200000,
            0x8000_00000,
            32,
            Some(20),
            0x2102_BC000,
        ),
        DevicePlatform::new(
            0x8011,
            0x10,
            0x01,
            Arch::Arm64,
            "iBoot-3135.0.0.2.3",
            0x1000_00000,
            0x100000,
            "2fae20a11860b0e3ce1d8a6df7d3961f610ab70d",
            0x1800_00000,
            0x200000,
            0x8000_00000,
            32,
            Some(20),
            0x2102_BC000,
        ),
        DevicePlatform::new(
            0x8015,
            0x11,
            0x01,
            Arch::Arm64,
            "iBoot-3332.0.0.1.23",
            0x1000_00000,
            0x100000,
            "96fccb1a63de1a2d50ff14555d3898a5af46e9b1",
            0x1800_00000,
            0x200000,
            0x8000_00000,
            32,
            Some(20),
            0x2352_BC000,
        ),
    ]
});
