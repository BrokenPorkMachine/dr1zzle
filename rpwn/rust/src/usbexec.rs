//! Port of `usbexec.py`: the `exec`/`memcpy`/`memset` protocol spoken by the checkm8 and
//! steaks4uce shellcodes over DFU control transfers.

use crate::device_platform::{DevicePlatform, ALL_PLATFORMS};
use crate::dfu;
use crate::libusb;
use crate::shellcode::Arch;
use crate::utilities::{die, hex_encode, slice, u32_le};

/// `'execexec'[::-1]`
pub const EXEC_MAGIC: &[u8] = b"cexecexe";
/// `'donedone'[::-1]`
pub const DONE_MAGIC: &[u8] = b"enolden";
/// `'memcmemc'[::-1]`
pub const MEMC_MAGIC: &[u8] = b"cmcemce";
/// `'memsmems'[::-1]`
#[allow(dead_code)] // referenced by cmd_memset
pub const MEMS_MAGIC: &[u8] = b"smesmes";

pub const USB_READ_LIMIT: usize = 0x8000;
pub const CMD_TIMEOUT: u32 = 5000;
pub const AES_BLOCK_SIZE: usize = 16;
pub const AES_GID_KEY: u32 = 0x2000_0200;
pub const AES_UID_KEY: u32 = 0x2000_0201;

pub struct ExecConfig {
    /// (copyright line, kind, iBoot version) - each NUL padded to its field width.
    pub info: [&'static str; 3],
    pub aes_crypto_cmd: u64,
}

impl ExecConfig {
    /// `ExecConfig.match`
    pub fn matches(&self, info: &[u8]) -> bool {
        let mut expected = Vec::with_capacity(0x100);
        for (index, field) in self.info.iter().enumerate() {
            let width = match index {
                0 | 1 => 0x40,
                _ => 0x80,
            };
            let mut bytes = field.as_bytes().to_vec();
            bytes.resize(width, 0);
            expected.extend_from_slice(&bytes);
        }
        info == expected.as_slice()
    }
}

pub static CONFIGS: &[ExecConfig] = &[
    ExecConfig {
        info: [
            "SecureROM for s5l8947xsi, Copyright 2011, Apple Inc.",
            "RELEASE",
            "iBoot-1458.2",
        ],
        aes_crypto_cmd: 0x7060 + 1,
    },
    ExecConfig {
        info: [
            "SecureROM for s5l8950xsi, Copyright 2011, Apple Inc.",
            "RELEASE",
            "iBoot-1145.3",
        ],
        aes_crypto_cmd: 0x7300 + 1,
    },
    ExecConfig {
        info: [
            "SecureROM for s5l8955xsi, Copyright 2011, Apple Inc.",
            "RELEASE",
            "iBoot-1145.3.3",
        ],
        aes_crypto_cmd: 0x7340 + 1,
    },
    ExecConfig {
        info: [
            "SecureROM for t8002si, Copyright 2007-2014, Apple Inc.",
            "ROMRELEASE",
            "iBoot-2651.0.0.1.31",
        ],
        aes_crypto_cmd: 0x86DC + 1,
    },
    ExecConfig {
        info: [
            "SecureROM for t8004si, Copyright 2007-2014, Apple Inc.",
            "ROMRELEASE",
            "iBoot-2651.0.0.3.3",
        ],
        aes_crypto_cmd: 0x786C + 1,
    },
    ExecConfig {
        info: [
            "SecureROM for s5l8960xsi, Copyright 2012, Apple Inc.",
            "RELEASE",
            "iBoot-1704.10",
        ],
        aes_crypto_cmd: 0x1000_0B9A8,
    },
    ExecConfig {
        info: [
            "SecureROM for t8010si, Copyright 2007-2015, Apple Inc.",
            "ROMRELEASE",
            "iBoot-2696.0.0.1.33",
        ],
        aes_crypto_cmd: 0x1000_0C8F4,
    },
    ExecConfig {
        info: [
            "SecureROM for t8011si, Copyright 2007-2015, Apple Inc.",
            "ROMRELEASE",
            "iBoot-3135.0.0.2.3",
        ],
        aes_crypto_cmd: 0x1000_0C994,
    },
    ExecConfig {
        info: [
            "SecureROM for t8015si, Copyright 2007-2016, Apple Inc.",
            "ROMRELEASE",
            "iBoot-3332.0.0.1.23",
        ],
        aes_crypto_cmd: 0x1000_09E9C,
    },
];

/// One word of a `exec` command. Mirrors the Python variadic: numbers pack as a word,
/// a string is only accepted as the final argument.
pub enum ExecArg {
    Word(u64),
    Blob(Vec<u8>),
}

pub struct PwnedUSBDevice {
    pub serial_number: String,
    pub platform: &'static DevicePlatform,
    pub config: &'static ExecConfig,
}

impl PwnedUSBDevice {
    /// `PwnedUSBDevice.__init__`
    pub fn new() -> PwnedUSBDevice {
        let serial_number = read_serial_number();

        let platform = ALL_PLATFORMS
            .iter()
            .find(|dp| {
                serial_number.starts_with(&format!("CPID:{:04x} CPRV:{:02x} ", dp.cpid, dp.cprv))
            })
            .unwrap_or_else(|| {
                println!("{}", serial_number);
                die("ERROR: No matching usbexec.platform found for this device.");
            });

        // `config` is only needed after the image has been identified, so the object is
        // briefly assembled without it - exactly as the Python original does.
        let mut device = PwnedUSBDevice {
            serial_number,
            platform,
            config: CONFIGS.first().unwrap(),
        };

        let info = device.read_memory(device.image_base() + 0x200, 0x100);
        device.config = CONFIGS
            .iter()
            .find(|config| config.matches(&info))
            .unwrap_or_else(|| {
                println!("{}", crate::utilities::hex_dump(&info, 0));
                die("ERROR: No matching usbexec.config found for this image.");
            });

        device
    }

    // --- command encoding -------------------------------------------------

    pub fn cmd_arg_size(&self) -> usize {
        match self.platform.arch {
            Arch::Arm64 => 8,
            Arch::Armv7 => 4,
        }
    }

    pub fn cmd_data_offset(&self, index: usize) -> usize {
        16 + index * self.cmd_arg_size()
    }

    pub fn cmd_data_address(&self, index: usize) -> u64 {
        self.load_base() + self.cmd_data_offset(index) as u64
    }

    /// `cmd_memcpy`: `<8s magic><8x padding><arg0><arg1><arg2>`
    fn cmd_memcpy(&self, dest: u64, src: u64, length: u64) -> Vec<u8> {
        self.cmd_with_magic(MEMC_MAGIC, dest, src, length)
    }

    /// `cmd_memset`
    #[allow(dead_code)] // part of the ported usbexec API
    fn cmd_memset(&self, address: u64, c: u64, length: u64) -> Vec<u8> {
        self.cmd_with_magic(MEMS_MAGIC, address, c, length)
    }

    fn cmd_with_magic(&self, magic: &[u8], a: u64, b: u64, c: u64) -> Vec<u8> {
        let size = self.cmd_arg_size();
        let mut out = Vec::with_capacity(8 + 8 + size * 3);
        out.extend_from_slice(magic);
        out.extend_from_slice(&[0u8; 8]);
        for value in [a, b, c] {
            if size == 4 {
                out.extend_from_slice(&(value as u32).to_le_bytes());
            } else {
                out.extend_from_slice(&value.to_le_bytes());
            }
        }
        out
    }

    /// `load_base()`
    pub fn load_base(&self) -> u64 {
        if self.serial_number.contains("SRTG:") {
            self.platform.dfu_image_base
        } else {
            self.platform.dfu_load_base
        }
    }

    /// `image_base()`
    pub fn image_base(&self) -> u64 {
        if self.serial_number.contains("SRTG:") {
            self.platform.rom_base
        } else {
            self.platform.dfu_image_base
        }
    }

    // --- transport --------------------------------------------------------

    /// `PwnedUSBDevice.command`
    fn command(&self, request_data: &[u8], response_length: usize) -> Vec<u8> {
        assert!(
            response_length <= USB_READ_LIMIT,
            "command: response length {} exceeds USB_READ_LIMIT",
            response_length
        );
        let device = dfu::acquire_device();
        assert_eq!(self.serial_number, device.serial_number);

        dfu::send_data(&device, &[0u8; 16]);
        libusb::ctrl_out(&device, 0x21, 1, 0, 0, &[], 100);
        let _ = libusb::ctrl_in(&device, 0xA1, 3, 0, 0, 6, 100);
        let _ = libusb::ctrl_in(&device, 0xA1, 3, 0, 0, 6, 100);
        dfu::send_data(&device, request_data);

        // HACK: with a zero-length response the device prefixes one junk byte.
        let response = if response_length == 0 {
            let raw = libusb::ctrl_in(
                &device,
                0xA1,
                2,
                0xFFFF,
                0,
                response_length + 1,
                CMD_TIMEOUT,
            )
            .unwrap_or_else(|e| die(libusb::usb_error("usbexec.command", e)));
            slice(&raw, 1, raw.len())
        } else {
            libusb::ctrl_in(&device, 0xA1, 2, 0xFFFF, 0, response_length, CMD_TIMEOUT)
                .unwrap_or_else(|e| die(libusb::usb_error("usbexec.command", e)))
        };
        drop(device);

        assert_eq!(
            response.len(),
            response_length,
            "usbexec.command: expected {} bytes, got {}",
            response_length,
            response.len()
        );
        response
    }

    /// `PwnedUSBDevice.execute`
    pub fn execute(&self, response_length: usize, args: &[ExecArg]) -> (u64, Vec<u8>) {
        let size = self.cmd_arg_size();
        let mut cmd = Vec::new();
        for (i, arg) in args.iter().enumerate() {
            match arg {
                ExecArg::Word(value) => {
                    if size == 4 {
                        cmd.extend_from_slice(&(*value as u32).to_le_bytes());
                    } else {
                        cmd.extend_from_slice(&value.to_le_bytes());
                    }
                }
                ExecArg::Blob(data) => {
                    if i != args.len() - 1 {
                        die(format!(
                            "ERROR: usbexec.execute: invalid argument at position {}",
                            i
                        ));
                    }
                    cmd.extend_from_slice(data);
                }
            }
            if i == 0 && self.platform.arch != Arch::Arm64 {
                cmd.extend_from_slice(&[0u8; 4]);
            }
        }

        let mut request = EXEC_MAGIC.to_vec();
        request.extend_from_slice(&cmd);
        let data_offset = self.cmd_data_offset(0);
        let response = self.command(&request, data_offset + response_length);

        let done = &response[..8];
        assert_eq!(
            done, DONE_MAGIC,
            "usbexec.execute: bad done magic, request was not executed"
        );
        let retval = u64::from_le_bytes(response[8..16].try_into().unwrap());

        (retval, slice(&response, data_offset, response.len()))
    }

    // --- memory helpers ---------------------------------------------------

    pub fn read_memory(&self, address: u64, length: usize) -> Vec<u8> {
        let mut data: Vec<u8> = Vec::with_capacity(length);
        while data.len() < length {
            let part_length = (length - data.len()).min(USB_READ_LIMIT - self.cmd_data_offset(0));
            let response = self.command(
                &self.cmd_memcpy(
                    self.cmd_data_address(0),
                    address + data.len() as u64,
                    part_length as u64,
                ),
                self.cmd_data_offset(0) + part_length,
            );
            assert_eq!(
                &response[..8],
                DONE_MAGIC,
                "usbexec.read_memory: bad done magic"
            );
            data.extend_from_slice(&slice(&response, self.cmd_data_offset(0), response.len()));
        }
        data
    }

    pub fn write_memory(&self, address: u64, data: &[u8]) {
        let mut cmd = self.cmd_memcpy(address, self.cmd_data_address(3), data.len() as u64);
        cmd.extend_from_slice(data);
        self.command(&cmd, 0);
    }

    #[allow(dead_code)] // part of the ported usbexec API
    pub fn memset(&self, address: u64, c: u64, length: u64) {
        self.command(&self.cmd_memset(address, c, length), 0);
    }

    #[allow(dead_code)] // part of the ported usbexec API
    pub fn memcpy(&self, dest: u64, src: u64, length: u64) {
        self.command(&self.cmd_memcpy(dest, src, length), 0);
    }

    #[allow(dead_code)] // part of the ported usbexec API
    pub fn read_memory_uint8(&self, address: u64) -> u8 {
        self.read_memory(address, 1)[0]
    }

    #[allow(dead_code)] // part of the ported usbexec API
    pub fn read_memory_uint16(&self, address: u64) -> u16 {
        u16::from_le_bytes(self.read_memory(address, 2).try_into().unwrap())
    }

    pub fn read_memory_uint32(&self, address: u64) -> u32 {
        u32_le(&self.read_memory(address, 4), 0)
    }

    #[allow(dead_code)] // part of the ported usbexec API
    pub fn read_memory_uint64(&self, address: u64) -> u64 {
        u64::from_le_bytes(self.read_memory(address, 8).try_into().unwrap())
    }

    #[allow(dead_code)] // part of the ported usbexec API
    pub fn read_memory_ptr(&self, address: u64) -> u64 {
        match self.cmd_arg_size() {
            8 => self.read_memory_uint64(address),
            _ => self.read_memory_uint32(address) as u64,
        }
    }

    #[allow(dead_code)] // part of the ported usbexec API
    pub fn write_memory_uint8(&self, address: u64, value: u8) {
        self.write_memory(address, &value.to_le_bytes());
    }

    #[allow(dead_code)] // part of the ported usbexec API
    pub fn write_memory_uint16(&self, address: u64, value: u16) {
        self.write_memory(address, &value.to_le_bytes());
    }

    #[allow(dead_code)] // part of the ported usbexec API
    pub fn write_memory_uint32(&self, address: u64, value: u32) {
        self.write_memory(address, &value.to_le_bytes());
    }

    #[allow(dead_code)] // part of the ported usbexec API
    pub fn write_memory_uint64(&self, address: u64, value: u64) {
        self.write_memory(address, &value.to_le_bytes());
    }

    #[allow(dead_code)] // part of the ported usbexec API
    pub fn write_memory_ptr(&self, address: u64, value: u64) {
        match self.cmd_arg_size() {
            8 => self.write_memory_uint64(address, value),
            _ => self.write_memory_uint32(address, value as u32),
        }
    }

    /// `PwnedUSBDevice.aes`
    pub fn aes(&self, data: &[u8], action: u32, key: u32) -> Vec<u8> {
        assert!(data.len().is_multiple_of(AES_BLOCK_SIZE));
        let args = vec![
            ExecArg::Word(self.config.aes_crypto_cmd),
            ExecArg::Word(action as u64),
            ExecArg::Word(self.cmd_data_address(7)),
            ExecArg::Word(self.cmd_data_address(0)),
            ExecArg::Word(data.len() as u64),
            ExecArg::Word(key as u64),
            ExecArg::Word(0),
            ExecArg::Word(0),
            ExecArg::Blob(data.to_vec()),
        ];
        let (retval, received) = self.execute(data.len(), &args);
        assert_eq!(
            retval & 0xFFFF_FFFF,
            0,
            "usbexec.aes: on-device AES returned 0x{:x}",
            retval
        );
        slice(&received, 0, data.len())
    }

    /// Convenience for the CLI's `--decrypt-*` / `--encrypt-*` options.
    pub fn aes_hex(&self, hexdata: &str, action: u32, key: u32) -> String {
        let data = crate::utilities::hex_decode(hexdata)
            .unwrap_or_else(|e| die(format!("ERROR: Could not decode hex data. {}", e)));
        hex_encode(&self.aes(&data, action, key))
    }
}

/// Reads the USB serial number and releases the handle, matching the pattern the Python
/// original uses everywhere it only needs to identify the device.
fn read_serial_number() -> String {
    let device = dfu::acquire_device();
    device.serial_number.clone()
}
