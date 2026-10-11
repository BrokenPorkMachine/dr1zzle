//! Port of `dfuexec.py`: the `exec` command interpreter that runs inside a device already
//! pwned in DFU Mode.

use std::thread::sleep;
use std::time::Duration;

use crate::dfu;
use crate::image3::Image3;
use crate::recovery;
use crate::shellcode;
use crate::utilities::{
    apply_patches, die, hex_decode, hex_encode, read_file, sha256_hex, slice, timestamp, u32_le,
    write_file,
};

/// `'exec'[::-1]`
pub const EXEC_MAGIC: &[u8] = b"cexe";
pub const AES_BLOCK_SIZE: usize = 16;
pub const AES_GID_KEY: u32 = 0x2000_0200;
pub const AES_UID_KEY: u32 = 0x2000_0201;
pub const AES_ENCRYPT: u32 = 16;
pub const AES_DECRYPT: u32 = 17;

const IBSS_SHA256: &str = "b47816105ce97ef02637ec113acdefcdee32336a11e04eda0a6f4fc5e6617e61";
const IBSS_HELP_1: &str =
    "Download iPhone2,1_4.3.5_8L1_Restore.ipsw and use the following command to extract iBSS:";
const IBSS_HELP_2: &str =
    "unzip -p iPhone2,1_4.3.5_8L1_Restore.ipsw Firmware/dfu/iBSS.n88ap.RELEASE.dfu > n88ap-iBSS-4.3.5.img3";

#[derive(Clone, Copy)]
pub struct PwnedDeviceConfig {
    pub version: &'static str,
    pub cpid: &'static str,
    pub aes_crypto_cmd: u32,
    pub memmove: u32,
    pub get_block_device: u32,
    pub load_address: u32,
    pub rom_address: u32,
    pub rom_size: u32,
    pub rom_sha256: &'static str,
}

pub static CONFIGS: &[PwnedDeviceConfig] = &[
    // S5L8920 (old bootrom)
    PwnedDeviceConfig {
        version: "359.3",
        cpid: "8920",
        aes_crypto_cmd: 0x925,
        memmove: 0x83d4,
        get_block_device: 0x1351,
        load_address: 0x8400_0000,
        rom_address: 0xbf00_0000,
        rom_size: 0x10000,
        rom_sha256: "99fd16f919a506c7f0701620e132e18c0e6f4025a57a85807960ca092e5e3587",
    },
    // S5L8920 (new bootrom)
    PwnedDeviceConfig {
        version: "359.3.2",
        cpid: "8920",
        aes_crypto_cmd: 0x925,
        memmove: 0x83dc,
        get_block_device: 0x1351,
        load_address: 0x8400_0000,
        rom_address: 0xbf00_0000,
        rom_size: 0x10000,
        rom_sha256: "0e6feb1144c95b1ee088ecd6c45bfdc2ed17191167555b6ca513d6572e463c86",
    },
    // S5L8922
    PwnedDeviceConfig {
        version: "359.5",
        cpid: "8922",
        aes_crypto_cmd: 0x919,
        memmove: 0x8564,
        get_block_device: 0x1851,
        load_address: 0x8400_0000,
        rom_address: 0xbf00_0000,
        rom_size: 0x10000,
        rom_sha256: "07b8a615f00961c5802451b5717c344db287b68c5f6d2331ac6ba7a6acdbac9d",
    },
    // S5L8930
    PwnedDeviceConfig {
        version: "574.4",
        cpid: "8930",
        aes_crypto_cmd: 0x686d,
        memmove: 0x84dc,
        get_block_device: 0x81d5,
        load_address: 0x8400_0000,
        rom_address: 0xbf00_0000,
        rom_size: 0x10000,
        rom_sha256: "4f34652a238a57ae0018b6e66c20a240cdbee8b4cca59a99407d09f83ea8082d",
    },
];

pub struct PwnedDFUDevice {
    pub identifier: String,
    pub config: &'static PwnedDeviceConfig,
}

impl PwnedDFUDevice {
    /// `PwnedDFUDevice.__init__`
    pub fn new() -> PwnedDFUDevice {
        let identifier = Self::identifier();

        if !identifier.contains("PWND:[") {
            die("ERROR: Device is not in pwned DFU Mode. Use -p flag to exploit device and then try again.");
        }
        if identifier.contains("CPID:8720") {
            die("ERROR: This feature is not supported on iPod Touch (2nd generation).");
        }

        let config = CONFIGS
            .iter()
            .find(|config| identifier.contains(&format!("SRTG:[iBoot-{}]", config.version)))
            .unwrap_or_else(|| {
                die("ERROR: Device seems to be in pwned DFU Mode, but a matching configuration was not found.")
            });

        PwnedDFUDevice { identifier, config }
    }

    /// Reads the USB serial number, releasing the handle as the Python original does.
    pub fn identifier() -> String {
        let device = dfu::acquire_device();
        device.serial_number.clone()
    }

    /// `PwnedDFUDevice.ecid_string`
    pub fn ecid_string(&self) -> String {
        self.identifier
            .split_whitespace()
            .find(|token| token.starts_with("ECID:"))
            .map(|token| token[5..].to_string())
            .unwrap_or_else(|| die("ERROR: ECID is missing from USB serial number string."))
    }

    /// `PwnedDFUDevice.execute`: send a command to the `exec` interpreter and read back
    /// `receive_length` bytes of its return value.
    pub fn execute(&self, cmd: &[u8], receive_length: usize) -> (u32, Vec<u8>) {
        let device = dfu::acquire_device();
        assert_eq!(self.identifier, device.serial_number);

        dfu::reset_counters(&device);
        let mut request = EXEC_MAGIC.to_vec();
        request.extend_from_slice(cmd);
        dfu::send_data(&device, &request);
        dfu::request_image_validation(&device);
        drop(device);

        sleep(Duration::from_millis(500));

        let device = dfu::acquire_device();
        assert_eq!(self.identifier, device.serial_number);

        let required_length = 0x8 + receive_length;
        let required_length = if required_length.is_multiple_of(0x800) {
            required_length
        } else {
            required_length / 0x800 * 0x800 + 0x800
        };
        let received = dfu::get_data(&device, required_length);
        drop(device);

        let exec_cleared = u32_le(&received, 0);
        let retval = u32_le(&received, 4);
        assert_eq!(exec_cleared, 0, "exec magic was not cleared by the device");

        (retval, slice(&received, 8, 8 + receive_length))
    }

    /// `PwnedDFUDevice.securerom_dump`
    pub fn securerom_dump(&self) -> Vec<u8> {
        let securerom = self.read_memory(
            self.config.rom_address as u64,
            self.config.rom_size as usize,
        );
        if sha256_hex(&securerom) != self.config.rom_sha256 {
            die("ERROR: SecureROM was dumped, but the SHA256 hash does not match. Exiting.");
        }
        securerom
    }

    /// `PwnedDFUDevice.aes`
    pub fn aes(&self, data: &[u8], action: u32, key: u32) -> Vec<u8> {
        if !data.len().is_multiple_of(AES_BLOCK_SIZE) {
            die(format!(
                "ERROR: Length of data for AES encryption/decryption must be a multiple of {}.",
                AES_BLOCK_SIZE
            ));
        }

        let mut cmd = Vec::new();
        for value in [
            self.config.aes_crypto_cmd,
            action,
            self.config.load_address + 36,
            self.config.load_address + 0x8,
            data.len() as u32,
            key,
            0,
            0,
        ] {
            cmd.extend_from_slice(&value.to_le_bytes());
        }
        cmd.extend_from_slice(data);

        let (_, received) = self.execute(&cmd, data.len());
        slice(&received, 0, data.len())
    }

    /// `PwnedDFUDevice.aes_hex`
    pub fn aes_hex(&self, hexdata: &str, action: u32, key: u32) -> String {
        if !hexdata.len().is_multiple_of(32) {
            die(format!(
                "ERROR: Length of hex data for AES encryption/decryption must be a multiple of {}.",
                2 * AES_BLOCK_SIZE
            ));
        }
        let data = hex_decode(hexdata)
            .unwrap_or_else(|e| die(format!("ERROR: Could not decode hex data. {}", e)));
        hex_encode(&self.aes(&data, action, key))
    }

    /// `PwnedDFUDevice.read_memory`
    pub fn read_memory(&self, address: u64, length: usize) -> Vec<u8> {
        let mut cmd = Vec::new();
        for value in [
            self.config.memmove,
            self.config.load_address + 8,
            address as u32,
            length as u32,
        ] {
            cmd.extend_from_slice(&value.to_le_bytes());
        }
        let (_, data) = self.execute(&cmd, length);
        data
    }

    /// `PwnedDFUDevice.write_memory`
    #[allow(dead_code)] // part of the ported exec API
    pub fn write_memory(&self, address: u64, data: &[u8]) {
        let mut cmd = Vec::new();
        for value in [
            self.config.memmove,
            address as u32,
            self.config.load_address + 20,
            data.len() as u32,
        ] {
            cmd.extend_from_slice(&value.to_le_bytes());
        }
        cmd.extend_from_slice(data);
        self.execute(&cmd, 0);
    }

    /// `PwnedDFUDevice.nor_dump`
    pub fn nor_dump(&self, save_backup: bool) -> Vec<u8> {
        let mut cmd = Vec::new();
        cmd.extend_from_slice(&self.config.get_block_device.to_le_bytes());
        cmd.extend_from_slice(&(self.config.load_address + 12).to_le_bytes());
        cmd.extend_from_slice(b"nor0\0");

        let (bdev, _) = self.execute(&cmd, 0);
        if bdev == 0 {
            die("ERROR: Unable to dump NOR. Pointer to nor0 block device was NULL.");
        }

        let data = self.read_memory(bdev as u64 + 28, 4);
        let read = u32_le(&data, 0);
        if read == 0 {
            die("ERROR: Unable to dump NOR. Function pointer for reading was NULL.");
        }

        const NOR_PART_SIZE: usize = 0x20000;
        const NOR_PARTS: usize = 8;

        let mut nor = Vec::with_capacity(NOR_PART_SIZE * NOR_PARTS);
        for i in 0..NOR_PARTS {
            println!("Dumping NOR, part {}/{}.", i + 1, NOR_PARTS);
            let mut cmd = Vec::new();
            for value in [
                read,
                bdev,
                self.config.load_address + 8,
                (i * NOR_PART_SIZE) as u32,
                0,
                NOR_PART_SIZE as u32,
            ] {
                cmd.extend_from_slice(&value.to_le_bytes());
            }
            let (_, received) = self.execute(&cmd, NOR_PART_SIZE);
            nor.extend_from_slice(&received);
        }

        if save_backup {
            let filename = format!(
                "nor-backups/nor-{}-{}.dump",
                self.ecid_string(),
                timestamp()
            );
            write_file(&filename, &nor).unwrap_or_else(|e| die(format!("ERROR: {}.", e)));
            println!("NOR backed up to file: {}", filename);
        }

        nor
    }

    /// `PwnedDFUDevice.boot_ibss`: push a patched iBSS to bounce the device into Recovery.
    pub fn boot_ibss(&self) {
        println!("Sending iBSS.");
        if self.config.cpid != "8920" {
            die("ERROR: Boot iBSS is currently only supported on iPhone 3GS.");
        }

        let data = match read_file("n88ap-iBSS-4.3.5.img3") {
            Ok(data) => data,
            Err(_) => {
                println!("ERROR: n88ap-iBSS-4.3.5.img3 is missing.");
                println!("{}", IBSS_HELP_1);
                println!("{}", IBSS_HELP_2);
                std::process::exit(1);
            }
        };
        if data.is_empty() {
            println!("ERROR: n88ap-iBSS-4.3.5.img3 exists, but is empty (size: 0 bytes).");
            println!("{}", IBSS_HELP_1);
            println!("{}", IBSS_HELP_2);
            std::process::exit(1);
        }
        if sha256_hex(&data) != IBSS_SHA256 {
            println!(
                "ERROR: n88ap-iBSS-4.3.5.img3 exists, but is from the wrong IPSW or corrupted."
            );
            println!("{}", IBSS_HELP_1);
            println!("{}", IBSS_HELP_2);
            std::process::exit(1);
        }

        let ibss = Image3::new(&data);
        let decrypted = ibss.new_image3(Some(self), true);
        let patches: Vec<(u32, Vec<u8>)> = vec![
            // patch 'reset' command string to 'run'
            (0x14954, b"run\0".to_vec()),
            // patch 'reset' command handler to LOAD_ADDRESS + 1
            (0x17654, 0x4100_0001u32.to_le_bytes().to_vec()),
        ];
        let patched_ibss = [
            slice(&decrypted, 0, 64),
            apply_patches(&slice(&decrypted, 64, decrypted.len()), &patches),
        ]
        .concat();

        let device = dfu::acquire_device();
        assert_eq!(self.identifier, device.serial_number);
        dfu::reset_counters(&device);
        dfu::request_image_validation(&device);
        drop(device);

        sleep(Duration::from_millis(500));

        let device = dfu::acquire_device();
        assert_eq!(self.identifier, device.serial_number);
        dfu::send_data(&device, &patched_ibss);
        dfu::request_image_validation(&device);
        drop(device);

        sleep(Duration::from_millis(500));

        println!("Waiting for iBSS to enter Recovery Mode.");
        drop(recovery::acquire_device());
    }

    /// `PwnedDFUDevice.flash_nor`
    pub fn flash_nor(&self, nor: &[u8]) {
        self.boot_ibss();
        println!("Sending iBSS payload to flash NOR.");

        const MAX_SHELLCODE_LENGTH: usize = 128;
        let mut payload = shellcode::IBSS_FLASH_NOR.to_vec();
        assert!(payload.len() <= MAX_SHELLCODE_LENGTH);
        payload.resize(MAX_SHELLCODE_LENGTH, 0x00);
        payload.extend_from_slice(nor);

        let device = recovery::acquire_device();
        assert!(
            device.serial_number.contains("CPID:8920"),
            "ERROR: Expected an iPhone 3GS in Recovery Mode."
        );
        recovery::send_data(&device, &payload);
        // Sending 'run' resets the port, so the request fails on a healthy device. The
        // error is expected and deliberately ignored.
        recovery::send_command(&device, "run");
        drop(device);
        println!("If screen is not red, NOR was flashed successfully and device will reboot.");
    }

    /// `PwnedDFUDevice.decrypt_keybag`, backed by the `aes-keys/` cache directory.
    pub fn decrypt_keybag(&self, keybag: &[u8]) -> Vec<u8> {
        const KEYBAG_LENGTH: usize = 48;
        assert_eq!(keybag.len(), KEYBAG_LENGTH);

        let keybag_filename = format!("aes-keys/S5L{}-firmware", self.config.cpid);
        let data = read_file(&keybag_filename).unwrap_or_default();
        assert_eq!(data.len() % (2 * KEYBAG_LENGTH), 0);

        let mut i = 0;
        while i < data.len() {
            if &data[i..i + KEYBAG_LENGTH] == keybag {
                return slice(&data, i + KEYBAG_LENGTH, i + 2 * KEYBAG_LENGTH);
            }
            i += 2 * KEYBAG_LENGTH;
        }

        let decrypted_keybag = self.aes(keybag, AES_DECRYPT, AES_GID_KEY);

        let mut entry = keybag.to_vec();
        entry.extend_from_slice(&decrypted_keybag);
        append_file(&keybag_filename, &entry);

        decrypted_keybag
    }
}

fn append_file(path: &str, data: &[u8]) {
    use std::io::Write;
    if let Some(parent) = std::path::Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            let _ = std::fs::create_dir_all(parent);
        }
    }
    match std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(path)
    {
        Ok(mut file) => file
            .write_all(data)
            .unwrap_or_else(|e| die(format!("ERROR: {}: {}", path, e))),
        Err(e) => die(format!("ERROR: {}: {}", path, e)),
    }
}
