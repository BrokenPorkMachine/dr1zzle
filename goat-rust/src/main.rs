use std::{
    env, fs, io,
    path::{Path, PathBuf},
    process::{Command, ExitCode},
    thread,
    time::Duration,
};

mod container;
mod crypto;

const BOARDS: [&str; 4] = [
    "pico2",
    "pimoroni_tiny2350",
    "waveshare_rp2350_usb_a",
    "waveshare_rp2350_zero",
];
const UF2_MAGIC: [u8; 4] = [0x55, 0x46, 0x32, 0x0a];
const UF2_FAMILY: [u8; 4] = [0x57, 0x51, 0x5d, 0x9e];
const UF2_END: [u8; 4] = [0x30, 0x6f, 0xb1, 0x0a];

fn err(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}
fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}
fn firmware_dir(arg: Option<&str>) -> PathBuf {
    arg.map(PathBuf::from)
        .unwrap_or_else(|| root().join("goat/usbr34ker/firmware"))
}
fn firmware(board: &str, dir: &Path) -> io::Result<PathBuf> {
    if !BOARDS.contains(&board) {
        return Err(err(format!(
            "unknown board {board}; choose {}",
            BOARDS.join(", ")
        )));
    }
    let name = format!("usbr34ker.{board}.uf2");
    let candidates = [
        dir.join(&name),
        PathBuf::from(&name),
        PathBuf::from("firmware").join(&name),
    ];
    candidates
        .into_iter()
        .find(|p| p.is_file())
        .ok_or_else(|| err(format!("missing bundled firmware: {name}")))
}
fn validate(path: &Path) -> io::Result<u64> {
    let data = fs::read(path)?;
    if data.is_empty() || data.len() % 512 != 0 {
        return Err(err(format!("{} is not a complete UF2", path.display())));
    }
    if data[..4] != UF2_MAGIC || data[4..8] != UF2_FAMILY || data[data.len() - 4..] != UF2_END {
        return Err(err(format!("{} has invalid UF2 markers", path.display())));
    }
    Ok(data.len() as u64)
}
fn ports() -> Vec<PathBuf> {
    let mut out = Vec::new();
    for dir in ["/dev", "/dev"] {
        if let Ok(entries) = fs::read_dir(dir) {
            for e in entries.flatten() {
                let n = e.file_name().to_string_lossy().to_string();
                if n.contains("usbmodem")
                    || n.contains("usbserial")
                    || n.starts_with("ttyACM")
                    || n.starts_with("ttyUSB")
                {
                    out.push(e.path());
                }
            }
        }
    }
    out.sort();
    out.dedup();
    out
}
fn mounts() -> Vec<PathBuf> {
    ["/Volumes/RPI-RP2", "/media/RPI-RP2", "/run/media/RPI-RP2"]
        .into_iter()
        .map(PathBuf::from)
        .filter(|p| p.is_dir())
        .collect()
}
fn list(dir: &Path) -> io::Result<()> {
    println!("goat-rs: usbr34ker firmware bundle: {}", dir.display());
    for b in BOARDS {
        match firmware(b, dir).and_then(|p| Ok((p.clone(), validate(&p)?))) {
            Ok((p, n)) => println!("  {b:<30} {n:>7} bytes  {}", p.display()),
            Err(_) => println!("  {b:<30} MISSING"),
        }
    }
    println!(
        "goat-rs: serial ports: {}",
        ports()
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!(
        "goat-rs: RP2 boot volumes: {}",
        mounts()
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
    Ok(())
}
fn flash(board: &str, dir: &Path, mount: &Path, wait: f64) -> io::Result<()> {
    let src = firmware(board, dir)?;
    let size = validate(&src)?;
    if !mount.is_dir() {
        return Err(err(format!(
            "boot volume does not exist: {}",
            mount.display()
        )));
    }
    let dst = mount.join(src.file_name().unwrap());
    println!(
        "goat-rs: flashing {board} ({size} bytes) to {}",
        dst.display()
    );
    fs::copy(src, dst)?;
    println!("goat-rs: UF2 copied; waiting for RP2350 reboot");
    thread::sleep(Duration::from_secs_f64(wait.max(0.0)));
    Ok(())
}
/// Find the RPWN binary: the two environment overrides, then the in-tree
/// release build, then the name on PATH. The in-tree candidate is what a fresh
/// checkout has after `cargo build --release --manifest-path rpwn/rust/Cargo.toml`,
/// so the usual case does not need the override at all.
fn rpwn_binary() -> PathBuf {
    for key in ["GOAT_RPWN", "RPWN"] {
        if let Some(value) = env::var_os(key) {
            return PathBuf::from(value);
        }
    }
    // The in-tree release build is four levels up from the binary
    // (<root>/goat-rust/target/release/goat -> <root>), so the usual case
    // needs neither an override nor a PATH entry.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(root) = exe.ancestors().nth(4) {
            let candidate = root.join("rpwn/rust/target/release/rpwn");
            if candidate.is_file() {
                return candidate;
            }
        }
    }
    PathBuf::from("rpwn")
}

fn rpwn() -> io::Result<ExitCode> {
    let bin = rpwn_binary();
    let status = Command::new(&bin).arg("-p").status().map_err(|e| {
        err(format!(
            "cannot run RPWN {}: {e}\nbuild it with: cargo build --release \
             --manifest-path rpwn/rust/Cargo.toml --locked\nor set GOAT_RPWN \
             to an installed rpwn",
            bin.display()
        ))
    })?;
    Ok(status
        .code()
        .and_then(|c| u8::try_from(c).ok())
        .map(ExitCode::from)
        .unwrap_or(ExitCode::FAILURE))
}
fn walkthrough() {
    println!("GOAT / usbr34ker Rust walkthrough\n1. Connect the RP2350 helper board in BOOTSEL mode.\n2. Select one of: {}\n3. Flash its UF2 to RPI-RP2.\n4. Observe the 115200 baud UART.\n5. Use the Rust RPWN path for Apple DFU.", BOARDS.join(", "));
}
fn hex_bytes(s: &str) -> io::Result<Vec<u8>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() % 2 != 0 {
        return Err(err("hex value must have an even length"));
    };
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| err("invalid hex key")))
        .collect()
}
fn hex(v: &[u8]) -> String {
    v.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() -> ExitCode {
    let a: Vec<String> = env::args().skip(1).collect();
    let result: io::Result<ExitCode> = match a.first().map(String::as_str) {
        Some("usbr34ker") => match a.get(1).map(String::as_str) {
            Some("list") => list(&firmware_dir(
                a.iter()
                    .position(|x| x == "--firmware-dir")
                    .and_then(|i| a.get(i + 1))
                    .map(String::as_str),
            ))
            .map(|_| ExitCode::SUCCESS),
            Some("walkthrough") => {
                walkthrough();
                Ok(ExitCode::SUCCESS)
            }
            Some("flash") => {
                let b = a
                    .iter()
                    .position(|x| x == "--board")
                    .and_then(|i| a.get(i + 1))
                    .ok_or_else(|| err("--board is required"));
                let m = a
                    .iter()
                    .position(|x| x == "--mount")
                    .and_then(|i| a.get(i + 1))
                    .map(PathBuf::from)
                    .or_else(|| mounts().into_iter().next());
                match (b, m) {
                    (Ok(b), Some(m)) => {
                        flash(b, &firmware_dir(None), &m, 0.0).map(|_| ExitCode::SUCCESS)
                    }
                    (_, None) => Err(err("RP2 boot volume not found; pass --mount")),
                    (Err(e), _) => Err(e),
                }
            }
            _ => Err(err("usage: goat usbr34ker {list|walkthrough|flash}")),
        },
        Some("verify") => (|| -> io::Result<ExitCode> {
            let p = a
                .get(1)
                .ok_or_else(|| err("usage: goat verify <container>"))?;
            let (cert, outer) = container::verify_signatures(&fs::read(p)?)?;
            println!(
                "goat-rs: certificate self-signature {}",
                if cert { "OK" } else { "FAILED" }
            );
            println!(
                "goat-rs: container signature {}",
                if outer { "OK" } else { "FAILED" }
            );
            if cert && outer {
                Ok(ExitCode::SUCCESS)
            } else {
                Ok(ExitCode::FAILURE)
            }
        })(),
        Some("unseal") => (|| -> io::Result<ExitCode> {
            let p = a
                .get(1)
                .ok_or_else(|| err("usage: goat unseal <container> --key-hex HEX"))?;
            let i = a
                .iter()
                .position(|x| x == "--key-hex")
                .and_then(|n| a.get(n + 1))
                .ok_or_else(|| err("--key-hex is required"))?;
            let key = hex_bytes(i)?;
            let (cert, outer) = container::verify_signatures(&fs::read(p)?)?;
            if !cert || !outer {
                return Err(err("container signature verification failed"));
            };
            let payload = container::decrypt_payload(&fs::read(p)?, &key)?;
            print!(
                "unsealed {} bytes, sha256={}\n",
                payload.len(),
                hex(&crypto::sha256(&payload))
            );
            Ok(ExitCode::SUCCESS)
        })(),
        Some("inspect") => (|| -> io::Result<ExitCode> {
            let p = a
                .get(1)
                .ok_or_else(|| err("usage: goat inspect <container>"))?;
            let text = container::inspect(&fs::read(p)?)?;
            print!("{text}");
            Ok(ExitCode::SUCCESS)
        })(),
        Some("pwn") => rpwn(),
        Some("--help") | None => {
            println!("goat-rs: Rust-native Goat\n  usbr34ker list|walkthrough|flash\n  inspect <file>  inspect a Goat container\n  verify <file>   verify certificate and container signatures\n  unseal <file> --key-hex HEX\n  pwn   run Rust RPWN");
            Ok(ExitCode::SUCCESS)
        }
        _ => Err(err("unknown command; use --help")),
    };
    match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("goat-rs: {e}");
            ExitCode::FAILURE
        }
    }
}
