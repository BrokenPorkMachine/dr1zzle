//! Port of `utilities.py` plus a few small helpers the Python code got for free from
//! `struct`, `binascii` and friends.

use aes::cipher::{BlockDecrypt, KeyInit};
use sha2::Digest;

/// Prints `message` and exits with status 1, mirroring the original's
/// `print ... ; sys.exit(1)` idiom.
pub fn die(message: impl AsRef<str>) -> ! {
    println!("{}", message.as_ref());
    std::process::exit(1);
}

/// `binascii.hexlify`, lower case, no separator.
pub fn hex_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 2);
    for byte in data {
        out.push_str(&format!("{:02x}", byte));
    }
    out
}

/// `binascii.unhexlify`.
pub fn hex_decode(text: &str) -> Result<Vec<u8>, String> {
    if !text.len().is_multiple_of(2) {
        return Err(format!(
            "Odd-length string: cannot decode '{}' as hex",
            text
        ));
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks(2) {
        let hi = (pair[0] as char).to_digit(16);
        let lo = (pair[1] as char).to_digit(16);
        match (hi, lo) {
            (Some(hi), Some(lo)) => out.push(((hi << 4) | lo) as u8),
            _ => return Err(format!("Non-hexadecimal digit found: '{}'", text)),
        }
    }
    Ok(out)
}

/// `utilities.apply_patches`: splice `data` over `binary` at `offset`.
pub fn apply_patches(binary: &[u8], patches: &[(u32, Vec<u8>)]) -> Vec<u8> {
    let mut out = binary.to_vec();
    for (offset, data) in patches {
        let start = *offset as usize;
        out.splice(start..start + data.len(), data.iter().copied());
    }
    out
}

/// `utilities.aes_decrypt`, which shelled out to `openssl enc -aes-<n>-cbc -d -nopad`.
/// The IV is the raw 16 byte value and the key is 16 (AES-128) or 32 (AES-256) bytes.
/// Padding is neither applied nor checked, matching `-nopad`.
pub fn aes_decrypt(data: &[u8], iv: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
    if !data.len().is_multiple_of(16) {
        return Err("AES input length must be a multiple of the 16-byte block size".into());
    }
    if iv.len() != 16 {
        return Err(format!("AES IV must be 16 bytes, got {}", iv.len()));
    }
    if key.len() != 16 && key.len() != 32 {
        return Err(format!("Bad AES key length: {} bytes", key.len()));
    }

    let mut out = Vec::with_capacity(data.len());
    let mut chain: [u8; 16] = iv.try_into().unwrap();
    let mut block = [0u8; 16];

    for chunk in data.chunks(16) {
        block.copy_from_slice(chunk);
        let ciphertext = block;
        match key.len() {
            16 => aes::Aes128::new_from_slice(key)
                .map_err(|e| e.to_string())?
                .decrypt_block((&mut block).into()),
            _ => aes::Aes256::new_from_slice(key)
                .map_err(|e| e.to_string())?
                .decrypt_block((&mut block).into()),
        }
        for (j, byte) in block.iter_mut().enumerate() {
            *byte ^= chain[j];
            chain[j] = ciphertext[j];
        }
        out.extend_from_slice(&block);
    }
    Ok(out)
}

/// `utilities.hex_dump`, which shelled out to `xxd -o <address>`.
///
/// Reproduces xxd's canonical layout exactly: an 8 digit offset, a 39 column hex field
/// right padded with spaces, two spaces, then the printable-ASCII gutter where bytes
/// outside `0x20..=0x7e` render as `.`. Callers slice off the first 10 characters to strip
/// the offset column, so that prefix has to match byte for byte.
pub fn hex_dump(data: &[u8], address: u64) -> String {
    const HEX_FIELD_WIDTH: usize = 39;
    let mut out = String::new();
    for (line, chunk) in data.chunks(16).enumerate() {
        out.push_str(&format!("{:08x}: ", address + (line as u64) * 16));
        let mut hex = String::with_capacity(HEX_FIELD_WIDTH);
        for (i, pair) in chunk.chunks(2).enumerate() {
            if i > 0 {
                hex.push(' ');
            }
            for byte in pair {
                hex.push_str(&format!("{:02x}", byte));
            }
        }
        for _ in hex.len()..HEX_FIELD_WIDTH {
            hex.push(' ');
        }
        out.push_str(&hex);
        out.push_str("  ");
        for byte in chunk {
            out.push(if (0x20..=0x7e).contains(byte) {
                *byte as char
            } else {
                '.'
            });
        }
        out.push('\n');
    }
    out
}

pub fn sha1_hex(data: &[u8]) -> String {
    hex_encode(&sha1::Sha1::digest(data))
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex_encode(&sha2::Sha256::digest(data))
}

/// Python's `raw_input("Press ENTER to continue.")` / `input()`.
pub fn prompt(message: &str) {
    use std::io::Write;
    print!("{}", message);
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
}

/// Reads a file, reporting the Python original's `IOError` message on failure.
pub fn read_file(path: &str) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("{}: {}", path, e))
}

pub fn write_file(path: &str, data: &[u8]) -> Result<(), String> {
    if let Some(parent) = std::path::Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            let _ = std::fs::create_dir_all(parent);
        }
    }
    std::fs::write(path, data).map_err(|e| format!("{}: {}", path, e))
}

/// Timestamp used for NOR backup filenames: `datetime.now().strftime('%Y%m%d-%H%M%S')`.
pub fn timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    // Civil-from-days conversion (Howard Hinnant's algorithm).
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{:04}{:02}{:02}-{:02}{:02}{:02}",
        y,
        m,
        d,
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Python slice semantics: out-of-range bounds clamp instead of panicking.
pub fn slice(data: &[u8], start: usize, end: usize) -> Vec<u8> {
    if start >= data.len() || end <= start {
        return Vec::new();
    }
    let end = end.min(data.len());
    data[start..end].to_vec()
}

/// Reads a little-endian `u32` from `data` at `offset`, panicking like `struct.unpack`
/// would if the buffer is too short.
pub fn u32_le(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
}

pub fn u64_le(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap())
}
