// Assemble the payload at `payload/checkm8_payload.S` and emit it next to the
// crate's output so `payload.rs` can `include_bytes!` it.
//
// The symbol table is emitted as text (`name value` per line) because
// `payload.rs` needs `stage2`'s offset inside the code section to lay out the
// context struct the exploit's pivot consumes. Reading the object file here
// rather than at run time keeps the build to one dependency: the clang that
// already builds the payload image.
//
// If clang is missing the build fails loudly rather than producing a crate
// without a payload: an empty payload is a working build with no exploit in
// it, which is exactly the kind of quiet failure this project avoids.

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

const PAYLOAD_SRC: &str = "payload/checkm8_payload.S";

fn main() {
    println!("cargo:rerun-if-changed={PAYLOAD_SRC}");

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let obj = out_dir.join("payload.o");
    let bin = out_dir.join("payload.bin");
    let sym = out_dir.join("payload.sym");

    let clang = env::var("PAYLOAD_CC").unwrap_or_else(|_| "clang".to_string());
    let status = Command::new(&clang)
        .args(["--target=aarch64-none-elf", "-c", "-o"])
        .arg(&obj)
        .arg(PAYLOAD_SRC)
        .status()
        .unwrap_or_else(|e| {
            panic!("could not run {clang} to assemble the payload: {e}");
        });
    assert!(status.success(), "{clang} failed to assemble {PAYLOAD_SRC}");

    // Extract the section with the toolchain's own objcopy when it is
    // available; fall back to reading the ELF directly, which is what this
    // build does on a machine with clang but no llvm tools.
    let copied = Command::new("objcopy")
        .args(["-O", "binary", "--only-section=.payload"])
        .arg(&obj)
        .arg(&bin)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !copied {
        let elf = fs::read(&obj).expect("read the assembled payload object");
        let (bytes, symbols) = parse_elf(&elf);
        fs::write(&bin, bytes).expect("write the payload bytes");
        let text: String = symbols
            .iter()
            .map(|(name, value)| format!("{name} 0x{value:x}\n"))
            .collect();
        fs::write(&sym, text).expect("write the payload symbols");
    } else {
        let elf = fs::read(&obj).expect("read the assembled payload object");
        let (_bytes, symbols) = parse_elf(&elf);
        let text: String = symbols
            .iter()
            .map(|(name, value)| format!("{name} 0x{value:x}\n"))
            .collect();
        fs::write(&sym, text).expect("write the payload symbols");
    }
}

/// (section bytes, symbols) from an ELF64 little-endian object.
///
/// A deliberately small reader: section headers plus a symbol table, nothing
/// else. Anything it does not understand is a build failure, not a silently
/// short payload.
fn parse_elf(blob: &[u8]) -> (Vec<u8>, Vec<(String, u64)>) {
    assert!(
        blob.len() > 0x40 && &blob[..4] == b"\x7fELF",
        "not an ELF object"
    );
    assert_eq!(blob[4], 2, "not ELF64");
    assert_eq!(blob[5], 1, "not little-endian");

    let u16_at = |off: usize| u16::from_le_bytes([blob[off], blob[off + 1]]);
    let u64_at = |off: usize| u64::from_le_bytes(blob[off..off + 8].try_into().expect("8 bytes"));
    let u32_at = |off: usize| u32::from_le_bytes(blob[off..off + 4].try_into().expect("4 bytes"));

    let e_shoff = u64_at(0x28) as usize;
    let e_shentsize = u16_at(0x3A) as usize;
    let e_shnum = u16_at(0x3C) as usize;
    let e_shstrndx = u16_at(0x3E) as usize;

    let mut raw = Vec::with_capacity(e_shnum);
    for i in 0..e_shnum {
        let base = e_shoff + i * e_shentsize;
        raw.push((
            u32_at(base) as usize,
            u32_at(base + 4),
            u64_at(base + 0x18) as usize,
            u64_at(base + 0x20) as usize,
        ));
    }
    let shstr_off = raw[e_shstrndx].2;
    let name_at = |entry: &(usize, _, _, _)| -> String {
        let start = shstr_off + entry.0;
        let end = blob[start..].iter().position(|&b| b == 0).expect("NUL") + start;
        String::from_utf8_lossy(&blob[start..end]).into_owned()
    };

    let mut payload = None;
    let mut symtab = None;
    for entry in &raw {
        let name = name_at(entry);
        if name == ".payload" {
            payload = Some(*entry);
        } else if name == ".symtab" {
            symtab = Some(*entry);
        }
    }
    let payload = payload.expect("the payload object has no .payload section");
    let bytes = blob[payload.2..payload.2 + payload.3].to_vec();

    let mut symbols = Vec::new();
    if let Some((_name, _ty, off, size)) = symtab {
        // The strtab is the section after the symtab in this object layout.
        let strtab = raw
            .iter()
            .find(|e| name_at(e) == ".strtab")
            .copied()
            .expect("the payload object has no .strtab");
        let strtab_bytes = &blob[strtab.2..strtab.2 + strtab.3];
        for k in (0..size).step_by(24) {
            let at = off + k;
            let st_name = u32_at(at) as usize;
            let st_shndx = u16_at(at + 6);
            let st_value = u64_at(at + 8);
            if st_shndx == 0 || st_name == 0 {
                continue;
            }
            let end = strtab_bytes[st_name..]
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(0)
                + st_name;
            let name = String::from_utf8_lossy(&strtab_bytes[st_name..end]).into_owned();
            if !name.is_empty() {
                symbols.push((name, st_value));
            }
        }
    }
    (bytes, symbols)
}
