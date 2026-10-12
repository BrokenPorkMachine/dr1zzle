//! Verification tests for the parts of the port that can be checked without a device.
//!
//! The high-risk logic is byte-exact payload construction, so these tests pin the
//! behaviour against independent references where possible: `xxd` for the hex dump,
//! `openssl` for AES, and the placeholder/size invariants that the original Python
//! asserted with bare `assert` statements.

use crate::alloc8;
use crate::checkm8;
use crate::cli;
use crate::device_platform::ALL_PLATFORMS;
use crate::image3::{Image3, Tag};
use crate::nor::NorData;
use crate::shellcode::{self, Arch};
use crate::usbexec::{ExecConfig, CONFIGS as USBEXEC_CONFIGS};
use crate::utilities::{
    aes_decrypt, apply_patches, hex_decode, hex_dump, hex_encode, slice, timestamp,
};
use std::process::Command;

// ---------------------------------------------------------------------------
// utilities: hex dump must match `xxd -o <addr>` byte for byte
// ---------------------------------------------------------------------------

fn xxd(data: &[u8], address: u64) -> String {
    use std::io::Write;
    use std::process::Stdio;

    let mut child = Command::new("xxd")
        .arg("-o")
        .arg(address.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("xxd should be available");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(data)
        .expect("write to xxd");
    let output = child.wait_with_output().expect("xxd output");
    String::from_utf8(output.stdout).expect("xxd emits ASCII")
}

#[test]
fn hex_dump_matches_xxd() {
    let cases: Vec<(Vec<u8>, u64)> = vec![
        (vec![], 0),
        (b"A".to_vec(), 0),
        (b"ABCDEFGHIJKLMNOPQ".to_vec(), 0),
        (b"ABCDEFGHIJKLMNOP".to_vec(), 0),
        ((0u8..=255).collect(), 0),
        (
            b"CPID:8015 CPRV:11 EPID:05FA SRTG:[iBoot-3332.0.0.1.23]".to_vec(),
            0x1C8B4F00,
        ),
        ((0..=47).map(|i| (i * 7) as u8).collect(), 0xdeadbeef),
        (vec![0xff; 200], 0x1000),
    ];

    for (data, address) in cases {
        assert_eq!(
            hex_dump(&data, address),
            xxd(&data, address),
            "hex_dump mismatch for {} bytes at 0x{:x}",
            data.len(),
            address
        );
    }
}

// ---------------------------------------------------------------------------
// utilities: AES must match `openssl enc -aes-<n>-cbc -d -nopad`
// ---------------------------------------------------------------------------

#[test]
fn aes_decrypt_matches_openssl() {
    // A 48 byte firmware keybag splits into a 16 byte IV and a 32 byte AES-256 key,
    // which is exactly what `Image3.getDecryptedPayload` feeds to the cipher.
    let keybag: Vec<u8> = (0u8..48)
        .map(|i| i.wrapping_mul(7).wrapping_add(3))
        .collect();
    let iv = &keybag[..16];
    let key256 = &keybag[16..];

    let plaintext: Vec<u8> = (0..160u32).map(|i| (i * 31) as u8).collect();
    let ciphertext = openssl_encrypt(&plaintext, iv, key256);

    assert_eq!(
        aes_decrypt(&ciphertext, iv, key256).expect("AES-256"),
        plaintext
    );

    // The 16 byte key path selects AES-128, matching the branch in the original.
    let key128 = &keybag[..16];
    let ciphertext128 = openssl_encrypt(&plaintext, iv, key128);
    assert_eq!(
        aes_decrypt(&ciphertext128, iv, key128).expect("AES-128"),
        plaintext
    );
}

fn openssl_encrypt(data: &[u8], iv: &[u8], key: &[u8]) -> Vec<u8> {
    use std::io::Write;
    use std::process::Stdio;

    let bits = key.len() * 8;
    let mut child = Command::new("openssl")
        .args([
            "enc",
            &format!("-aes-{}-cbc", bits),
            "-e",
            "-nopad",
            "-iv",
            &hex_encode(iv),
            "-K",
            &hex_encode(key),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("openssl should be available");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(data)
        .expect("write to openssl");
    let output = child.wait_with_output().expect("openssl output");
    assert!(output.status.success(), "openssl failed: {:?}", output);
    output.stdout
}

#[test]
fn aes_decrypt_rejects_bad_inputs() {
    assert!(aes_decrypt(&[0u8; 5], &[0u8; 16], &[0u8; 32]).is_err());
    assert!(aes_decrypt(&[0u8; 16], &[0u8; 16], &[0u8; 20]).is_err());
}

// ---------------------------------------------------------------------------
// utilities: hex, patching, timestamps
// ---------------------------------------------------------------------------

#[test]
fn hex_round_trips() {
    let data: Vec<u8> = (0..=255u8).collect();
    let encoded = hex_encode(&data);
    assert_eq!(encoded.len(), 512);
    assert_eq!(hex_decode(&encoded).expect("decode"), data);

    assert!(hex_decode("abc").is_err(), "odd length must fail");
    assert!(hex_decode("zz").is_err(), "non-hex must fail");
}

#[test]
fn apply_patches_splices_in_place() {
    let binary = b"AAAABBBBCCCC".to_vec();
    let patched = apply_patches(&binary, &[(4, b"X".to_vec()), (8, b"YY".to_vec())]);
    assert_eq!(patched, b"AAAAXBBBYYCC".to_vec());
}

#[test]
fn timestamp_is_yyyymmdd_hhmmss() {
    let stamp = timestamp();
    assert_eq!(stamp.len(), 15, "got {}", stamp);
    assert_eq!(&stamp[8..9], "-");
    assert!(stamp[..8].chars().all(|c| c.is_ascii_digit()));
    assert!(stamp[9..].chars().all(|c| c.is_ascii_digit()));
}

#[test]
fn slice_clamps_like_python() {
    let data: Vec<u8> = (0..10u8).collect();
    assert_eq!(slice(&data, 2, 5), vec![2, 3, 4]);
    assert_eq!(slice(&data, 8, 100), vec![8, 9]);
    assert_eq!(slice(&data, 50, 100), Vec::<u8>::new());
    assert_eq!(slice(&data, 5, 5), Vec::<u8>::new());
}

// ---------------------------------------------------------------------------
// CLI: getopt compatibility
// ---------------------------------------------------------------------------

fn args(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

#[test]
fn getopt_short_options() {
    assert_eq!(
        cli::getopt(&args(&["-p"])).unwrap(),
        vec![("-p".to_string(), String::new())]
    );
    assert_eq!(
        cli::getopt(&args(&["-f", "image.dfu"])).unwrap(),
        vec![("-f".to_string(), "image.dfu".to_string())]
    );
    // Attached argument, as getopt also accepts.
    assert_eq!(
        cli::getopt(&args(&["-fimage.dfu"])).unwrap(),
        vec![("-f".to_string(), "image.dfu".to_string())]
    );
    // The remainder of the token is the argument, not more flags. Regression test: the
    // 'i' in "image.dfu" must not be re-parsed as a short option.
    assert_eq!(cli::getopt(&args(&["-fimage.dfu"])).unwrap().len(), 1);
    // Clustered flags.
    assert_eq!(
        cli::getopt(&args(&["-px"])).unwrap(),
        vec![
            ("-p".to_string(), String::new()),
            ("-x".to_string(), String::new())
        ]
    );
}

#[test]
fn getopt_long_options() {
    assert_eq!(
        cli::getopt(&args(&["--dump-rom"])).unwrap(),
        vec![("--dump-rom".to_string(), String::new())]
    );
    assert_eq!(
        cli::getopt(&args(&["--dump=0x100,0x20"])).unwrap(),
        vec![("--dump".to_string(), "0x100,0x20".to_string())]
    );
    // Argument supplied as the following element.
    assert_eq!(
        cli::getopt(&args(&["--dump-nor", "out.dump"])).unwrap(),
        vec![("--dump-nor".to_string(), "out.dump".to_string())]
    );
    // A single dash routes to the short-option parser, so "-demote" is rejected -
    // long options need the double dash.
    assert!(cli::getopt(&args(&["-demote"])).is_err());
    // Numeric-looking option names still parse as names, not as a short cluster.
    assert_eq!(
        cli::getopt(&args(&["--24kpwn"])).unwrap(),
        vec![("--24kpwn".to_string(), String::new())]
    );
}

#[test]
fn getopt_rejects_bad_usage() {
    assert!(cli::getopt(&args(&["--bogus"])).is_err());
    assert!(cli::getopt(&args(&["--dump"])).is_err(), "missing argument");
    assert!(
        cli::getopt(&args(&["--dump-rom=1"])).is_err(),
        "flag must not take an argument"
    );
    assert!(cli::getopt(&args(&["-z"])).is_err());
    assert!(cli::getopt(&args(&["-f"])).is_err());
}

#[test]
fn getopt_stops_at_first_operand() {
    assert_eq!(
        cli::getopt(&args(&["-p", "leftover", "-x"])).unwrap(),
        vec![("-p".to_string(), String::new())]
    );
    assert!(cli::getopt(&args(&["leftover"])).unwrap().is_empty());
}

#[test]
fn getopt_double_dash_terminator() {
    assert!(cli::getopt(&args(&["--", "-p"])).unwrap().is_empty());
}

// ---------------------------------------------------------------------------
// Shellcode: placeholder substitution
// ---------------------------------------------------------------------------

#[test]
fn prepare_shellcode_rejects_mismatched_placeholders() {
    // Every shipped blob must use the 0xBAD0000N convention.
    let bogus = vec![0u8; 64];
    let result = std::panic::catch_unwind(|| {
        shellcode::prepare_shellcode(&bogus, Arch::Armv7, &[0x1000, 0x2000])
    });
    assert!(result.is_err(), "bogus placeholders must be rejected");
}

#[test]
fn prepare_shellcode_substitutes_in_order() {
    let mut blob = vec![0xAAu8; 16];
    blob.extend_from_slice(&0xBAD0_0001u32.to_le_bytes());
    blob.extend_from_slice(&0xBAD0_0002u32.to_le_bytes());
    let out = shellcode::prepare_shellcode(&blob, Arch::Armv7, &[0x1111_1111, 0x2222_2222]);
    assert_eq!(out.len(), 16 + 8);
    assert_eq!(&out[..16], &[0xAAu8; 16]);
    assert_eq!(hex_encode(&out[16..]), "1111111122222222");
}

// ---------------------------------------------------------------------------
// checkm8: every supported CPID must produce a well formed payload
// ---------------------------------------------------------------------------

const SUPPORTED_CPIDS: &[u32] = &[
    0x8947, 0x8950, 0x8955, 0x8960, 0x8002, 0x8004, 0x8010, 0x8011, 0x8015,
];

#[test]
fn every_checkm8_payload_builds() {
    for cpid in SUPPORTED_CPIDS {
        let payload = checkm8::payload(*cpid);
        assert!(!payload.is_empty(), "CPID 0x{:x}: empty payload", cpid);
        // Whatever the size, it must be delivered in whole 0x800 byte DNLOADs.
        let remainder = payload.chunks(0x800).last().unwrap().len();
        assert!(remainder <= 0x800);
    }
}

#[test]
fn checkm8_armv7_payloads_fit_the_documented_layout() {
    for cpid in [0x8947u32, 0x8950, 0x8955, 0x8002, 0x8004] {
        let payload = checkm8::payload(cpid);
        // The layout is a fixed offset followed by the handler, so the length is bounded
        // rather than exact.
        assert!(
            payload.len() >= checkm8::PAYLOAD_OFFSET_ARMV7 as usize
                && payload.len() as u64
                    <= checkm8::PAYLOAD_OFFSET_ARMV7 + checkm8::PAYLOAD_SIZE_ARMV7,
            "CPID 0x{:x}: armv7 payload is {} bytes",
            cpid,
            payload.len()
        );
    }
}

#[test]
fn checkm8_arm64_payloads_fit_the_documented_layout() {
    for cpid in ARM64_CPIDS {
        let payload = checkm8::payload(*cpid);
        assert!(
            payload.len() >= checkm8::PAYLOAD_OFFSET_ARM64 as usize
                && payload.len() as u64
                    <= checkm8::PAYLOAD_OFFSET_ARM64 + checkm8::PAYLOAD_SIZE_ARM64,
            "CPID 0x{:x}: arm64 payload is {} bytes",
            cpid,
            payload.len()
        );
    }
}

/// S5L8960 is the only CPID that uses a plain arm64 handler with no ROP stage.
const ARM64_CPIDS: &[u32] = &[0x8960];

#[test]
fn checkm8_t801x_payloads_carry_rop_callbacks() {
    // T8010/T8011 emit the WXN-disable payload plus a ROP callback list; the payload is
    // 1024 + 8 + 504 + 16 + 496 + 32 bytes of header before the callbacks.
    // 1024 payload + Q + 504 pad + 2Q + 496 + 32 pad, followed by the ROP callback list.
    // T8010 has 10 callbacks (2 full rows) whereas T8011 has 9, and the trailing
    // padding row emits no callback entries, so T8011 is one 16 byte entry shorter.
    assert_eq!(checkm8::payload(0x8010).len(), 2080 + 320);
    assert_eq!(checkm8::payload(0x8011).len(), 2080 + 304);
    // T8015 uses its own layout: 6Q + 16 pad + 448 + 1536 + 1024.
    let payload = checkm8::payload(0x8015);
    assert_eq!(payload.len(), 6 * 8 + 16 + 448 + 1536 + 1024);
}

#[test]
fn asm_helpers_match_the_original_encodings() {
    // B .+0x40 from 0x180018000
    assert_eq!(
        hex_encode(&shellcode::asm_arm64_branch(0x1800_18000, 0x1800_18040)),
        "10000014"
    );
    // LDR X7, [PC, #8]; BR X7; <literal>
    let trampoline = shellcode::asm_arm64_x7_trampoline(0x1000_0CFB4);
    assert_eq!(trampoline.len(), 16);
    assert_eq!(hex_encode(&trampoline), "47000058e0001fd6b4cf000001000000");
    // Thumb LDR.W PC, [PC]
    assert_eq!(
        hex_encode(&shellcode::asm_thumb_trampoline(0x3403_9801, 0x7BC9)),
        "dff800f0c97b0000"
    );
    assert_eq!(
        hex_encode(&shellcode::asm_thumb_trampoline(0x3403_9803, 0x7BC9)),
        "dff802f0c97b0000"
    );
}

// ---------------------------------------------------------------------------
// alloc8 / NOR
// ---------------------------------------------------------------------------

#[test]
fn empty_img3_layout() {
    let img3 = alloc8::empty_img3(1024);
    assert_eq!(img3.len(), 1024);
    assert_eq!(&img3[..4], b"3gmI");
    assert_eq!(hex_encode(&img3[4..20]), "0004000000000000000000006f72657a");
    assert!(img3[20..].iter().all(|&b| b == 0));
}

/// Builds a synthetic but structurally valid 1 MiB NOR image.
fn synthetic_nor(block_size: u32, firmware_block: u32, firmware_block_count: u32) -> Vec<u8> {
    let firmware_offset = block_size as usize * firmware_block as usize;
    let firmware_length = block_size as usize * firmware_block_count as usize;
    let mut dump = vec![0u8; crate::nor::NOR_SIZE];

    // IMG2 header: magic, block size, unused, firmware block, block count.
    dump[..4].copy_from_slice(b"2GMI");
    dump[4..8].copy_from_slice(&block_size.to_le_bytes());
    dump[8..12].copy_from_slice(&0u32.to_le_bytes());
    dump[12..16].copy_from_slice(&firmware_block.to_le_bytes());
    dump[16..20].copy_from_slice(&firmware_block_count.to_le_bytes());
    let header_crc = crc32(&dump[..48]);
    dump[48..52].copy_from_slice(&header_crc.to_le_bytes());

    // Partition table area must stay zero, then fill the firmware region with 0xff.
    for byte in dump[firmware_offset..firmware_offset + firmware_length].iter_mut() {
        *byte = 0xff;
    }
    dump
}

fn crc32(data: &[u8]) -> u32 {
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(data);
    hasher.finalize()
}

#[test]
fn nor_round_trips_and_finds_images() {
    let mut dump = synthetic_nor(0x400, 0x100, 0x300);

    // Chain two IMG3 images at the start of the firmware region.
    let firmware_offset = 0x400 * 0x100;
    let mut base = firmware_offset;
    for (index, size) in [0x800usize, 0x400].iter().enumerate() {
        let mut image = alloc8::empty_img3(*size);
        // Give each a distinguishable payload tag.
        image[20] = index as u8 + 1;
        dump[base..base + size].copy_from_slice(&image);
        base += size;
    }

    let nor = NorData::new(&dump);
    assert_eq!(nor.block_size, 0x400);
    assert_eq!(nor.firmware_offset, firmware_offset);
    assert_eq!(nor.firmware_length, 0xC0000);
    assert_eq!(nor.images.len(), 2);
    assert_eq!(nor.images[0][20], 1);
    assert_eq!(nor.images[1][20], 2);
    assert!(nor.alloc8_area_is_empty());
    assert_eq!(nor.dump(), dump, "round trip must be lossless");
}

#[test]
fn alloc8_installs_then_removes_cleanly() {
    // Use a small block size so the synthetic NOR stays cheap to build.
    let block_size = 0x100u32;
    let firmware_length = block_size as usize * 0xC00;
    let mut dump = synthetic_nor(block_size, 0x100, 0xC00);

    // Seed one 24Kpwn-sized LLB so alloc8 has a base image to work from.
    let firmware_offset = block_size as usize * 0x100;
    let mut llb = alloc8::empty_img3(0x24000);
    llb[16..20].copy_from_slice(b"blli"); // 'illb'
    dump[firmware_offset..firmware_offset + 0x24000].copy_from_slice(&llb);

    let nor = NorData::new(&dump);
    assert_eq!(nor.images.len(), 1);
    assert!(firmware_length > 0x24000);

    let installed = alloc8::exploit(&nor, "359.3");

    // The shellcode block is written into the area right after the IMG2 header.
    assert_eq!(installed.parts[1].len(), 460);
    assert_eq!(&installed.parts[1][..4], &shellcode::ALLOC8[..4]);
    assert!(!installed.alloc8_area_is_empty());
    assert!(
        installed.images.len() > 700,
        "alloc8 feng shui expects 700+ images"
    );

    // The rebuilt image must still be exactly 1 MiB with the firmware region padded.
    let rebuilt = installed.dump();
    assert_eq!(rebuilt.len(), crate::nor::NOR_SIZE);
    assert!(rebuilt[firmware_offset..].starts_with(b"3gmI"));

    // Removing it again restores an image list with only the LLB.
    let removed = alloc8::remove_exploit(&installed);
    assert_eq!(removed.images.len(), 1);
    assert!(removed.alloc8_area_is_empty());
    assert_eq!(
        removed.dump(),
        dump,
        "removal must restore the original NOR"
    );
}

// ---------------------------------------------------------------------------
// IMAGE3
// ---------------------------------------------------------------------------

#[test]
fn image3_round_trips_through_from_tags() {
    let tags = vec![
        Tag::new(b"EPYT", 16, 4, vec![1, 2, 3, 4]),
        Tag::new(b"ATAD", 28, 16, vec![0xAA; 16]),
        Tag::new(b"HSHS", 20, 8, vec![0xBB; 8]),
        Tag::new(b"TREC", 20, 8, vec![0xCC; 8]),
    ];
    let encoded = Image3::from_tags(b"blli", &tags);
    assert_eq!(encoded.len() % 64, 0, "total size must be 64-byte aligned");
    assert_eq!(&encoded[..4], b"3gmI");
    assert_eq!(&encoded[16..20], b"blli");

    let decoded = Image3::new(&encoded);
    assert_eq!(decoded.kind, *b"blli");
    assert_eq!(decoded.tags.len(), 4);
    assert_eq!(decoded.get_payload().expect("DATA tag"), &vec![0xAAu8; 16]);
    assert_eq!(decoded.get_tags(b"EPYT").len(), 1);
    assert_eq!(decoded.get_tags(b"HSHS")[0].data, vec![0xBBu8; 8]);
}

#[test]
fn image3_signed_size_excludes_shsh_and_cert() {
    let tags = vec![
        Tag::new(b"EPYT", 16, 4, vec![1, 2, 3, 4]), // 16
        Tag::new(b"ATAD", 28, 16, vec![0xAA; 16]),  // 28
        Tag::new(b"HSHS", 20, 8, vec![0xBB; 8]),    // excluded
        Tag::new(b"TREC", 20, 8, vec![0xCC; 8]),    // excluded
    ];
    let encoded = Image3::from_tags(b"blli", &tags);
    let decoded = Image3::new(&encoded);
    assert_eq!(decoded.data_size as usize, 16 + 28 + 20 + 20);
    assert_eq!(decoded.signed_size as usize, 16 + 28);
}

#[test]
fn image3_shrinks_an_oversized_certificate() {
    let mut cert = vec![0u8; 3072];
    cert[..4].copy_from_slice(b"DEAD");
    let tags = vec![
        Tag::new(b"EPYT", 16, 4, vec![1, 2, 3, 4]),
        Tag::new(b"ATAD", 28, 16, vec![0xAA; 16]),
        Tag::new(b"TREC", (12 + cert.len()) as u32, cert.len() as u32, cert),
    ];
    let encoded = Image3::from_tags(b"blli", &tags);

    let mut decoded = Image3::new(&encoded);
    decoded.shrink_24kpwn_certificate();

    let cert_tag = decoded.get_tags(b"TREC")[0];
    assert_eq!(cert_tag.data.len(), 4, "trailing NULs should be trimmed");
    assert_eq!(hex_encode(&cert_tag.data), "44454144");
    assert_eq!(cert_tag.total_size as usize, 12 + 4);
    assert_eq!(cert_tag.data_size as usize, 4);
}

// ---------------------------------------------------------------------------
// Device platform / exec config tables
// ---------------------------------------------------------------------------

#[test]
fn all_nine_platforms_are_registered() {
    assert_eq!(ALL_PLATFORMS.len(), 9);
}

#[test]
fn platform_names_follow_the_original_rules() {
    for platform in ALL_PLATFORMS.iter() {
        let name = platform.name();
        if (0x8720..=0x8960).contains(&platform.cpid) {
            assert!(
                name.starts_with("s5l"),
                "CPID 0x{:x} -> {}",
                platform.cpid,
                name
            );
        } else {
            assert!(
                name.starts_with("t"),
                "CPID 0x{:x} -> {}",
                platform.cpid,
                name
            );
        }
        assert!(
            name.ends_with("xsi"),
            "CPID 0x{:x} -> {}",
            platform.cpid,
            name
        );
    }
}

#[test]
fn exec_config_match_is_exact() {
    let config: &ExecConfig = &USBEXEC_CONFIGS[0];
    let mut built = Vec::new();
    for (index, field) in config.info.iter().enumerate() {
        let width = if index == 2 { 0x80 } else { 0x40 };
        let mut bytes = field.as_bytes().to_vec();
        bytes.resize(width, 0);
        built.extend_from_slice(&bytes);
    }
    assert!(config.matches(&built));
    assert!(!config.matches(&built[..0x100 - 1]));
}

#[test]
fn every_exec_config_has_a_distinct_aes_command() {
    let mut seen = std::collections::HashSet::new();
    for config in USBEXEC_CONFIGS {
        assert!(seen.insert(config.aes_crypto_cmd), "duplicate AES command");
    }
    assert_eq!(seen.len(), 9);
}
// ---------------------------------------------------------------------------
// checkm8: overwrite buffers are sent as the wLength of a control transfer, so their
// exact sizes are part of the protocol.
// ---------------------------------------------------------------------------

#[test]
fn checkm8_overwrite_buffers_have_the_documented_sizes() {
    // struct.pack('<20xI4x', base) is 28 bytes; the 32-bit and 64-bit variants are
    // 48, 116 and 128 bytes respectively.
    let expected: &[(u32, usize)] = &[
        (0x8947, 0x660 + 28),
        (0x8950, 0x640 + 28),
        (0x8955, 0x640 + 28),
        (0x8960, 0x580 + 48),
        (0x8002, 0x5C0 + 28),
        (0x8004, 0x5C0 + 28),
        (0x8010, 0x580 + 116),
        (0x8011, 0x500 + 116),
        (0x8015, 0x500 + 128),
    ];

    for (cpid, size) in expected {
        let config = checkm8::all_exploit_configs()
            .into_iter()
            .find(|c| c.cpid == *cpid)
            .unwrap_or_else(|| panic!("no config for CPID 0x{:x}", cpid));
        assert_eq!(
            config.overwrite.len(),
            *size,
            "CPID 0x{:x}: overwrite is {} bytes, expected {}",
            cpid,
            config.overwrite.len(),
            size
        );
    }
}

#[test]
fn checkm8_configs_pair_large_leak_with_hole_strategies() {
    let configs = checkm8::all_exploit_configs();
    for config in &configs {
        // Exactly one of the two grooming strategies is used per device.
        assert!(
            config.large_leak.is_some() != config.hole.is_some(),
            "CPID 0x{:x}: inconsistent leak strategy",
            config.cpid
        );
        if config.large_leak.is_some() {
            assert!(config.leak.is_none());
        } else {
            assert!(config.leak.is_some());
        }
    }
}

// ---------------------------------------------------------------------------
// 24Kpwn: the forged IMG3 must land on the exact size the loader expects.
// ---------------------------------------------------------------------------

#[test]
fn twentyfour_kpwn_forges_an_exactly_sized_img3() {
    use crate::image3_24kpwn;
    // A minimal signed LLB: TYPE, DATA, then an SHSH tag just past the signed region.
    let data_len = 0x100usize;
    let shsh_total = 20usize;
    let signed_size = 16 + 12 + data_len;
    let total_size = 20 + signed_size + shsh_total;
    let data_size = 16 + 12 + data_len + shsh_total;

    let mut llb = Vec::new();
    llb.extend_from_slice(b"3gmI");
    for value in [total_size as u32, data_size as u32, signed_size as u32] {
        llb.extend_from_slice(&value.to_le_bytes());
    }
    llb.extend_from_slice(b"blli");
    // TYPE tag
    llb.extend_from_slice(b"EPYT");
    llb.extend_from_slice(&16u32.to_le_bytes());
    llb.extend_from_slice(&4u32.to_le_bytes());
    llb.extend_from_slice(&[1, 0, 0, 0]);
    // DATA tag
    llb.extend_from_slice(b"ATAD");
    llb.extend_from_slice(&((12 + data_len) as u32).to_le_bytes());
    llb.extend_from_slice(&(data_len as u32).to_le_bytes());
    llb.extend_from_slice(&vec![0xCCu8; data_len]);
    // SHSH tag (20 bytes), which must sit immediately after the signed region.
    llb.extend_from_slice(b"HSHS");
    llb.extend_from_slice(&20u32.to_le_bytes());
    llb.extend_from_slice(&8u32.to_le_bytes());
    llb.extend_from_slice(&[0u8; 8]);
    assert_eq!(llb.len(), total_size);

    let securerom = vec![0x5Au8; 0xB000 + 460];
    let forged = image3_24kpwn::exploit(&llb, &securerom);

    assert_eq!(forged.len(), 0x24200);
    assert_eq!(&forged[..4], b"3gmI");
    assert_eq!(&forged[16..20], b"blli");
    // The declared sizes are the fixed forged header, not the originals.
    assert_eq!(
        u32::from_le_bytes(forged[4..8].try_into().unwrap()),
        0x24200
    );
    assert_eq!(
        u32::from_le_bytes(forged[8..12].try_into().unwrap()),
        0x241BC
    );
    assert_eq!(
        u32::from_le_bytes(forged[12..16].try_into().unwrap()),
        0x23F88
    );

    // The shellcode is carried verbatim inside the forged 24KP tag, after a run of
    // padding whose length is implied by the tag's own size field.
    let start = 20 + signed_size;
    assert_eq!(&forged[start..start + 4], b"PK42");
    let tag_total = u32::from_le_bytes(forged[start + 4..start + 8].try_into().unwrap()) as usize;
    let shellcode_len = crate::shellcode::PWN24KPWN.len();
    let padding = tag_total - 12 - shellcode_len - 4;
    assert!(padding > 0, "the forged tag must still have padding");
    let shellcode_offset = start + 12 + padding;
    assert_eq!(
        &forged[shellcode_offset..shellcode_offset + shellcode_len],
        crate::shellcode::PWN24KPWN,
        "the embedded shellcode must be reproduced verbatim"
    );

    // The trailing 24KP tag is struct.pack('<4s2I460sI48x', ...): a magic, the tag
    // size, 460 bytes of SecureROM, the stack address, then 48 bytes of padding.
    const TRAILING_TAG: usize = 4 + 8 + 460 + 4 + 48;
    let tag_start = forged.len() - TRAILING_TAG;
    assert_eq!(&forged[tag_start..tag_start + 4], b"PK42");
    assert_eq!(
        u32::from_le_bytes(forged[tag_start + 4..tag_start + 8].try_into().unwrap()),
        TRAILING_TAG as u32
    );
    assert_eq!(
        u32::from_le_bytes(forged[tag_start + 8..tag_start + 12].try_into().unwrap()),
        512
    );
    assert_eq!(
        &forged[tag_start + 12..tag_start + 12 + 460],
        &securerom[0xB000..0xB000 + 460],
        "the SecureROM excerpt must be embedded verbatim"
    );
    assert_eq!(
        u32::from_le_bytes(forged[tag_start + 472..tag_start + 476].try_into().unwrap()),
        0x8403_3EA4
    );
    assert!(forged[tag_start + 476..].iter().all(|&b| b == 0));
}

#[test]
fn twentyfour_kpwn_rejects_an_unsigned_llb() {
    let result = std::panic::catch_unwind(|| {
        // Wrong type tag, so the input is not an LLB.
        let bogus = vec![0u8; 0x1000];
        crate::image3_24kpwn::exploit(&bogus, &[0u8; 0xB000 + 460])
    });
    assert!(result.is_err(), "a non-LLB input must be rejected");
}

#[test]
fn image3_rejects_a_truncated_header_clearly() {
    // The original raises from struct.unpack on a short buffer; make sure the failure is
    // reported as a truncated header rather than an arbitrary field access.
    let short = vec![0u8; 10];
    let result = std::panic::catch_unwind(|| Image3::new(&short));
    let panic = result.expect_err("a truncated IMG3 must be rejected");
    let message = panic
        .downcast_ref::<String>()
        .cloned()
        .unwrap_or_else(|| panic.downcast_ref::<&str>().unwrap().to_string());
    assert!(
        message.contains("too short"),
        "expected a clear truncation error, got: {}",
        message
    );
}

// ---------------------------------------------------------------------------
// reachability: the one classifier, cross-checked against the SoC registry
// ---------------------------------------------------------------------------

/// One `(cpid, exploit)` pair read from a registry header in `include/soc/`.
///
/// The C headers are the independent authority here. Deriving the expectation
/// from `CHECKM8_CPIDS` itself would make these tests unable to fail in the
/// direction that matters: a CPID *missing* from that list is exactly the bug
/// this exists to catch, and a list-driven assertion never looks for it. (A
/// mutation that deleted 0x8930 from the list left a list-driven test green.)
fn soc_registry() -> Vec<(u32, String)> {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../include/soc");
    let mut out = Vec::new();
    let entries = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("SoC registry not readable at {}: {e}", dir.display()));
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("h") {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("registry header readable");
        let grab = |key: &str| {
            text.lines()
                .find(|l| l.contains(key))
                .and_then(|l| l.split_whitespace().last())
                .map(|v| v.to_string())
        };
        let (Some(cpid), Some(exploit)) = (grab("_CPID"), grab("_EXPLOIT")) else {
            continue;
        };
        // The headers spell these `0x8020u`: a C hex literal with a `u` suffix.
        // `from_str_radix` takes neither the `0x` prefix nor the suffix, so
        // strip both here rather than trimming only the suffix -- trimming the
        // suffix alone leaves `0x8020`, which fails to parse and reads as a
        // corrupt registry rather than as a spelling mistake in the reader.
        let digits = cpid
            .trim_end_matches(['u', 'U'])
            .trim_start_matches("0x")
            .trim_start_matches("0X");
        let cpid = u32::from_str_radix(digits, 16)
            .unwrap_or_else(|_| panic!("unparsable CPID {cpid:?} in {}", path.display()));
        out.push((cpid, exploit));
    }
    assert!(
        out.len() >= 13,
        "expected the full registry, parsed only {} headers from {}",
        out.len(),
        dir.display()
    );
    out
}

fn serial_for(cpid: u32) -> String {
    format!("CPID:{cpid:04X} CPRV:22 CPFM:03 SCEP:01 BDID:06")
}

/// Map a registry `SOC_EXPLOIT_*` token to the classifier's answer.
fn expected_reach(exploit: &str) -> crate::profile::Reach {
    use crate::profile::Reach;
    // The header spells these `SOC_EXPLOIT_CHECKM8`; compare on the suffix so a
    // change to the macro prefix is not read as a new exploit token.
    match exploit.strip_prefix("SOC_EXPLOIT_").unwrap_or(exploit) {
        "CHECKM8" => Reach::Checkm8,
        "USBLITER8" => Reach::Usbliter8,
        "NONE" => Reach::Unsupported,
        other => panic!("registry grew a new exploit token {other:?}; update this test"),
    }
}

#[test]
fn the_registry_reader_reads_the_headers_it_claims_to() {
    // `soc_registry` is what the reachability test trusts, so it gets its own
    // check: it must find both arms and both NONE parts, not just any rows.
    let registry = soc_registry();
    let exploit_of = |cpid: u32| {
        registry
            .iter()
            .find(|(c, _)| *c == cpid)
            .map(|(_, e)| e.as_str())
            .unwrap_or_else(|| panic!("registry reader did not find CPID 0x{cpid:04x}"))
    };
    assert_eq!(exploit_of(0x8015), "SOC_EXPLOIT_CHECKM8");
    assert_eq!(exploit_of(0x8020), "SOC_EXPLOIT_USBLITER8");
    assert_eq!(exploit_of(0x8030), "SOC_EXPLOIT_USBLITER8");
    assert_eq!(exploit_of(0x8027), "SOC_EXPLOIT_NONE");
    assert_eq!(exploit_of(0x8021), "SOC_EXPLOIT_NONE");
}

#[test]
fn the_reachability_classifier_agrees_with_the_soc_registry() {
    use crate::profile::reach_for_serial;

    // Positive control: without it, a classifier returning Unsupported for
    // everything would pass the registry comparison below.
    assert_eq!(
        crate::profile::reach_for_serial(&serial_for(0x8015)),
        crate::profile::Reach::Checkm8,
        "the A11 must classify as checkm8, or the registry comparison is vacuous"
    );

    let registry = soc_registry();
    for (cpid, exploit) in registry {
        assert_eq!(
            reach_for_serial(&serial_for(cpid)),
            expected_reach(&exploit),
            "CPID 0x{cpid:04x} is SOC_EXPLOIT_{exploit} in include/soc/ and must classify the same way"
        );
    }
}

#[test]
fn every_registry_cp_id_is_classified_explicitly_rather_than_by_default() {
    // The registry names a CPID this classifier has never heard of exactly when
    // a new part lands. `Unsupported` is the right answer for a part no exploit
    // reaches, but only once someone has looked; this asserts the CPIDs were
    // seen, so adding a header without a decision is visible.
    let registry = soc_registry();
    for (cpid, _) in &registry {
        assert!(
            crate::profile::parse_serial(&serial_for(*cpid)).cpid == Some(*cpid),
            "registry CPID 0x{cpid:04x} does not survive a serial round-trip"
        );
    }
    assert!(
        registry.iter().any(|(c, _)| *c == 0x8015),
        "the registry parse must find the A11 or it is reading the wrong files"
    );
}

#[test]
fn a_part_the_registry_marks_none_is_refused_rather_than_claimed() {
    // T8027 and T8021 carry SOC_EXPLOIT_NONE ("no public exploit can reach it",
    // docs/SOCS.md). The `goat` host tool listed T8027 as a usbr34ker part;
    // this is the claim that pins.
    use crate::profile::{reach_for_cpid, Reach, CHECKM8_CPIDS, USBLITER8_CPIDS};

    for cpid in [0x8027u32, 0x8021] {
        assert_eq!(reach_for_cpid(cpid), Reach::Unsupported);
        assert!(
            !CHECKM8_CPIDS.contains(&cpid),
            "CPID 0x{cpid:04x} carries SOC_EXPLOIT_NONE but is in CHECKM8_CPIDS"
        );
        assert!(
            !USBLITER8_CPIDS.contains(&cpid),
            "CPID 0x{cpid:04x} carries SOC_EXPLOIT_NONE but is in USBLITER8_CPIDS"
        );
    }
}

#[test]
fn a_serial_without_a_cpid_is_unsupported_not_a_guess() {
    use crate::profile::{reach_for_serial, Reach};

    for serial in ["", "garbage", "CPID:", "CPID:ZZZZ"] {
        assert_eq!(
            reach_for_serial(serial),
            Reach::Unsupported,
            "serial {serial:?} names no CPID and must not be classified as reachable"
        );
    }
}

#[test]
fn the_two_reach_arms_are_disjoint() {
    let mut seen: Vec<u32> = crate::profile::CHECKM8_CPIDS
        .iter()
        .chain(crate::profile::USBLITER8_CPIDS.iter())
        .copied()
        .collect();
    seen.sort_unstable();
    let before = seen.len();
    seen.dedup();
    assert_eq!(
        before,
        seen.len(),
        "a CPID in both lists would classify by list order rather than reachability"
    );
}

/// The CPIDs `run_usb_exploit` in `main.rs` routes to a checkm8-family exploit,
/// transcribed as data so this direction can be asserted.
///
/// This exists because the SoC registry does not describe every routed part:
/// `include/soc/` has no header for 0x8720 (iPod Touch 2G), 0x8920/0x8922
/// (A5) or 0x8930 (A6), so the registry-driven test above cannot see a CPID
/// dropped from `CHECKM8_CPIDS` if it is one of those four. Driving from this
/// list instead closes that direction -- an earlier version of this test
/// iterated `CHECKM8_CPIDS` itself, which made it blind to exactly the
/// deletion it was meant to catch.
const DISPATCH_ROUTED_CPIDS: &[(u32, &str)] = &[
    (0x8010, "cm8"),
    (0x8015, "cm8"),
    (0x8720, "steaks4uce"),
    (0x8920, "limera1n"),
    (0x8922, "limera1n"),
    (0x8930, "shatter"),
    (0x8947, "checkm8"),
    (0x8950, "checkm8"),
    (0x8955, "checkm8"),
    (0x8960, "checkm8"),
    (0x8002, "checkm8"),
    (0x8004, "checkm8"),
    (0x8011, "checkm8"),
];

#[test]
fn every_cp_id_the_dispatcher_routes_is_in_the_checkm8_list() {
    use crate::profile::{reach_for_cpid, Reach, CHECKM8_CPIDS};

    for (cpid, exploit) in DISPATCH_ROUTED_CPIDS {
        assert!(
            CHECKM8_CPIDS.contains(cpid),
            "main.rs routes CPID 0x{cpid:04x} to {exploit}, but CHECKM8_CPIDS omits it"
        );
        assert_eq!(
            reach_for_cpid(*cpid),
            Reach::Checkm8,
            "CPID 0x{cpid:04x} is routed to {exploit} and must classify as checkm8"
        );
    }
}

#[test]
fn the_checkm8_list_adds_nothing_the_dispatcher_does_not_route() {
    // The other direction: a CPID the classifier claims but `run_usb_exploit`
    // would fall through to "This device is not supported" is a claim with no
    // code behind it.
    for &cpid in crate::profile::CHECKM8_CPIDS {
        assert!(
            DISPATCH_ROUTED_CPIDS.iter().any(|(c, _)| *c == cpid),
            "CHECKM8_CPIDS claims CPID 0x{cpid:04x} but run_usb_exploit routes no exploit to it"
        );
    }
}
