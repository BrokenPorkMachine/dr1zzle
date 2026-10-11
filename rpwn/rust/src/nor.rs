//! Port of `nor.py`: the IMG2 container that fills an iPhone 3GS NOR flash chip.

use crate::utilities::{die, slice, u32_le};

pub const NOR_SIZE: usize = 0x100000;

#[derive(Clone)]
#[allow(dead_code)] // firmware_offset is parsed for parity with the original
pub struct NorData {
    pub block_size: u32,
    pub firmware_offset: usize,
    pub firmware_length: usize,
    /// Split of the raw dump into header / alloc8 area / partition table / firmware / rest.
    pub parts: [Vec<u8>; 5],
    /// The chained IMG3 images that make up the firmware region.
    pub images: Vec<Vec<u8>>,
}

impl NorData {
    /// `NorData.__init__`
    pub fn new(dump: &[u8]) -> NorData {
        assert_eq!(
            dump.len(),
            NOR_SIZE,
            "NorData: dump is not {} bytes",
            NOR_SIZE
        );

        let block_size = u32_le(dump, 4);
        let firmware_block = u32_le(dump, 12);
        let firmware_block_count = u32_le(dump, 16);

        let img2_crc = u32_le(dump, 48);
        let computed = crc32(&dump[..48]);
        if img2_crc != computed {
            die(format!(
                "ERROR: IMG2 header CRC32 mismatch (0x{:08x} != 0x{:08x}).",
                img2_crc, computed
            ));
        }

        let firmware_offset = block_size as usize * firmware_block as usize;
        let firmware_length = block_size as usize * firmware_block_count as usize;

        let parts = [
            slice(dump, 0, 52),
            slice(dump, 52, 512),
            slice(dump, 512, firmware_offset),
            slice(dump, firmware_offset, firmware_offset + firmware_length),
            slice(dump, firmware_offset + firmware_length, dump.len()),
        ];

        let mut images = Vec::new();
        let firmware = &parts[3];
        let mut offset = 0usize;
        loop {
            if offset + 8 > firmware.len() {
                break;
            }
            let magic = &firmware[offset..offset + 4];
            let size = u32_le(firmware, offset + 4) as usize;
            if magic != b"3gmI" || size == 0 {
                break;
            }
            images.push(slice(firmware, offset, offset + size));
            offset += size;
        }

        NorData {
            block_size,
            firmware_offset,
            firmware_length,
            parts,
            images,
        }
    }

    /// `NorData.dump()`: reassemble, refilling the firmware region with 0xff padding.
    pub fn dump(&self) -> Vec<u8> {
        let mut all_images: Vec<u8> = Vec::with_capacity(self.firmware_length);
        for image in &self.images {
            all_images.extend_from_slice(image);
        }
        all_images.resize(self.firmware_length, 0xff);

        let mut dump = Vec::with_capacity(NOR_SIZE);
        dump.extend_from_slice(&self.parts[0]);
        dump.extend_from_slice(&self.parts[1]);
        dump.extend_from_slice(&self.parts[2]);
        dump.extend_from_slice(&all_images);
        dump.extend_from_slice(&self.parts[4]);

        assert_eq!(dump.len(), NOR_SIZE, "NorData: rebuilt dump has wrong size");
        dump
    }

    /// True when every byte between the IMG2 header and the partition table is zero,
    /// i.e. no alloc8 exploit is currently installed.
    pub fn alloc8_area_is_empty(&self) -> bool {
        self.parts[1].iter().all(|&b| b == 0)
    }
}

fn crc32(data: &[u8]) -> u32 {
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(data);
    hasher.finalize()
}
