//! Port of `image3.py`: the Apple IMG3 container parser/rewriter.

use crate::dfuexec::PwnedDFUDevice;
use crate::utilities::{slice, u32_le};

/// Tag magics in their on-disk (byte-reversed) form, as the Python code stores them.
pub const MAGIC_TYPE: &[u8; 4] = b"EPYT"; // 'TYPE'[::-1]
pub const MAGIC_VERS: &[u8; 4] = b"SREV"; // 'VERS'[::-1]
pub const MAGIC_SEPO: &[u8; 4] = b"OPES"; // 'SEPO'[::-1]
pub const MAGIC_BORD: &[u8; 4] = b"DROB"; // 'BORD'[::-1]
pub const MAGIC_KBAG: &[u8; 4] = b"GABK"; // 'KBAG'[::-1]
pub const MAGIC_SHSH: &[u8; 4] = b"HSHS"; // 'SHSH'[::-1]
pub const MAGIC_CERT: &[u8; 4] = b"TREC"; // 'CERT'[::-1]
pub const MAGIC_DATA: &[u8; 4] = b"ATAD"; // 'DATA'[::-1]

const IMG3_MAGIC: &[u8; 4] = b"3gmI"; // 'Img3'[::-1]
/// Tag magics that live outside the signed region.
const UNSIGNED_MAGICS: [&[u8; 4]; 2] = [b"TREC", b"HSHS"];

#[derive(Clone, Debug)]
pub struct Tag {
    pub magic: [u8; 4],
    pub total_size: u32,
    pub data_size: u32,
    pub data: Vec<u8>,
}

impl Tag {
    pub fn new(magic: &[u8; 4], total_size: u32, data_size: u32, data: Vec<u8>) -> Tag {
        Tag {
            magic: *magic,
            total_size,
            data_size,
            data,
        }
    }
}

#[derive(Clone, Debug)]
#[allow(dead_code)] // header fields are parsed for parity with the original
pub struct Image3 {
    pub total_size: u32,
    pub data_size: u32,
    pub signed_size: u32,
    pub kind: [u8; 4],
    pub tags: Vec<Tag>,
}

/// Extracts a 4 byte tag magic, zero padding a short buffer rather than panicking.
fn magic4(data: &[u8]) -> [u8; 4] {
    let mut out = [0u8; 4];
    let available = data.len().min(4);
    out[..available].copy_from_slice(&data[..available]);
    out
}

impl Image3 {
    /// `Image3.__init__`
    pub fn new(data: &[u8]) -> Image3 {
        // The original relies on `struct.unpack` raising on a short buffer; be explicit
        // so a truncated image reports itself instead of failing on an arbitrary field.
        assert!(
            data.len() >= 20,
            "IMG3 image is {} bytes, too short for a 20-byte header",
            data.len()
        );
        let total_size = u32_le(data, 4);
        let data_size = u32_le(data, 8);
        let signed_size = u32_le(data, 12);
        let kind = magic4(&slice(data, 16, 20));

        let mut tags = Vec::new();
        let mut pos = 20usize;
        while pos < 20 + data_size as usize {
            if pos + 12 > data.len() {
                break;
            }
            let tag_magic = magic4(&slice(data, pos, pos + 4));
            let tag_total_size = u32_le(data, pos + 4);
            let tag_data_size = u32_le(data, pos + 8);
            let tag_data = slice(data, pos + 12, pos + tag_total_size as usize);
            tags.push(Tag::new(
                &tag_magic,
                tag_total_size,
                tag_data_size,
                tag_data,
            ));
            pos += tag_total_size as usize;
            if tag_total_size == 0 {
                break;
            }
        }

        Image3 {
            total_size,
            data_size,
            signed_size,
            kind,
            tags,
        }
    }

    /// `Image3.createImage3FromTags`
    pub fn from_tags(kind: &[u8; 4], tags: &[Tag]) -> Vec<u8> {
        let mut data_size = 0usize;
        let mut signed_size = 0usize;
        for tag in tags {
            data_size += 12 + tag.data.len();
            if !UNSIGNED_MAGICS.contains(&&tag.magic) {
                signed_size += 12 + tag.data.len();
            }
        }

        // totalSize must be rounded up to a 64-byte boundary.
        let mut total_size = 20 + data_size;
        let remainder = total_size % 64;
        if remainder != 0 {
            total_size += 64 - remainder;
        }

        let mut out = Vec::with_capacity(total_size);
        out.extend_from_slice(IMG3_MAGIC);
        out.extend_from_slice(&(total_size as u32).to_le_bytes());
        out.extend_from_slice(&(data_size as u32).to_le_bytes());
        out.extend_from_slice(&(signed_size as u32).to_le_bytes());
        out.extend_from_slice(kind);
        for tag in tags {
            out.extend_from_slice(&tag.magic);
            out.extend_from_slice(&tag.total_size.to_le_bytes());
            out.extend_from_slice(&tag.data_size.to_le_bytes());
            out.extend_from_slice(&tag.data);
        }
        out.resize(total_size, 0x00);
        out
    }

    /// `Image3.getTags`
    pub fn get_tags(&self, magic: &[u8; 4]) -> Vec<&Tag> {
        self.tags.iter().filter(|tag| &tag.magic == magic).collect()
    }

    /// `Image3.getKeybag`: the payload key material of the first type 1 KBAG tag.
    pub fn get_keybag(&self) -> Option<Vec<u8>> {
        for tag in self.get_tags(MAGIC_KBAG) {
            if tag.data.len() >= 8 && u32_le(&tag.data, 0) == 1 {
                return Some(slice(&tag.data, 8, 8 + 48));
            }
        }
        None
    }

    /// `Image3.getPayload`
    pub fn get_payload(&self) -> Option<&Vec<u8>> {
        let data = self.get_tags(MAGIC_DATA);
        if data.len() == 1 {
            Some(&data[0].data)
        } else {
            None
        }
    }

    /// `Image3.getDecryptedPayload`: AES-CBC with the device's firmware key, split out of
    /// the decrypted KBAG (first 16 bytes IV, remainder key).
    pub fn get_decrypted_payload(&self, device: &PwnedDFUDevice) -> Vec<u8> {
        let keybag = self
            .get_keybag()
            .unwrap_or_else(|| crate::utilities::die("ERROR: IMG3 has no usable KBAG tag."));
        let decrypted_keybag = device.decrypt_keybag(&keybag);
        let iv = &decrypted_keybag[..16];
        let key = &decrypted_keybag[16..];
        let payload = self
            .get_payload()
            .unwrap_or_else(|| crate::utilities::die("ERROR: IMG3 has no DATA tag."));
        crate::utilities::aes_decrypt(payload, iv, key)
            .unwrap_or_else(|e| crate::utilities::die(format!("ERROR: {}.", e)))
    }

    /// `Image3.shrink24KpwnCertificate`: trim the oversized 24Kpwn certificate.
    pub fn shrink_24kpwn_certificate(&mut self) {
        for index in 0..self.tags.len() {
            let tag = &self.tags[index];
            if &tag.magic == MAGIC_CERT && tag.data.len() >= 3072 {
                let mut data = slice(&tag.data, 0, 3072);
                assert_eq!(
                    data.last().copied(),
                    Some(0x00),
                    "24Kpwn certificate does not end with a NUL byte"
                );
                while data.last() == Some(&0) {
                    data.pop();
                }
                self.tags[index] = Tag::new(
                    MAGIC_CERT,
                    (12 + data.len()) as u32,
                    data.len() as u32,
                    data,
                );
                break;
            }
        }
    }

    /// `Image3.newImage3`
    pub fn new_image3(&self, device: Option<&PwnedDFUDevice>, decrypted: bool) -> Vec<u8> {
        let type_tag = self.get_tags(MAGIC_TYPE);
        assert_eq!(type_tag.len(), 1, "expected exactly one TYPE tag");
        let vers_tag = self.get_tags(MAGIC_VERS);
        assert!(vers_tag.len() <= 1, "too many VERS tags");
        let data_tag = self.get_tags(MAGIC_DATA);
        assert_eq!(data_tag.len(), 1, "expected exactly one DATA tag");
        let sepo_tag = self.get_tags(MAGIC_SEPO);
        assert!(sepo_tag.len() <= 2, "too many SEPO tags");
        let bord_tag = self.get_tags(MAGIC_BORD);
        assert!(bord_tag.len() <= 2, "too many BORD tags");
        let kbag_tag = self.get_tags(MAGIC_KBAG);
        assert!(kbag_tag.len() <= 2, "too many KBAG tags");
        let shsh_tag = self.get_tags(MAGIC_SHSH);
        assert!(shsh_tag.len() <= 1, "too many SHSH tags");
        let cert_tag = self.get_tags(MAGIC_CERT);
        assert!(cert_tag.len() <= 1, "too many CERT tags");

        let data = data_tag[0];
        let new_tag_data: Vec<u8>;
        let kbag_tags: Vec<&Tag>;
        if !kbag_tag.is_empty() && decrypted {
            let device = device.expect("decrypting an IMG3 requires a device connection");
            new_tag_data = self.get_decrypted_payload(device);
            kbag_tags = Vec::new();
        } else {
            new_tag_data = data.data.clone();
            kbag_tags = kbag_tag;
        }
        assert_eq!(
            data.data.len(),
            new_tag_data.len(),
            "DATA tag changed size while rewriting"
        );

        let mut tags: Vec<Tag> = Vec::new();
        tags.extend(type_tag.iter().map(|t| (*t).clone()));
        tags.push(Tag::new(
            &data.magic,
            data.total_size,
            data.data_size,
            new_tag_data,
        ));
        for group in [vers_tag, sepo_tag, bord_tag] {
            tags.extend(group.iter().map(|t| (*t).clone()));
        }
        tags.extend(kbag_tags.iter().map(|t| (*t).clone()));
        tags.extend(shsh_tag.iter().map(|t| (*t).clone()));
        tags.extend(cert_tag.iter().map(|t| (*t).clone()));

        Image3::from_tags(&self.kind, &tags)
    }
}
