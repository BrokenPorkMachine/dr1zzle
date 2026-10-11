"""`goat pwn`: exploit a DFU device into pwndfu state, or explain why not.

This module is the guided front end. The exploit itself is
[goat/checkm8.py](checkm8.py), which the eLab forensics analysis of the
checkm8 bug is written against, here on this project's own transport and with
this project's own measured constants. What lives here is the part an operator
needs before and after: which firmware the device is running, which method that
firmware gets, what is still unmeasured, and what the state was when it
stopped.

What it will not do is point checkm8 at a part checkm8 cannot reach: the bug
ends with the A11, and a 2025 second bootROM bug (usbliter8) covers the
A12/A13 but needs an RP2350 spliced into the cable and cannot be driven from
this host. Both facts are printed as the reason for a refusal, so the operator
is left guessing at nothing.

The state it leaves the device in is the pwndfu command channel that
[goat/usb.py](usb.py) already speaks, so `goat send` works immediately after.
"""

import os
import shutil
import subprocess
import time

from . import checkm8 as cm8
from . import checkm8_profile as profiles
from . import usb

# Compatibility aliases for callers that inspect the reachability registry.
CHECKM8_CPIDS = profiles.CHECKM8_CPIDS
USBLITER8_CPIDS = profiles.USBLITER8_CPIDS
USBLITER8_HARDWARE = profiles.USBLITER8_HARDWARE
UsbError = usb.UsbError
LibusbDeviceList = usb.LibusbDeviceList
PwnedDFU = usb.PwnedDFU
_ORIGINAL_LIBUSB = LibusbDeviceList
_ORIGINAL_PWNED_DFU = PwnedDFU


def _usb_list():
    """Honor either module-level or usb-module test/device substitutions."""
    factory = LibusbDeviceList
    if factory is _ORIGINAL_LIBUSB:
        factory = usb.LibusbDeviceList
    return factory()


def _dfu_device(usb_dev, timeout):
    factory = PwnedDFU
    if factory is _ORIGINAL_PWNED_DFU:
        factory = usb.PwnedDFU
    return factory(usb_dev, timeout)

PWND_SERIAL = "PWND:[checkm8]"

# What the operator is told about the state of this work, per run. The plan
# carries the part-specific half; this is the part that is true of the whole
# tree: the trigger point is a runtime measurement this tree does not have.
HEAD_NOTES = (
    "the exploit's six stages are implemented; the constants are measured per "
    "build from the SecureROM images",
)


def _cpid_of(serial):
    """Return the hexadecimal CPID from a DFU serial string, if present."""
    for token in serial.split():
        if token.startswith("CPID:"):
            try:
                return int(token[5:], 16)
            except ValueError:
                return None
    return None


def _rpwn_binary():
    """Find the Rust-native RPWN driver, if it is installed or built locally."""
    configured = os.environ.get("GOAT_RPWN") or os.environ.get("RPWN")
    candidates = []
    if configured:
        candidates.append(configured)
    found = shutil.which("rpwn")
    if found:
        candidates.append(found)
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    candidates.extend((
        os.path.join(root, "rpwn", "rust", "target", "release", "rpwn"),
        os.path.join(root, "RPWN", "target", "release", "rpwn"),
    ))
    for candidate in candidates:
        if candidate and os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def _run_rpwn(verbose=False):
    """Run Rust RPWN when present; return None when compatibility fallback is needed."""
    binary = _rpwn_binary()
    if binary is None:
        return None
    print("goat: using Rust RPWN (%s)" % binary)
    result = subprocess.run(
        [binary, "-p"],
        check=False,
        capture_output=not verbose,
        text=True,
    )
    if not verbose:
        if result.stdout:
            print(result.stdout, end="")
        if result.stderr:
            print(result.stderr, end="", file=sys.stderr)
    return result.returncode


def checkm8(verbose=False, dry_run=False, wait=10.0, interpreter=None):
    """Run checkm8 on the attached device. Returns 0 on success.

    Called by `goat pwn` and by anything that wants a pwndfu device but is
    holding a plain DFU one (`goat send --pwn`, `goat kload --pwn`).
    """
    usb_dev = _usb_list()
    if hasattr(usb_dev, "dfu_present") and not usb_dev.dfu_present():
        print("goat: no Apple device in DFU mode (05ac:1227); put the device "
              "into DFU and try again")
        return 1

    try:
        dev = _dfu_device(usb_dev, timeout=5.0)
    except usb.UsbError as exc:
        print("goat: %s" % exc)
        return 1
    serial = dev.serial
    if hasattr(dev, "close"):
        dev.close()

    if PWND_SERIAL in serial:
        print("goat: device is already pwndfu (%s)" % serial)
        return 0

    plan = cm8.plan(serial)
    print("goat: %s" % serial)
    for line in plan.describe():
        print("goat: %s" % line)
    for note in HEAD_NOTES:
        print("goat: note               : %s" % note)

    if plan.blockers:
        return 1
    if dry_run:
        return 0

    print("goat: running Rust RPWN when available")
    rust_result = _run_rpwn(verbose=verbose)
    if rust_result is not None:
        return rust_result
    print("goat: RPWN binary not found; using Goat compatibility path")
    result = cm8.run(plan, verbose=verbose)
    if result != 0:
        return result

    deadline = time.time() + wait
    while time.time() < deadline:
        try:
            with _dfu_device(usb_dev, timeout=1.0) as dev:
                if PWND_SERIAL in dev.serial:
                    print("goat: device is pwndfu")
                    return 0
                print("goat: device is in DFU but not pwndfu yet "
                      "(%s)" % dev.serial)
        except UsbError:
            pass
        time.sleep(0.5)

    print("goat: device did not come back as pwndfu within %.0fs" % wait)
    return 1


def acquire_pwndfu(auto_pwn=True, verbose=False, timeout=5.0):
    """A pwndfu device, exploiting a plain DFU one first when that is allowed.

    Same contract as [goat/kload.py](kload.py)'s `acquire_pwndfu`, so the two
    callers of `checkm8` in this tree need only one place to change when the
    exploit starts working end to end.
    """
    usb_dev = _usb_list()
    if not usb_dev.dfu_present():
        raise UsbError("no Apple device in DFU mode (05ac:1227). Put the "
                       "device in DFU mode, then run 'goat send' again.")

    dev = None
    failure = None
    try:
        dev = _dfu_device(usb_dev, timeout)
    except usb.UsbError as exc:
        failure = exc
    if dev is not None and PWND_SERIAL in dev.serial:
        return dev
    if dev is not None:
        if hasattr(dev, "close"):
            dev.close()
    if failure is not None:
        # The device is there but could not be opened. Exploiting something we
        # know nothing about is not the fix, so report what the open said.
        raise failure
    if not auto_pwn:
        raise UsbError("the device is in DFU but not pwndfu. Run 'goat pwn' "
                       "first, or pass --pwn to let send exploit it.")
    result = checkm8(verbose=True) if verbose else checkm8()
    if result != 0:
        raise UsbError("checkm8 did not leave the device in pwndfu state")
    dev = _dfu_device(usb_dev, max(timeout, 10.0))
    if PWND_SERIAL not in dev.serial:
        serial = dev.serial
        if hasattr(dev, "close"):
            dev.close()
        raise UsbError("checkm8 reported success but the device is still not "
                       "pwndfu (%s)" % (serial or "no serial"))
    return dev
