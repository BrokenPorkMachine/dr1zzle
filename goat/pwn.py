"""The one delegated step: running checkm8.

goat does not reimplement the exploit. It is a large, fragile, well-tested body
of work with nothing to do with loading images, and this project vendors it
(ipwndfu/, upstream checkm8 tooling). Everything after `goat pwn` is goat's
own: its own transport, its own container, its own loader protocol.

This module shells out to the vendored ipwndfu with `-p` (checkm8) and then
confirms the device re-enumerated as pwndfu.

What it will not do is point checkm8 at a part checkm8 cannot reach. The bug
that ipwndfu implements ends with the A11; a 2025 second bootrom bug (usbliter8)
covers the A12/A13 profiles recorded here, but it needs an RP2350 spliced into
the cable and cannot be driven from this host. `checkm8` reads the attached
device's CPID first and refuses with that explanation rather than letting the
exploit fail on the device and leave an operator guessing at the cable.
"""

import subprocess
import sys
import time

from .usb import PwnedDFU, LibusbDeviceList, UsbError

# What the attached device is, from the DFU serial string. Both checkm8 and
# usbliter8 identify a part the same way, by CPID.
CHECKM8_CPIDS = {
    # The nine profile headers cover ten CPIDs because S5L8960 represents two
    # A7 variants in the vendored checkm8 table.
    0x8015, 0x8011, 0x8010, 0x8960,
    0x8004, 0x8002, 0x8955, 0x8950, 0x8947,
}

# The runnable usbliter8 CPIDs represented by this registry. Its source tree
# also carries a T8006 target; that older identity is outside this registry.
# The A12X and A12Z are named in its README as theoretically reachable but not
# implemented, so they are absent here and have to be absent there too.
USBLITER8_CPIDS = {0x8020, 0x8030}

# Instruments, not tooling: the exploit runs on the microcontroller, and this
# host cannot talk to the bus it needs. Listed last so the failure reads as
# "wrong bus", not "unsupported part".
USBLITER8_HARDWARE = "an RP2350 board (e.g. Raspberry Pi Pico 2) as the USB host"


def _cpid_of(serial):
    """The CPID out of a DFU serial string, or None."""
    for token in serial.split():
        if token.startswith("CPID:"):
            digits = token[len("CPID:"):]
            try:
                return int(digits, 16)
            except ValueError:
                return None
    return None


def checkm8(ipwndfu_dir="ipwndfu", interpreter=None, wait=10.0):
    """Exploit the DFU device into pwndfu state. Returns 0 on success.

    The vendored tree arrived as Python 2, which no current macOS ships and
    which arm64 Homebrew no longer builds. It is ported to Python 3 in place,
    so the interpreter is the one goat itself runs under.
    """
    interpreter = interpreter or sys.executable or "python3"

    # Refuse here rather than on the device, and say why.
    try:
        with PwnedDFU(LibusbDeviceList(), timeout=5.0) as dev:
            cpid = _cpid_of(dev.serial)
    except UsbError:
        cpid = None
    if cpid is not None and cpid not in CHECKM8_CPIDS:
        if cpid in USBLITER8_CPIDS:
            print("goat: CPID 0x%04X is not reachable by checkm8 -- the bug "
                  "it implements ends with the A11." % cpid)
            print("goat: this part needs usbliter8, which runs on %s, not on "
                  "this host's USB stack." % USBLITER8_HARDWARE)
        else:
            print("goat: CPID 0x%04X has no exploit path in this tree. "
                  "checkm8 ends at the A11 and usbliter8 covers the A12 and "
                  "A13 only." % cpid)
        print("goat: refused before attempting the exploit.")
        return 1

    print("goat: running checkm8 via %s (ipwndfu -p)" % interpreter)
    proc = subprocess.run([interpreter, "ipwndfu", "-p"], cwd=ipwndfu_dir)
    if proc.returncode != 0:
        print("goat: ipwndfu exited %d" % proc.returncode)
        return proc.returncode

    deadline = time.time() + wait
    while time.time() < deadline:
        try:
            with PwnedDFU(LibusbDeviceList(), timeout=1.0) as dev:
                print("goat: device serial: %s" % dev.serial)
                if "PWND:[checkm8]" in dev.serial:
                    print("goat: device is pwndfu")
                    return 0
                print("goat: device is in DFU but not pwndfu yet")
        except UsbError:
            pass
        time.sleep(0.5)

    print("goat: device did not come back as pwndfu within %.0fs" % wait)
    return 1
