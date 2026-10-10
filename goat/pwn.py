"""The one delegated step: running checkm8.

goat does not reimplement the exploit. It is a large, fragile, well-tested body
of work with nothing to do with loading images, and this project vendors it
(ipwndfu/, upstream checkm8 tooling). Everything after `goat pwn` is goat's
own: its own transport, its own container, its own loader protocol.

This module shells out to the vendored ipwndfu with `-p` (checkm8) and then
confirms the device re-enumerated as pwndfu.
"""

import subprocess
import sys

from .usb import PwnedDFU, LibusbDeviceList, UsbError


def checkm8(ipwndfu_dir="ipwndfu", interpreter=None, wait=10.0):
    """Exploit the DFU device into pwndfu state. Returns 0 on success.

    The vendored tree arrived as Python 2, which no current macOS ships and
    which arm64 Homebrew no longer builds. It is ported to Python 3 in place,
    so the interpreter is the one goat itself runs under.
    """
    interpreter = interpreter or sys.executable or "python3"
    print("goat: running checkm8 via %s (ipwndfu -p)" % interpreter)
    proc = subprocess.run([interpreter, "ipwndfu", "-p"], cwd=ipwndfu_dir)
    if proc.returncode != 0:
        print("goat: ipwndfu exited %d" % proc.returncode)
        return proc.returncode

    import time
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
