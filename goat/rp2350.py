"""Goat's explicit RP2350/usbr34ker board workflow.

This is deliberately separate from ``kload``: UF2 files are firmware for the
RP2350 helper board, while kload sends AArch64 images to an Apple DFU device.
"""

import glob
import os
import shutil
import sys
import termios
import tty
import select
import time
from types import SimpleNamespace


BOARDS = (
    "pico2",
    "pimoroni_tiny2350",
    "waveshare_rp2350_usb_a",
    "waveshare_rp2350_zero",
)
ASSET_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "usbr34ker", "firmware"))
UF2_MAGIC = (0x0A324655).to_bytes(4, "little")
UF2_MAGIC_END = (0x0AB16F30).to_bytes(4, "little")


def firmware_path(board, firmware_dir=None):
    if board not in BOARDS:
        raise ValueError("unknown board %r (choose: %s)" % (board, ", ".join(BOARDS)))
    filename = "usbr34ker.%s.uf2" % board
    roots = []
    if firmware_dir:
        roots.append(os.path.abspath(firmware_dir))
    roots.append(ASSET_DIR)
    # A zipapp cannot open data through its __file__ path. Releases therefore
    # keep UF2s beside the executable (or in a sibling firmware directory).
    launcher_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
    roots.extend((launcher_dir, os.path.join(launcher_dir, "firmware")))
    for root in roots:
        path = os.path.join(root, filename)
        if os.path.isfile(path):
            return path
    raise OSError("missing bundled firmware: %s" % os.path.join(roots[0], filename))


def validate_uf2(path):
    size = os.path.getsize(path)
    if size == 0 or size % 512:
        raise ValueError("%s is not a complete UF2 (size=%d)" % (path, size))
    with open(path, "rb") as fh:
        first = fh.read(512)
        fh.seek(-512, os.SEEK_END)
        last = fh.read(512)
    if first[:4] != UF2_MAGIC or first[4:8] != (0x9E5D5157).to_bytes(4, "little"):
        raise ValueError("%s has invalid UF2 header" % path)
    if last[508:512] != UF2_MAGIC_END:
        raise ValueError("%s has invalid UF2 end marker" % path)
    return size


def serial_ports():
    patterns = ("/dev/cu.usbmodem*", "/dev/tty.usbmodem*",
                "/dev/cu.usbserial*", "/dev/ttyUSB*", "/dev/ttyACM*")
    result = []
    for pattern in patterns:
        result.extend(glob.glob(pattern))
    return sorted(set(result))


def boot_mounts():
    candidates = ["/Volumes/RPI-RP2", "/media/RPI-RP2", "/run/media/RPI-RP2"]
    user = os.environ.get("USER")
    if user:
        candidates.append("/run/media/%s/RPI-RP2" % user)
    return [p for p in candidates if os.path.isdir(p)]


def cmd_list(args):
    root = os.path.abspath(args.firmware_dir or ASSET_DIR)
    print("goat: usbr34ker firmware bundle: %s" % root)
    for board in BOARDS:
        try:
            path = firmware_path(board, args.firmware_dir)
            print("  %-30s %7d bytes  %s" % (board, validate_uf2(path), path))
        except OSError:
            print("  %-30s MISSING" % board)
    ports = serial_ports()
    mounts = boot_mounts()
    print("goat: serial ports: %s" % (", ".join(ports) if ports else "none detected"))
    print("goat: RP2 boot volumes: %s" % (", ".join(mounts) if mounts else "none detected"))
    return 0


def cmd_flash(args):
    path = firmware_path(args.board, args.firmware_dir)
    size = validate_uf2(path)
    mount = args.mount or (boot_mounts()[0] if boot_mounts() else None)
    if not mount:
        raise OSError("RP2 boot volume not found; hold BOOTSEL and pass --mount /Volumes/RPI-RP2")
    if not os.path.isdir(mount):
        raise OSError("boot volume does not exist: %s" % mount)
    target = os.path.join(mount, os.path.basename(path))
    print("goat: flashing %s (%d bytes) to %s" % (args.board, size, target))
    with open(path, "rb") as src, open(target, "wb") as dst:
        shutil.copyfileobj(src, dst, 1024 * 1024)
        dst.flush()
        os.fsync(dst.fileno())
    print("goat: UF2 copied; waiting for the RP2350 bootloader to reboot")
    time.sleep(args.wait)
    return 0


def cmd_terminal(args):
    ports = serial_ports()
    port = args.port or (ports[0] if len(ports) == 1 else None)
    if not port:
        if ports:
            raise OSError("multiple serial ports detected; pass --port: %s" % ", ".join(ports))
        raise OSError("no USB modem serial port detected; pass --port /dev/tty.usbmodemXXXX")
    try:
        import serial
    except ImportError:
        raise OSError("pyserial is required for goat usbr34ker terminal (pip install pyserial)")
    print("goat: opening %s at %d baud (Ctrl-] exits)" % (port, args.baud))
    link = serial.Serial(port, args.baud, timeout=0.05)
    old = termios.tcgetattr(sys.stdin.fileno())
    try:
        tty.setraw(sys.stdin.fileno())
        while True:
            readable, _, _ = select.select([sys.stdin, link], [], [], 0.05)
            if link in readable:
                data = link.read(link.in_waiting or 1)
                if data:
                    os.write(sys.stdout.fileno(), data)
            if sys.stdin in readable:
                data = os.read(sys.stdin.fileno(), 1024)
                if b"\x1d" in data:
                    break
                if data:
                    link.write(data)
    finally:
        termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, old)
        link.close()
    return 0


def cmd_walkthrough(args):
    print("GOAT / usbr34ker live walkthrough")
    print("1. Connect the RP2350 helper board and hold BOOTSEL while plugging it in.")
    print("2. Select the matching board: %s" % ", ".join(BOARDS))
    print("3. Flash the UF2 to the RP2 volume, then reconnect the USB data cable.")
    print("4. Open the 115200-8N1 terminal to watch usbr34ker's DFU workflow.")
    print("5. With the board ready, use `goat kload` for the separate Dr1zzle A11 payload.")
    print("\nAvailable boards: %s" % ", ".join(BOARDS))
    if args.list_only:
        return cmd_list(args)
    if not args.interactive:
        print("Run again with --interactive to select, flash, and open the UART.")
        return 0
    board = args.board
    if not board:
        board = input("Board [%s]: " % BOARDS[0]).strip() or BOARDS[0]
    cmd_flash(SimpleNamespace(board=board, firmware_dir=args.firmware_dir,
                              mount=args.mount, wait=args.wait))
    if args.no_terminal:
        return 0
    return cmd_terminal(SimpleNamespace(port=args.port, baud=args.baud))


def add_parser(sub):
    sp = sub.add_parser("usbr34ker", help="flash and monitor the RP2350 helper board")
    nested = sp.add_subparsers(dest="usbr34ker_command")
    for name, help_text, func in (("list", "list boards, UF2s, ports and boot volumes", cmd_list),
                                  ("flash", "flash a bundled UF2", cmd_flash),
                                  ("terminal", "open the 115200 baud UART terminal", cmd_terminal),
                                  ("walkthrough", "print the live preparation walkthrough", cmd_walkthrough)):
        child = nested.add_parser(name, help=help_text)
        child.add_argument("--firmware-dir", default=None)
        if name == "flash":
            child.add_argument("--board", required=True, choices=BOARDS)
            child.add_argument("--mount", default=None)
            child.add_argument("--wait", type=float, default=2.0)
        elif name == "terminal":
            child.add_argument("--port", default=None)
            child.add_argument("--baud", type=int, default=115200)
        elif name == "walkthrough":
            child.add_argument("--list-only", action="store_true")
            child.add_argument("--interactive", action="store_true",
                               help="select, flash, and open the UART")
            child.add_argument("--board", choices=BOARDS, default=None)
            child.add_argument("--mount", default=None)
            child.add_argument("--port", default=None)
            child.add_argument("--baud", type=int, default=115200)
            child.add_argument("--wait", type=float, default=2.0)
            child.add_argument("--no-terminal", action="store_true")
        child.set_defaults(func=func)
    sp.set_defaults(func=lambda args: cmd_walkthrough(type("Args", (), {
        "list_only": False, "interactive": False, "board": None,
        "mount": None, "port": None, "baud": 115200, "wait": 2.0,
        "no_terminal": True, "firmware_dir": None})()))
