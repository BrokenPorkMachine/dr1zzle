#!/usr/bin/env python3
"""goat -- the dr1zzle private loader.

    seal a payload  ->  .g1 container  ->  pwndfu device
    or seal  ->  device goatloader (persistent server)  ->  run

Subcommands:
    keygen    mint a sealing identity (RSA keypair + self-signed certificate)
    seal      wrap a payload into a sealed .g1 container
    inspect   print a container without any key material
    verify    check a container's certificate and signature
    unseal    verify, decrypt and extract a payload from a container
    pwn       exploit a DFU device into pwndfu state (goat's own checkm8)
    send      boot an image on a pwndfu device (alias: kload)
    push      push a sealed container to a device goatloader over TCP
    install   stage a container and write it into a NAND firmware slot
    shell     interactive session against a device goatloader
    run       jump a pwndfu device to an address
    readmem   read device memory out to a file

`send`/`kload` is checkra1n's ktool step: a built dr1zzle image is planned on
the host, written to the device, read back, and jumped to -- exploiting the
device first if it is only in DFU. `push` is the steady state, talking to the
goatloader that the payload runs as a persistent server.
"""

import argparse
import json
import os
import re
import socket
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from goat import aes, container, corpus, kload, rsa  # noqa: E402
from goat import rp2350  # noqa: E402
from goat.container import GOAT_DEFAULT_LOAD_BASE  # noqa: E402
from goat.der import DerError  # noqa: E402
from goat.usb import UsbError  # noqa: E402

VERSION = "goat/1"

GOATLOADER_PORT = 1234
GOATLOADER_IP = "192.168.42.1"

# x1 handed to a payload launched by goat: 'goat' big endian, so the payload
# can tell who started it. Must match GOAT_LAUNCH_TAG in include/goat/goat.h.
GOAT_LAUNCH_TAG = 0x676F6174


def load_identity(path):
    """Read a goat key document. Returns a dict with ints and cert bytes."""
    with open(path) as fh:
        doc = json.load(fh)
    if doc.get("format") != "goat-key/1":
        raise ValueError("%s is not a goat key document" % path)

    def as_int(text):
        if isinstance(text, int):
            return text
        text = text.strip()
        return int(text, 16) if text.lower().startswith("0x") else int(text)

    return {
        "serial": doc["serial"],
        "issuer": doc["issuer"],
        "subject": doc["subject"],
        "not_before": doc["not_before"],
        "not_after": doc["not_after"],
        "n": as_int(doc["n"]),
        "e": as_int(doc["e"]),
        "d": as_int(doc["d"]),
        "cert": bytes.fromhex(doc["cert"]),
    }


# ---------------------------------------------------------------------------
# key handling
# ---------------------------------------------------------------------------

def load_aes_key(args):
    """AES key from --key-hex, --key-file, or a fresh one (with a warning)."""
    if getattr(args, "key_hex", None):
        text = args.key_hex.strip().lower().replace(":", "").replace(" ", "")
        if text.startswith("0x"):
            text = text[2:]
        if len(text) != 64:
            raise SystemExit("goat: --key-hex must be 32 bytes (64 hex chars)")
        return bytes.fromhex(text)

    if getattr(args, "key_file", None):
        with open(args.key_file, "rb") as fh:
            raw = fh.read()
        if len(raw) == 32:
            return raw
        text = raw.strip().decode("ascii").lower()
        if text.startswith("0x"):
            text = text[2:]
        if len(text) == 64:
            return bytes.fromhex(text)
        raise SystemExit("goat: key file must hold 32 raw bytes or 64 hex chars")

    key = os.urandom(32)
    print("goat: no key given, generated one: %s" % key.hex())
    print("goat: keep it -- without it the container cannot be opened")
    if getattr(args, "key_out", None):
        with open(args.key_out, "w") as fh:
            fh.write(key.hex())
        os.chmod(args.key_out, 0o600)
        print("goat: wrote %s" % args.key_out)
    return key


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------

def cmd_keygen(args):
    identity = {
        "serial": args.serial,
        "issuer": args.issuer,
        "subject": args.subject or args.issuer,
        "not_before": args.not_before,
        "not_after": args.not_after,
    }
    print("goat: generating %d-bit RSA keypair (this takes a moment)..."
          % args.bits)
    priv = rsa.keygen(args.bits)
    identity.update(n=priv["n"], e=priv["e"], d=priv["d"])
    cert, tbs = rsa.build_cert(identity, priv)

    document = {
        "format": "goat-key/1",
        "name": identity["subject"],
        "serial": identity["serial"],
        "issuer": identity["issuer"],
        "subject": identity["subject"],
        "not_before": identity["not_before"],
        "not_after": identity["not_after"],
        "n": "0x%x" % identity["n"],
        "e": "0x%x" % identity["e"],
        "d": "0x%x" % identity["d"],
        "cert": cert.hex(),
    }
    with open(args.out, "w") as fh:
        json.dump(document, fh, indent=2)
    os.chmod(args.out, 0o600)

    # Round-trip the identity: the container code has to rebuild this exact
    # certificate from the document alone, or `seal` would produce containers
    # that do not belong to this key.
    round_trip = load_identity(args.out)
    again, _ = rsa.build_cert(round_trip, round_trip)
    if again != cert:
        raise SystemExit("goat: certificate is not reproducible, refusing")

    # Prove it end to end: seal something, then have the parse/verify path
    # accept it.
    probe = container.seal(b"goat-keygen self test\n", bytes(range(32)),
                           identity, 0x180180000, 0)
    if not container.parse(probe).verify():
        raise SystemExit("goat: freshly minted identity fails its own check")

    print("goat: wrote %s" % args.out)
    print("  subject      : %s" % identity["subject"])
    print("  modulus      : %d bits" % priv["bits"])
    print("  certificate  : %d bytes, self-signed" % len(cert))
    return 0


def cmd_seal(args):
    identity = load_identity(args.cert)
    aes_key = load_aes_key(args)
    with open(args.image, "rb") as fh:
        payload = fh.read()

    load_base = args.load_base
    if load_base is None:
        load_base = GOAT_DEFAULT_LOAD_BASE
    der = container.seal(payload, aes_key, identity, load_base,
                        args.entry_off, wrap=args.wrap)
    with open(args.out, "wb") as fh:
        fh.write(der)

    print("goat: sealed %s -> %s (%d bytes)"
          % (args.image, args.out, len(der)))
    print("goat: payload %d bytes, loadBase=0x%x, entry=0x%x"
          % (len(payload), load_base, load_base + args.entry_off))
    if args.wrap:
        print("goat: AES key wrapped to the certificate (unseal needs the "
              "private key)")
    else:
        print("goat: AES key is NOT in the container; the user must supply "
              "it on the device")
    return 0


def cmd_inspect(args):
    with open(args.container_file, "rb") as fh:
        der = fh.read()
    c = container.parse(der)

    print("goat container: %d bytes" % len(der))
    print("  version       : %d" % c.version)
    print("  payload sha256: %s" % c.payload_sha.hex())
    print("  payload length: %d (0x%x)" % (c.payload_len, c.payload_len))
    print("  load base     : 0x%x" % c.load_base)
    print("  entry offset  : 0x%x -> entry 0x%x"
          % (c.entry_off, c.load_base + c.entry_off))
    print("  iv            : %s" % c.iv.hex())
    print("  ciphertext    : %d bytes at +0x%x in this file"
          % (len(c.cipher), der.find(c.cipher)))
    print("  certificate   :")
    print("    subject     : %s" % c.subject)
    print("    issuer      : %s" % c.issuer)
    print("    serial      : 0x%x" % c.cert_serial)
    print("    not before  : %d" % c.not_before)
    print("    not after   : %d" % c.not_after)
    print("    key         : %d bit" % (len(c.modulus) * 8))
    print("  keywrap       : %s" % ("present (algo %d)" % c.keywrap_algo
                                   if c.has_keywrap else "none"))
    print("  signature     : %d bytes over %d body bytes"
          % (len(c.signature), len(c.signed_region)))

    cert_ok = c.cert_ok()
    verified = c.verify()
    print("  cert self-sig : %s" % ("OK" if cert_ok else "FAILED"))
    print("  signature     : %s" % ("OK" if verified else "FAILED"))
    return 0 if verified else 1


def cmd_verify(args):
    with open(args.container_file, "rb") as fh:
        c = container.parse(fh.read())
    if not c.cert_ok():
        print("goat: certificate self-signature FAILED")
        return 1
    if not c.verify():
        print("goat: container signature FAILED")
        return 1
    print("goat: certificate and signature verify")
    return 0


def cmd_unseal(args):
    with open(args.container_file, "rb") as fh:
        c = container.parse(fh.read())
    if not c.verify():
        print("goat: refusing to decrypt -- signature check failed")
        return 1

    if args.key_from_cert:
        identity = load_identity(args.cert)
        aes_key = c.unwrap_key(identity)
        print("goat: unwrapped the AES key with %s" % args.cert)
    else:
        aes_key = load_aes_key(args)

    try:
        payload = c.decrypt(aes_key)
    except ValueError as exc:
        print("goat: decrypt failed: %s" % exc)
        return 1

    if args.out:
        with open(args.out, "wb") as fh:
            fh.write(payload)
        print("goat: wrote %d bytes to %s" % (len(payload), args.out))
    else:
        sys.stdout.buffer.write(payload)
    return 0


def cmd_pwn(args):
    """Exploit a DFU device into pwndfu state, with goat's own checkm8.

    The exploit is this project's implementation of the published checkm8 bug
    (goat/checkm8.py), on this project's own transport, with constants
    measured per build from the SecureROM images in the corpus. It does not
    run the vendored tool and does not take its constants from it.

    `--dry-run` prints the plan for the attached device and exits, which is
    the answer to "which firmware do I need for this part" before the device
    is touched.
    """
    from goat.pwn import checkm8
    return checkm8(verbose=getattr(args, "verbose", False),
                   dry_run=getattr(args, "dry_run", False))


def _open_pwndfu():
    from goat.usb import PwnedDFU, LibusbDeviceList
    usb = LibusbDeviceList()
    return PwnedDFU(usb)


def _acquire_pwndfu(timeout=5.0, auto_pwn=False, verbose=False):
    """Open a device that is in pwndfu state, exploiting it first if allowed.

    With auto_pwn, a device that is only in DFU is run through checkm8 before
    the image is sent, which is what makes `goat kload` one command instead of
    an exploit step and a boot step. The exploit runs here rather than in this
    function: goat/pwn.py owns the whole "which firmware, which method, and did
    it leave the device pwndfu" question.
    """
    from goat.pwn import acquire_pwndfu
    return acquire_pwndfu(auto_pwn=auto_pwn, verbose=verbose, timeout=timeout)


def _container_key(parsed, args):
    """The AES key for a sealed container, from whichever flag supplied it."""
    if getattr(args, "key_from_cert", False):
        if not parsed.has_keywrap:
            raise SystemExit("goat: container does not wrap a key; pass "
                             "--key-hex or --key-file")
        identity = load_identity(args.cert)
        print("goat: unwrapping the payload key with %s" % args.cert)
        return parsed.unwrap_key(identity)
    if getattr(args, "key_hex", None) or getattr(args, "key_file", None):
        return load_aes_key(args)
    return None


def cmd_send(args):
    """Boot a dr1zzle image on a pwndfu device: goat's kload.

    The image is planned on the host first -- where it goes, what the entry is
    -- so an image that cannot be booted fails before a byte reaches the
    device. Then it is written, read back, and the device is told to jump.
    """
    with open(args.image, "rb") as fh:
        data = fh.read()

    kind = kload.sniff(data)
    key = None
    if kind == kload.KIND_CONTAINER:
        key = _container_key(container.parse(data), args)

    image = kload.plan_image(data, stage=args.stage, entry=args.entry, key=key,
                             stage_container=args.stage_container)
    if args.run and image.staged:
        raise SystemExit("goat: a staged container is entered by the "
                        "device-side loader, not from the host. Drop --run, "
                        "or drop --stage-container to unseal it here.")

    run = args.run if args.run is not None else not image.staged
    print("goat: %s" % image.summary())
    if image.note:
        print("goat: %s" % image.note)

    dev = _acquire_pwndfu(auto_pwn=args.pwn,
                            verbose=getattr(args, "verbose", False))
    try:
        print("goat: device serial: %s" % dev.serial)
        print("goat: writing %d bytes to 0x%x" % (image.size, image.load_base))
        written = kload.load(dev, image, chunk=args.chunk, verify=args.verify)
        if args.verify:
            print("goat: readback verified, %d bytes" % written)
        if not run:
            print("goat: staged at 0x%x (not executed)" % image.load_base)
            return 0
        # x0 = 0 (no device tree from pwndfu), x1 = launch tag, x2 = 0 (nothing
        # staged for the payload). SPEC.md 3.1 and include/goat/goat.h.
        print("goat: executing at 0x%x" % image.entry)
        kload.boot(dev, image.entry, (0, GOAT_LAUNCH_TAG, 0))
    finally:
        dev.close()

    if args.wait <= 0:
        return 0
    print("goat: waiting up to %.0fs for the device to take over" % args.wait)
    if kload.wait_for_handoff(dev.usb, args.wait):
        print("goat: device left DFU, the image is running")
        return 0
    print("goat: device still reports DFU after %.0fs; the image may not have "
          "taken over" % args.wait)
    return 1


def _stage_container(args, der):
    """HELLO/KEY/PUSH a container over TCP; returns (sock, fh, error).

    Shared by `push` and `install` so the handshake and the staging-window
    check live in one place. `error` is None on success, else a short reason;
    the device's replies are printed either way.
    """
    c = container.parse(der)

    sock = socket.create_connection((args.host, args.port), timeout=10)
    sock.settimeout(30)
    fh = sock.makefile("rwb")

    def send_line(text):
        fh.write(text.encode("ascii") + b"\n")
        fh.flush()

    send_line("GOAT/1 HELLO client=goat-%s" % VERSION)
    banner = fh.readline().decode().strip()
    print("device: %s" % banner)

    # The device says where its staging window is, because it cannot be a
    # constant on this side: it is whatever SRAM the linker left over, so it
    # moves whenever the payload image does. A container that asked to be
    # decrypted outside it is refused on the device with stage=placement;
    # checking here turns that into a message about *this* container.
    window = re.search(r"stage=0x([0-9a-f]+)0x([0-9a-f]+)", banner)
    if window:
        base = int(window.group(1), 16)
        size = int(window.group(2), 16)
        if not (base <= c.load_base and c.load_base + len(c.cipher) <= base + size):
            sock.close()
            raise SystemExit(
                "goat: container load base 0x%x does not fit the device's "
                "staging window [0x%x, 0x%x); re-seal it with a load base "
                "inside that range" % (c.load_base, base, base + size))

    send_line("GOAT/1 KEY %s" % args.key_hex)
    reply = fh.readline().decode().strip()
    print("device: %s" % reply)
    if not reply.startswith("GOAT/1 OK"):
        sock.close()
        return None, None, "key rejected"

    send_line("GOAT/1 PUSH %d" % len(der))
    fh.write(der)
    fh.flush()
    reply = fh.readline().decode().strip()
    print("device: %s" % reply)
    if not reply.startswith("GOAT/1 OK"):
        sock.close()
        return None, None, "push refused"

    return sock, fh, None


def cmd_push(args):
    """Push a sealed container to the device goatloader over TCP."""
    with open(args.container_file, "rb") as fh:
        der = fh.read()

    sock, fh, error = _stage_container(args, der)
    if error:
        if error == "key rejected":
            print("goat: key rejected, aborting")
        return 1

    if args.run:
        fh.write(b"GOAT/1 RUN\n")
        fh.flush()
        print("device: %s" % fh.readline().decode().strip())
    fh.write(b"GOAT/1 BYE\n")
    fh.flush()
    fh.readline()
    sock.close()
    return 0


def cmd_install(args):
    """Stage a container, then have the device write it into a NAND slot.

    This is the pristine install path: the device decrypts the sealed image
    straight into its NAND slot with the ECC engine enabled and reads every
    page back, so the copy on flash is the exact image the container carries.
    (`fw save` on the device does the same from the running image, which is
    convenient but snapshots its initialized .data.)
    """
    with open(args.container_file, "rb") as fh:
        der = fh.read()

    sock, fh, error = _stage_container(args, der)
    if error:
        if error == "key rejected":
            print("goat: key rejected, aborting")
        return 1

    name = (" %s" % args.name) if args.name else ""
    fh.write(("GOAT/1 INSTALL %d%s\n" % (args.slot, name)).encode("ascii"))
    fh.flush()
    reply = fh.readline().decode().strip()
    print("device: %s" % reply)

    fh.write(b"GOAT/1 BYE\n")
    fh.flush()
    fh.readline()
    sock.close()

    if not reply.startswith("GOAT/1 OK"):
        print("goat: install failed")
        return 1
    print("goat: installed to NAND slot %d; the core menu can `run %d`"
          % (args.slot, args.slot))
    return 0


def cmd_shell(args):
    sock = socket.create_connection((args.host, args.port), timeout=10)
    sock.settimeout(None)
    print("goat: connected to %s:%d, type 'bye' to exit"
          % (args.host, args.port))
    try:
        while True:
            line = sys.stdin.readline()
            if not line or line.strip() in ("bye", "quit", "exit"):
                break
            sock.sendall(("GOAT/1 %s\n" % line.strip()).encode())
            sock.sendall(b"")  # flush
            reply = b""
            while not reply.endswith(b"\n"):
                chunk = sock.recv(4096)
                if not chunk:
                    return 0
                reply += chunk
            sys.stdout.write(reply.decode("utf-8", "replace"))
    finally:
        sock.close()
    return 0


def cmd_run(args):
    dev = _open_pwndfu()
    try:
        print("goat: executing 0x%x" % args.address)
        dev.execute(args.address, *[int(a, 0) for a in args.args])
    finally:
        dev.close()
    return 0


def cmd_readmem(args):
    dev = _open_pwndfu()
    try:
        data = dev.read_memory(args.address, args.length)
    finally:
        dev.close()
    if args.out:
        with open(args.out, "wb") as fh:
            fh.write(data)
        print("goat: wrote %d bytes to %s" % (len(data), args.out))
    else:
        sys.stdout.buffer.write(data)
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(prog="goat", description=__doc__)
    p.add_argument("--version", action="version", version=VERSION)
    sub = p.add_subparsers(dest="command")

    sp = sub.add_parser("keygen", help="mint a sealing identity")
    sp.add_argument("--out", default="goat-key.json")
    sp.add_argument("--issuer", default="dr1zzle goat CA")
    sp.add_argument("--subject", default=None)
    sp.add_argument("--serial", type=int, default=1)
    sp.add_argument("--bits", type=int, default=2048)
    sp.add_argument("--not-before", type=int, default=0)
    sp.add_argument("--not-after", type=int, default=4102444800)
    sp.set_defaults(func=cmd_keygen)

    rp2350.add_parser(sub)

    sp = sub.add_parser("seal", help="wrap a payload into a container")
    sp.add_argument("image")
    sp.add_argument("--cert", default="goat-key.json")
    sp.add_argument("--out", default="payload.g1")
    sp.add_argument("--key-hex", default=None)
    sp.add_argument("--key-file", default=None)
    sp.add_argument("--key-out", default=None)
    sp.add_argument("--load-base", type=lambda s: int(s, 0), default=None)
    sp.add_argument("--entry-off", type=lambda s: int(s, 0), default=0)
    sp.add_argument("--wrap", action="store_true",
                    help="wrap the AES key to the certificate's public key")
    sp.set_defaults(func=cmd_seal)

    sp = sub.add_parser("inspect", help="print a container without keys")
    sp.add_argument("container_file")
    sp.set_defaults(func=cmd_inspect)

    sp = sub.add_parser("verify", help="check certificate and signature")
    sp.add_argument("container_file")
    sp.set_defaults(func=cmd_verify)

    sp = sub.add_parser("unseal", help="verify, decrypt, extract")
    sp.add_argument("container_file")
    sp.add_argument("--cert", default="goat-key.json")
    sp.add_argument("--key-hex", default=None)
    sp.add_argument("--key-file", default=None)
    sp.add_argument("--key-from-cert", action="store_true")
    sp.add_argument("--out", default=None)
    sp.set_defaults(func=cmd_unseal)

    sp = sub.add_parser("pwn", help="exploit a DFU device into pwndfu state")
    sp.add_argument("--dry-run", action="store_true",
                    help="print the plan for the attached device and exit "
                         "without touching it")
    sp.add_argument("-v", "--verbose", action="store_true",
                    help="print each stage as it runs")
    sp.set_defaults(func=cmd_pwn)

    for name in ("send", "kload"):
        sp = sub.add_parser(name, help="boot a dr1zzle image on a DFU device")
        sp.add_argument("image")
        sp.add_argument("--stage", type=lambda s: int(s, 0), default=None,
                        help="where to write the image "
                             "(default: the image's own load address)")
        sp.add_argument("--entry", type=lambda s: int(s, 0), default=None,
                        help="entry point (default: from the image)")
        sp.add_argument("--run", dest="run", action="store_true", default=None,
                        help="jump to the entry once written (default)")
        sp.add_argument("--no-run", dest="run", action="store_false",
                        help="write and verify, then stop")
        sp.add_argument("--stage-container", action="store_true",
                        help="write a sealed .g1 into the staging window for "
                             "the device-side loader instead of unsealing it "
                             "on the host")
        sp.add_argument("--pwn", dest="pwn", action="store_true", default=True,
                        help="run checkm8 first if the device is only in DFU "
                             "(default)")
        sp.add_argument("--no-pwn", dest="pwn", action="store_false",
                        help="require a device that is already pwndfu")
        sp.add_argument("--wait", type=float, default=kload.DEFAULT_WAIT,
                        help="seconds to watch for the handoff (0 = do not "
                        "wait)")
        sp.add_argument("--verify", dest="verify", action="store_true",
                        default=True, help="read the image back and compare it "
                                           "(default)")
        sp.add_argument("--no-verify", dest="verify", action="store_false",
                        help="trust the write")
        sp.add_argument("--chunk", type=lambda s: int(s, 0),
                        default=kload.DEFAULT_CHUNK,
                        help="bytes per pwndfu write command")
        sp.add_argument("--key-hex", default=None,
                        help="AES key for a sealed container")
        sp.add_argument("--key-file", default=None)
        sp.add_argument("--cert", default="goat-key.json",
                        help="identity to unwrap a container's key with")
        sp.add_argument("--key-from-cert", action="store_true",
                        help="unwrap the container's key with --cert")
        sp.set_defaults(func=cmd_send)

    sp = sub.add_parser("push", help="push a container to the goatloader")
    sp.add_argument("container_file")
    sp.add_argument("--host", default=GOATLOADER_IP)
    sp.add_argument("--port", type=int, default=GOATLOADER_PORT)
    sp.add_argument("--key-hex", required=True)
    sp.add_argument("--run", action="store_true")
    sp.set_defaults(func=cmd_push)

    sp = sub.add_parser(
        "install", help="stage a container and write it to a NAND firmware slot")
    sp.add_argument("container_file")
    sp.add_argument("--slot", type=int, required=True,
                    help="NAND firmware slot index (see the core menu `list`)")
    sp.add_argument("--name", default=None,
                    help="slot label (default: certificate subject)")
    sp.add_argument("--host", default=GOATLOADER_IP)
    sp.add_argument("--port", type=int, default=GOATLOADER_PORT)
    sp.add_argument("--key-hex", required=True)
    sp.set_defaults(func=cmd_install)

    sp = sub.add_parser("shell", help="interactive goatloader session")
    sp.add_argument("--host", default=GOATLOADER_IP)
    sp.add_argument("--port", type=int, default=GOATLOADER_PORT)
    sp.set_defaults(func=cmd_shell)

    sp = sub.add_parser("run", help="jump a pwndfu device to an address")
    sp.add_argument("address", type=lambda s: int(s, 0))
    sp.add_argument("args", nargs="*")
    sp.set_defaults(func=cmd_run)

    sp = sub.add_parser("pull", help="capture firmware corpus targets")
    sp.add_argument("targets", nargs="*")
    sp.add_argument("--outdir", default="corpus")
    sp.add_argument("--list-targets", action="store_true")
    sp.add_argument("--dry-run", action="store_true")
    sp.add_argument("--skip-unverified", action="store_true")
    sp.set_defaults(func=cmd_pull)

    sp = sub.add_parser("readmem", help="read device memory to a file")
    sp.add_argument("address", type=lambda s: int(s, 0))
    sp.add_argument("length", type=lambda s: int(s, 0))
    sp.add_argument("--out", default=None)
    sp.set_defaults(func=cmd_readmem)

    return p


def cmd_pull(args):
    """Capture firmware-only corpus targets from a pwndfu device."""
    if args.list_targets:
        for t in corpus.list_targets():
            flags = []
            if t.get("unverified"):
                flags.append("unverified")
            flags.append(t["access"])
            print("  %-14s %-10s 0x%x+0x%-8x %s"
                  % (t["name"], "/".join(flags), t["address"],
                     t["length"], t["desc"]))
        print("\ngoat: sources are recorded in the manifest; --skip-unverified "
              "describes what it can drop.")
        return 0

    names = args.targets or [t["name"] for t in corpus.list_targets()]

    if args.dry_run:
        return corpus.capture(None, names, args.outdir,
                             skip_unverified=args.skip_unverified,
                             dry_run=True)

    dev = _open_pwndfu()
    try:
        print("goat: device serial: %s" % dev.serial)
        if "PWND:[checkm8]" not in dev.serial:
            print("goat: device is not pwndfu; corpus reads require the "
                  "exploited state (run 'goat pwn' first)")
            return 1
        return corpus.capture(dev, names, args.outdir,
                              skip_unverified=args.skip_unverified)
    finally:
        dev.close()


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 2
    try:
        return args.func(args)
    except (DerError, ValueError) as exc:
        print("goat: %s" % exc)
        return 1
    except UsbError as exc:
        print("goat: usb error: %s" % exc)
        return 1
    except kload.LoadError as exc:
        print("goat: %s" % exc)
        print("goat: the image is not intact on the device; run again, or use "
              "--no-verify only if the read path itself is the problem")
        return 1
    except OSError as exc:
        print("goat: %s" % exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
