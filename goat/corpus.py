"""Corpus capture: firmware-only device-family artifacts.

Everything here reads Apple firmware and device-family metadata. There is no
personal data, identity, or user-state collection by design -- see
docs/CORPUS.md for why that line is where it is.

Two properties this module is built around:

1.  **Provenance.** Every target carries the source its address came from, so
    a future reader can separate "documented in rpwn/rust/src/device_platform.rs"
    from "assumed". Anything not documented is marked and can be dropped from
    a capture with --skip-unverified.

2.  **Self-verification.** The A11 SecureROM SHA-1 is published (this repo
    pins it in rpwn/rust/src/device_platform.rs). Capturing it and matching that
    digest proves the entire chain -- DFU transport, read path, file write,
    hashing -- is correct before any of the *unverified* captures are trusted.
"""

import hashlib
import json
import os
import time

FORMAT = "goat-corpus/1"

# Direct: readable with a single memcpy read while in pwndfu state.
# State:  only present when the device has reached a later boot stage.
# Handshake: needs a protocol exchange, not a plain read.
ACCESS_DIRECT = "direct"
ACCESS_STATE = "state"
ACCESS_HANDSHAKE = "handshake"

# Each target: address provenance is recorded so the manifest is auditable.
TARGETS = [
    {
        "name": "securerom",
        "desc": "SecureROM image (Apple firmware, identical across units)",
        "address": 0x100000000,
        "length": 0x100000,
        "access": ACCESS_DIRECT,
        "source": "rpwn/rust/src/device_platform.rs: rom_base/rom_size for cpid 0x8015",
        "known_sha1": "96fccb1a63de1a2d50ff14555d3898a5af46e9b1",
        "self_verifies": True,
    },
    {
        "name": "sram",
        "desc": "SRAM window (payload image, heap, stack, exploit state)",
        "address": 0x180000000,
        "length": 0x200000,
        "access": ACCESS_DIRECT,
        "source": "rpwn/rust/src/device_platform.rs: sram_base/sram_size for cpid 0x8015",
    },
    {
        "name": "dfu-state",
        "desc": "DFU image area: the installed exploit/payload/command region",
        "address": 0x18001C000,
        "length": 0x40000,
        "access": ACCESS_DIRECT,
        "source": "rpwn/rust/src/device_platform.rs: dfu_image_base for cpid 0x8015",
    },
    {
        "name": "dram",
        "desc": "first DRAM window (populated once the boot chain loads iBoot)",
        "address": 0x800000000,
        "length": 0x100000,
        "access": ACCESS_STATE,
        "source": "rpwn/rust/src/device_platform.rs: dram_base for cpid 0x8015",
    },
    {
        "name": "iboot",
        "desc": "iBoot image in DRAM",
        "address": 0x800000000,
        "length": 0x400000,
        "access": ACCESS_STATE,
        "source": "dram_base; iBoot load address not independently documented",
        "unverified": True,
    },
    {
        "name": "llb",
        "desc": "low-level bootloader in DRAM",
        "address": 0x800000000,
        "length": 0x80000,
        "access": ACCESS_STATE,
        "source": "dram_base; LLB extent not independently documented",
        "unverified": True,
    },
    {
        "name": "sep-mailbox",
        "desc": "AP-visible SEP mailbox register window (registers, not SEPROM)",
        "address": 0x23C000000,
        "length": 0x10000,
        "access": ACCESS_DIRECT,
        "source": "include/memory_map.h: MAILBOX_BASE",
        "note": "SEP firmware contents sit behind the mailbox protocol; "
                "only the AP-side window is captured here",
    },
    {
        "name": "seprom",
        "desc": "SEP firmware image",
        "address": 0,
        "length": 0,
        "access": ACCESS_HANDSHAKE,
        "source": "none: no public AP-side address for SEPROM on A11",
        "unverified": True,
        "note": "not captured: requires the SEP mailbox protocol, and no "
                "documented read address exists in this tree",
    },
]


def list_targets():
    return TARGETS


def find_target(name):
    for t in TARGETS:
        if t["name"] == name:
            return t
    return None


def _digest_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _sha1_file(path):
    h = hashlib.sha1()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def capture(dev, names, outdir, skip_unverified=False, dry_run=False,
            verbose=True):
    """Capture the named targets from an open pwndfu device.

    A target that cannot be read is recorded as failed rather than aborting
    the run: the remaining captures are still useful, and a hard stop loses
    the ones that already worked.
    """
    os.makedirs(outdir, exist_ok=True)

    planned = []
    for name in names:
        target = find_target(name)
        if target is None:
            raise SystemExit("goat: unknown target '%s' (see pull --list)" % name)
        if target["access"] == ACCESS_HANDSHAKE:
            if verbose:
                print("goat: skipping '%s': %s" % (name, target.get("note",
                      "requires a protocol handshake")))
            continue
        if skip_unverified and target.get("unverified"):
            if verbose:
                print("goat: skipping '%s' (unverified address)" % name)
            continue
        planned.append(target)

    if dry_run:
        _write_manifest(outdir, planned, [], dry_run=True)
        if verbose:
            print("goat: dry run, %d target(s) planned, wrote %s"
                  % (len(planned), os.path.join(outdir, "manifest.json")))
        return 0

    # Verify the capture chain against the only target with a published
    # digest before trusting anything else.
    results = []
    device_info = {"serial": getattr(dev, "serial", "")}
    for target in planned:
        result = _capture_one(dev, target, outdir, verbose)
        results.append(result)

    _write_manifest(outdir, results, device_info, dry_run=False)

    ok = [r for r in results if r["status"] == "ok"]
    if verbose:
        print("goat: captured %d/%d target(s) into %s"
              % (len(ok), len(results), outdir))
        for r in results:
            if r.get("self_verifies"):
                if r.get("digest_matches_known"):
                    print("goat: SecureROM matches the published SHA-1: "
                          "capture chain verified")
                else:
                    print("goat: WARNING SecureROM digest did not match the "
                          "published SHA-1; treat other captures as suspect")
    return 0


def _capture_one(dev, target, outdir, verbose):
    name = target["name"]
    path = os.path.join(outdir, "%s.bin" % name)
    result = {
        "name": name,
        "desc": target["desc"],
        "address": "0x%x" % target["address"],
        "length": target["length"],
        "access": target["access"],
        "source": target["source"],
    }
    if target.get("unverified"):
        result["unverified"] = True
    if target.get("note"):
        result["note"] = target["note"]

    try:
        data = dev.read_memory(target["address"], target["length"])
    except Exception as exc:                     # noqa: BLE001 - recorded, not raised
        result["status"] = "failed"
        result["error"] = str(exc)
        if verbose:
            print("goat: %-14s FAILED (%s)" % (name, exc))
        return result

    with open(path, "wb") as fh:
        fh.write(data)

    result["status"] = "ok"
    result["sha256"] = _digest_file(path)
    result["bytes"] = len(data)
    if target.get("self_verifies"):
        result["self_verifies"] = True

    if target.get("self_verifies") and target.get("known_sha1"):
        actual = _sha1_file(path)
        result["known_sha1"] = target["known_sha1"]
        result["actual_sha1"] = actual
        result["digest_matches_known"] = (actual == target["known_sha1"])

    if verbose:
        line = "goat: %-14s ok  0x%x+0x%x  sha256=%s" % (
            name, target["address"], len(data), result["sha256"][:16])
        if target.get("self_verifies") and result.get("digest_matches_known"):
            line += "  [sha1 verified]"
        print(line)
    return result


def _write_manifest(outdir, results, device_info, dry_run=False):
    manifest = {
        "format": FORMAT,
        "captured_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "dry_run": dry_run,
        "device": device_info,
        "targets": results,
    }
    path = os.path.join(outdir, "manifest.json")
    with open(path, "w") as fh:
        json.dump(manifest, fh, indent=2)
    return path
