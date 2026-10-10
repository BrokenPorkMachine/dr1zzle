#!/usr/bin/env python3
"""Wrap a dr1zzle firmware image in a firmware_header_t record.

The core (src/core/fw_store.c, include/firmware.h) locates firmwares in fixed
NAND slots by reading a firmware_header_t followed by the image bytes. This
script builds that record from the firmware build artifact so the on-NAND
layout is produced by the same build that produced the image.

A record:

    firmware_header_t   (packed, 44 bytes; magic "DFW1", crc32 over image)
    uint8_t image[size]

`crc32` uses zlib's implementation, which is the same IEEE 802.3 reflected
polynomial the device side uses (fw_crc32 in src/core/fw_store.c), so a CRC
computed here matches a CRC computed on the device.

The image is linked for a fixed load base (0x180100000 for the current
build), and its entry point is the ELF's e_entry. entry_off is therefore
e_entry - load_base; passing the ELF lets the script derive it instead of
hard-coding it here.

Usage:
    python3 scripts/mkfirmware.py build/firmware/dr1zzle.bin \\
        --elf build/firmware/dr1zzle.elf \\
        --load-base 0x180100000 \\
        --name dr1zzle \\
        --out build/firmware/dr1zzle.fw

The record is written for the *host build directory*, not for NAND: writing it
to a NAND slot needs a flash tool with the right page/ECC plumbing, which
does not exist yet. The core treats goat push as the reliable delivery path
unless and until it does.
"""

import argparse
import struct
import sys
import zlib

FW_MAGIC = 0x31574644  # "DFW1" little-endian
FW_VERSION = 1
HEADER = struct.Struct("<IHHQIII16s")  # see firmware_header_t in firmware.h


def elf_entry(path):
    """Read the entry point (e_entry) of an ELF64 executable."""
    with open(path, "rb") as fh:
        blob = fh.read()
    if len(blob) < 64 or blob[:4] != b"\x7fELF":
        raise SystemExit(f"error: {path} is not an ELF file")
    if blob[4] != 2 or blob[5] != 1:  # 64-bit, little-endian
        raise SystemExit(f"error: {path} is not a 64-bit little-endian ELF")
    e_type = struct.unpack_from("<H", blob, 16)[0]
    if e_type != 2:  # ET_EXEC
        raise SystemExit(f"error: {path} is not an ET_EXEC executable")
    return struct.unpack_from("<Q", blob, 24)[0]


def make_record(image, load_base, entry_off, name):
    if entry_off is None:
        raise SystemExit("error: need --entry-off or --elf to know where to enter")
    if entry_off >= len(image):
        raise SystemExit("error: entry offset is outside the image")
    if load_base > 0xFFFF_FFFF_FFFF_FFFF:
        raise SystemExit("error: load base does not fit the header field")
    if not 1 <= len(name) <= 15:
        raise SystemExit(
            "error: --name must be 1..15 characters (the header's 16-byte "
            "field is NUL-padded, so the last byte must be a terminator)")
    name = name[:15]
    header = HEADER.pack(FW_MAGIC, FW_VERSION, 0, load_base, entry_off,
                         len(image), zlib.crc32(image) & 0xFFFFFFFF,
                         name.encode("ascii").ljust(16, b"\x00"))
    return header + image


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("image", help="firmware .bin (the raw image, linked for --load-base)")
    ap.add_argument("--elf", default=None,
                    help="parallel ELF build artifact; derives --entry-off from e_entry")
    ap.add_argument("--load-base", type=lambda s: int(s, 0), default=0x180100000,
                    help="address the image is linked for (default 0x180100000)")
    ap.add_argument("--entry-off", type=lambda s: int(s, 0), default=None,
                    help="entry point as an offset from --load-base "
                         "(default: derived from --elf)")
    ap.add_argument("--name", default="dr1zzle",
                    help="label stored in the header (NUL-padded, up to 15 chars)")
    ap.add_argument("--out", default="firmware.fw", help="output record file")
    args = ap.parse_args()

    with open(args.image, "rb") as fh:
        image = fh.read()
    if not image:
        raise SystemExit(f"error: {args.image} is empty")

    entry_off = args.entry_off
    if entry_off is None:
        if not args.elf:
            raise SystemExit("error: pass --elf (or --entry-off) to derive the entry")
        entry = elf_entry(args.elf)
        entry_off = entry - args.load_base

    if entry_off < 0:
        raise SystemExit("error: entry point is below the load base")

    record = make_record(image, args.load_base, entry_off, args.name)
    with open(args.out, "wb") as fh:
        fh.write(record)

    print(f"goat: firmware {args.name}: {len(image)} bytes at "
          f"0x{args.load_base:X}, entry 0x{args.load_base + entry_off:X}")
    print(f"goat: crc32=0x{zlib.crc32(image) & 0xFFFFFFFF:08X}, "
          f"record {len(record)} bytes -> {args.out}")


if __name__ == "__main__":
    main()