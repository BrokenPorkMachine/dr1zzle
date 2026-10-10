#!/usr/bin/env python3
"""
dr1zzle Multi-Stage Flash Image Builder
Builds a complete flash image with Stage 1, Stage 2 (compressed), and Stage 3
"""

import struct
import argparse
import subprocess
import sys
import os
import hashlib
import lz4.frame

STAGE1_LOAD_ADDR = 0x180000000
STAGE2_LOAD_ADDR = 0x180008000
STAGE2_MAX_SIZE = 128 * 1024
STAGE3_LOAD_ADDR = 0x800000000

STAGE2_MAGIC = 0x5354414732  # "STAG2"
STAGE2_VERSION = 1

def crc32(data):
    crc = ~0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (0xEDB88320 if (crc & 1) else 0)
    return ~crc & 0xFFFFFFFF

def read_file(path):
    with open(path, 'rb') as f:
        return f.read()

def write_file(path, data):
    with open(path, 'wb') as f:
        f.write(data)

def compress_lz4(data):
    """Compress using LZ4 frame format"""
    return lz4.frame.compress(data, compression_level=9)

def build_stage2_header(payload, load_addr, entry_offset, flags=0):
    """Build Stage 2 header"""
    compressed = False
    payload_data = payload
    compressed_size = 0
    
    # Try LZ4 compression
    compressed_payload = compress_lz4(payload)
    if len(compressed_payload) < len(payload):
        compressed = True
        payload_data = compressed_payload
        compressed_size = len(compressed_payload)
        flags |= 1  # Bit 0 = compressed
    
    header = struct.pack('<QIIIIIQQ24s',
        0x5354414732,           # magic "STAG2"
        1,                       # version
        len(payload),            # original size
        compressed_size,         # compressed size (0 if uncompressed)
        crc32(payload_data),     # CRC32 of payload data
        flags,                   # flags
        STAGE2_LOAD_ADDR,        # load address
        STAGE2_LOAD_ADDR + 0x1000  # entry point (after header)
    )
    
    # Pad header to 512 bytes
    header = header.ljust(512, b'\x00')
    return header, payload_data

def build_flash_image(stage1_bin, stage2_bin, stage3_elf, output):
    """Build complete flash image"""
    
    # Read inputs
    stage1 = read_file(stage1_bin)
    stage2 = read_file(stage2_bin)
    stage3 = read_file(stage3_elf)
    
    print(f"Stage 1: {len(stage1)} bytes")
    print(f"Stage 2: {len(stage2)} bytes")
    print(f"Stage 3: {len(stage3)} bytes")
    
    # Verify Stage 1 size
    if len(stage1) > 32 * 1024:
        raise ValueError(f"Stage 1 too large: {len(stage1)} > 32KB")
    
    # Build Stage 2 with header
    stage2_payload = read_file(stage2_bin)
    stage2_header, stage2_payload = build_stage2_header(
        stage2_payload, STAGE2_LOAD_ADDR, 0x1000
    )
    stage2_image = stage2_header + stage2_payload
    
    if len(stage2_image) > STAGE2_MAX_SIZE:
        raise ValueError(f"Stage 2 too large: {len(stage2_image)} > {STAGE2_MAX_SIZE}")
    
    print(f"Stage 2 (with header): {len(stage2_image)} bytes")
    
    # Build flash image layout:
    # 0x000000 - 0x07FFF: Stage 1 (32 KB)
    # 0x08000 - 0x1FFFF: Stage 2 (128 KB max)
    # 0x20000 - ...: Stage 3 (ELF)
    
    flash = bytearray()
    
    # Stage 1 at offset 0
    flash.extend(stage1)
    flash.extend(b'\x00' * (0x8000 - len(stage1)))  # Pad to 32 KB
    
    # Stage 2 at 32 KB offset
    flash.extend(stage2_image)
    flash.extend(b'\x00' * (0x20000 - len(stage2_image)))  # Pad to 128 KB
    
    # Stage 3 at 128 KB offset
    flash.extend(stage3)
    
    write_file(output, flash)
    print(f"Flash image: {len(flash)} bytes -> {output}")
    
    # Verify
    verify_flash_image(flash)

def verify_flash_image(flash):
    """Verify flash image integrity"""
    # Check Stage 1
    assert len(flash) >= 0x20000 + 4
    
    # Check Stage 2 header
    hdr_data = flash[0x8000:0x8200]
    magic = struct.unpack('<Q', hdr_data[:8])[0]
    if magic != 0x5354414732:
        raise ValueError("Invalid Stage 2 magic")
    
    version = struct.unpack('<I', hdr_data[8:12])[0]
    size = struct.unpack('<I', hdr_data[12:16])[0]
    crc = struct.unpack('<I', hdr_data[20:24])[0]
    
    print(f"Stage 2: version={version}, size={size}, crc={crc:#x}")
    
    # Verify CRC
    payload = flash[0x8200:0x8200+size]
    calc_crc = crc32(payload)
    if calc_crc != crc:
        raise ValueError(f"Stage 2 CRC mismatch: {calc_crc:#x} != {crc:#x}")
    
    print("All checks passed!")

def main():
    parser = argparse.ArgumentParser(description='Build dr1zzle multi-stage flash image')
    parser.add_argument('--stage1', required=True, help='Stage 1 binary')
    parser.add_argument('--stage2', required=True, help='Stage 2 binary')
    parser.add_argument('--stage3', required=True, help='Stage 3 ELF')
    parser.add_argument('--output', required=True, help='Output flash image')
    args = parser.parse_args()
    
    build_flash_image(args.stage1, args.stage2, args.stage3, args.output)

if __name__ == '__main__':
    main()