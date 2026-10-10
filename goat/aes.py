"""AES-256-CBC in pure Python, mirroring src/goat/aes.c.

Same algorithm, same state layout, same S-box table: what this module encrypts
the device decrypts, and vice versa. Slower than OpenSSL by orders of
magnitude, which does not matter at payload sizes and keeps the tool
dependency-free (and auditable).
"""

_SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]
INV_SBOX = [0] * 256
for _i, _v in enumerate(_SBOX):
    INV_SBOX[_v] = _i
_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _gmul(a, b):
    p = 0
    while b:
        if b & 1:
            p ^= a
        a <<= 1
        if a & 0x100:
            a ^= 0x11B
        a &= 0xFF
        b >>= 1
    return p


def expand_key_256(key):
    words = [list(key[4 * i:4 * i + 4]) for i in range(8)]
    for i in range(8, 60):
        temp = list(words[i - 1])
        if i % 8 == 0:
            temp = temp[1:] + temp[:1]
            temp = [_SBOX[b] for b in temp]
            temp[0] ^= _RCON[i // 8 - 1]
        elif i % 8 == 4:
            temp = [_SBOX[b] for b in temp]
        words.append([a ^ b for a, b in zip(words[i - 8], temp)])
    return [bytes(w for word in words[4 * r:4 * r + 4] for w in word)
            for r in range(15)]


def _shift_rows(s):
    t = list(s)
    for c in range(4):
        for r in range(4):
            t[4 * c + r] = s[4 * ((c + r) % 4) + r]
    return t


def _inv_shift_rows(s):
    t = list(s)
    for c in range(4):
        for r in range(4):
            t[4 * c + r] = s[4 * ((c + 4 - r) % 4) + r]
    return t


def _mix_columns(s):
    for c in range(4):
        a0, a1, a2, a3 = s[4 * c:4 * c + 4]
        s[4 * c + 0] = _gmul(a0, 2) ^ _gmul(a1, 3) ^ a2 ^ a3
        s[4 * c + 1] = a0 ^ _gmul(a1, 2) ^ _gmul(a2, 3) ^ a3
        s[4 * c + 2] = a0 ^ a1 ^ _gmul(a2, 2) ^ _gmul(a3, 3)
        s[4 * c + 3] = _gmul(a0, 3) ^ a1 ^ a2 ^ _gmul(a3, 2)
    return s


def _inv_mix_columns(s):
    for c in range(4):
        a0, a1, a2, a3 = s[4 * c:4 * c + 4]
        s[4 * c + 0] = _gmul(a0, 14) ^ _gmul(a1, 11) ^ _gmul(a2, 13) ^ _gmul(a3, 9)
        s[4 * c + 1] = _gmul(a0, 9) ^ _gmul(a1, 14) ^ _gmul(a2, 11) ^ _gmul(a3, 13)
        s[4 * c + 2] = _gmul(a0, 13) ^ _gmul(a1, 9) ^ _gmul(a2, 14) ^ _gmul(a3, 11)
        s[4 * c + 3] = _gmul(a0, 11) ^ _gmul(a1, 13) ^ _gmul(a2, 9) ^ _gmul(a3, 14)
    return s


def _add_key(s, round_key):
    return [a ^ b for a, b in zip(s, round_key)]


def encrypt_block(rk, block):
    s = _add_key(list(block[:16]), rk[0])
    for rnd in range(1, 14):
        s = _add_key(_mix_columns(_shift_rows([_SBOX[b] for b in s])), rk[rnd])
    s = _add_key(_shift_rows([_SBOX[b] for b in s]), rk[14])
    return bytes(s)


def decrypt_block(rk, block):
    s = _add_key(list(block[:16]), rk[14])
    for rnd in range(13, 0, -1):
        s = _inv_mix_columns(_add_key(_inv_shift_rows([INV_SBOX[b] for b in s]), rk[rnd]))
    s = _add_key(_inv_shift_rows([INV_SBOX[b] for b in s]), rk[0])
    return bytes(s)


def cbc_encrypt(key, iv, plaintext):
    rk = expand_key_256(key)
    pad = 16 - (len(plaintext) % 16)
    data = plaintext + bytes([pad]) * pad
    out = bytearray()
    prev = bytes(iv)
    for off in range(0, len(data), 16):
        blk = bytes(a ^ b for a, b in zip(data[off:off + 16], prev))
        enc = encrypt_block(rk, blk)
        out += enc
        prev = enc
    return bytes(out)


def cbc_decrypt(key, iv, ciphertext):
    if len(ciphertext) % 16:
        raise ValueError("ciphertext is not a multiple of the block size")
    rk = expand_key_256(key)
    out = bytearray()
    prev = bytes(iv)
    for off in range(0, len(ciphertext), 16):
        blk = ciphertext[off:off + 16]
        dec = decrypt_block(rk, blk)
        out += bytes(a ^ b for a, b in zip(dec, prev))
        prev = blk
    pad = out[-1]
    if pad < 1 or pad > 16 or out[-pad:] != bytes([pad]) * pad:
        raise ValueError("invalid PKCS#7 padding")
    return bytes(out[:-pad])
